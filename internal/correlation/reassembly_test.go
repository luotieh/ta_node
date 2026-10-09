package correlation

import (
	"bytes"
	"encoding/hex"
	"ta_node/internal/parser"
	"testing"
)

func fragment(seq uint32, s string) parser.PacketFeature {
	return parser.PacketFeature{TCPSeq: seq, Proto: "tcp", Payload: []byte(s), CapturedLen: uint32(len(s)), WireLen: uint32(len(s))}
}
func TestSequenceWindowRepairsOutOfOrderAndOverlap(t *testing.T) {
	tr := New(Options{})
	var side sideState
	tr.appendSide(&side, fragment(100, "abc"), 1)
	tr.appendSide(&side, fragment(106, "ghi"), 2)
	if string(side.payload) != "abc" || !side.context.ReassemblyIncomplete {
		t.Fatalf("gap concatenated: %q", side.payload)
	}
	tr.appendSide(&side, fragment(102, "cdefg"), 3)
	if string(side.payload) != "abcdefghi" || side.context.ReassemblyIncomplete || side.context.Retransmissions != 0 {
		t.Fatalf("late bytes not retained: %q %+v", side.payload, side.context)
	}
	tr.appendSide(&side, fragment(100, "abc"), 4)
	if side.context.Retransmissions != 1 || string(side.payload) != "abcdefghi" {
		t.Fatal("duplicate appended")
	}
}
func TestFirstPayloadMayArriveLateAndSequenceMayWrap(t *testing.T) {
	tr := New(Options{})
	var side sideState
	tr.appendSide(&side, fragment(2, "ghi"), 1)
	tr.appendSide(&side, fragment(0xfffffffc, "abcdef"), 2)
	if string(side.payload) != "abcdefghi" || side.context.ReassemblyIncomplete {
		t.Fatalf("wrap/late prefix: %q %+v", side.payload, side.context)
	}
}
func TestSamplePacketOrderDoesNotDiscardLate1448Bytes(t *testing.T) {
	tr := New(Options{StorePacketIndex: true})
	var side sideState
	for i, p := range []struct {
		seq               uint32
		captured, missing int
	}{{3601103356, 470, 0}, {3601103826, 1391, 0}, {3601105217, 1534, 1248}, {3601109447, 677, 0}, {3601107999, 1448, 0}} {
		pf := fragment(p.seq, string(bytes.Repeat([]byte{'x'}, p.captured)))
		pf.WireLen += uint32(p.missing)
		tr.appendSide(&side, pf, uint64(i+1))
	}
	if side.context.Retransmissions != 0 {
		t.Fatalf("late fragment counted as retransmission: %+v", side.context)
	}
	if !side.context.Truncated || !side.context.ReassemblyIncomplete {
		t.Fatal("truncated sample declared complete")
	}
	if len(side.payload) != 3395 {
		t.Fatalf("must stop before missing 1248 bytes, got %d", len(side.payload))
	}
	// Once genuinely missing bytes arrive, every retained fragment contributes in sequence order.
	tr.appendSide(&side, fragment(3601106751, string(bytes.Repeat([]byte{'x'}, 1248))), 6)
	if len(side.payload) != 6768 || side.context.ReassemblyIncomplete {
		t.Fatalf("repair=%d incomplete=%v", len(side.payload), side.context.ReassemblyIncomplete)
	}
	if responseComplete(&side) {
		t.Fatal("encrypted data marked complete")
	}
}
func TestResponseCompletenessRequiresFramingAndNoTruncation(t *testing.T) {
	payload := "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef"
	for _, tc := range []struct {
		input string
		want  bool
	}{
		{payload, true}, {payload[:len(payload)-1], false},
		{"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", false},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", true},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nabc\r\n0\r\n\r\n", false},
		{"TLS encrypted bytes", false}, {"HTTP/1.1 100 Continue\r\n\r\n", false},
	} {
		if got := httpMessageComplete([]byte(tc.input), true); got != tc.want {
			t.Fatalf("%q: complete=%v", tc.input, got)
		}
	}
	tr := New(Options{})
	var side sideState
	tr.appendSide(&side, fragment(100, payload[:len(payload)-3]), 1)
	tr.appendSide(&side, fragment(uint32(100+len(payload)-1), payload[len(payload)-1:]), 2)
	tx := &transactionState{response: side}
	if tr.exchange(tx).ResponseStatus != "partial" {
		t.Fatal("gap reported complete")
	}
	tr.appendSide(&tx.response, fragment(uint32(100+len(payload)-3), payload[len(payload)-3:len(payload)-1]), 3)
	ex := tr.exchange(tx)
	if ex.ResponseStatus != "complete" || ex.Response.CompletenessReason != "verified_http_framing" {
		t.Fatalf("filled response=%+v", ex)
	}
	if ex.Response.ReassembledHex != hex.EncodeToString([]byte(payload)) {
		t.Fatal("response out of order")
	}
	tx.response.context.Truncated = true
	if tr.exchange(tx).ResponseStatus != "partial" {
		t.Fatal("truncation reported complete")
	}
}
func TestReassemblyWindowAndPacketIndexStayBounded(t *testing.T) {
	tr := New(Options{MaxReassemblyBytesPerSide: 8, MaxOutOfOrderBytes: 4, MaxPacketsPerTransaction: 1, StorePacketIndex: true})
	var side sideState
	tr.appendSide(&side, fragment(100, "ab"), 1)
	tr.appendSide(&side, fragment(1000000, "cd"), 2)
	if len(side.data) > 8 || len(side.present) > 8 || len(side.seen) > 1 || len(side.context.Packets) > 1 || !side.context.Truncated || !side.context.ReassemblyIncomplete {
		t.Fatalf("limits not enforced: %+v", side)
	}
}

func TestUnknownResponseAndTimeoutNeverClaimCompleteness(t *testing.T) {
	tr := New(Options{})
	var side sideState
	tr.appendSide(&side, fragment(100, "encrypted TLS data"), 1)
	tx := &transactionState{response: side, final: true}
	ex := tr.exchange(tx)
	if ex.ResponseStatus != "partial" || ex.Response.CompletenessReason != "application_framing_unverified" {
		t.Fatalf("unverified response=%+v", ex)
	}
	if ex := tr.exchange(&transactionState{final: true}); ex.ResponseStatus != "not_captured" {
		t.Fatalf("empty final response=%+v", ex)
	}
	if ex := tr.exchange(&transactionState{}); ex.ResponseStatus != "pending" {
		t.Fatalf("empty pending response=%+v", ex)
	}
}
func TestConflictingOverlapCannotDeclareComplete(t *testing.T) {
	tr := New(Options{})
	var side sideState
	tr.appendSide(&side, fragment(100, "abcdef"), 1)
	tr.appendSide(&side, fragment(102, "ZZ"), 2)
	if !side.context.ReassemblyIncomplete || string(side.payload) != "abcdef" {
		t.Fatalf("conflicting evidence overwritten: %+v", side)
	}
}
