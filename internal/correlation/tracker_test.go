package correlation

import (
	"strings"
	"testing"
	"time"

	"ta_node/internal/event"
	"ta_node/internal/parser"
)

func TestTrackerLinksRealResponseToExistingOccurrence(t *testing.T) {
	tracker := New(Options{MaxSessions: 10, MaxTransactionsPerSession: 4, MaxPacketsPerTransaction: 8, MaxReassemblyBytesPerSide: 4096, ResponseWait: time.Second, StorePacketIndex: true})
	requestPayload := []byte("GET /alert HTTP/1.1\r\nHost: example.test\r\n\r\n")
	request := parser.PacketFeature{
		PacketTimeUsec: 1_000_000, SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "10.0.0.2", DstPort: 80, Proto: "tcp",
		Payload: requestPayload, RawPacket: requestPayload, CapturedLen: uint32(len(requestPayload)), WireLen: uint32(len(requestPayload)),
		MessageDirection: "request", HTTPMethod: "GET", TCPSeq: 100,
	}
	requestObs := tracker.Observe(request, 1)
	if requestObs.SessionID == "" || requestObs.TransactionID == "" || requestObs.Exchange == nil || requestObs.Exchange.Request == nil {
		t.Fatalf("request context incomplete: %+v", requestObs)
	}
	base := event.ThreatEvent{EventID: "evt-1", EventTime: request.PacketTimeUsec, RawPacket: &event.RawPacketContext{MessageDirection: "request", PacketHex: "00"}}
	registered := tracker.Register(requestObs, base)
	if registered.ContextRevision != 1 || registered.ContextFinal || registered.Exchange.ResponseStatus != "pending" {
		t.Fatalf("initial occurrence wrong: %+v", registered)
	}

	responsePayload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	response := parser.PacketFeature{
		PacketTimeUsec: 1_100_000, SrcIP: "10.0.0.2", SrcPort: 80, DstIP: "10.0.0.1", DstPort: 40000, Proto: "tcp",
		Payload: responsePayload, RawPacket: responsePayload, CapturedLen: uint32(len(responsePayload)), WireLen: uint32(len(responsePayload)),
		MessageDirection: "response", TCPSeq: 900,
	}
	responseObs := tracker.Observe(response, 2)
	if responseObs.SessionID != requestObs.SessionID || responseObs.TransactionID != requestObs.TransactionID {
		t.Fatalf("response was not linked: request=%+v response=%+v", requestObs, responseObs)
	}
	if len(responseObs.Updates) != 1 {
		t.Fatalf("response updates = %d, want 1", len(responseObs.Updates))
	}
	updated := responseObs.Updates[0]
	if updated.EventID != "evt-1" || updated.ContextRevision != 2 || !updated.ContextFinal {
		t.Fatalf("updated occurrence identity wrong: %+v", updated)
	}
	if updated.Exchange == nil || updated.Exchange.Response == nil || updated.Exchange.Response.ReassembledText != string(responsePayload) || updated.Exchange.ResponseStatus != "complete" {
		t.Fatalf("response evidence missing: %+v", updated.Exchange)
	}
	if updated.RawPacket.Response == nil || updated.RawPacket.Response.PayloadText != string(responsePayload) {
		t.Fatalf("legacy response tab was not enriched: %+v", updated.RawPacket)
	}
}

func TestTrackerBoundsReassemblyAndMarksRetransmission(t *testing.T) {
	tracker := New(Options{MaxSessions: 2, MaxTransactionsPerSession: 2, MaxPacketsPerTransaction: 1, MaxReassemblyBytesPerSide: 8, StorePacketIndex: true})
	payload := []byte("GET /long HTTP/1.1\r\n\r\n")
	pf := parser.PacketFeature{PacketTimeUsec: 10, SrcIP: "1.1.1.1", SrcPort: 1, DstIP: "2.2.2.2", DstPort: 80, Proto: "tcp", Payload: payload, RawPacket: payload, CapturedLen: uint32(len(payload)), WireLen: uint32(len(payload)), MessageDirection: "request", HTTPMethod: "GET", TCPSeq: 10}
	obs := tracker.Observe(pf, 1)
	if obs.Exchange.Request == nil || !obs.Exchange.Request.Truncated || len(obs.Exchange.Request.ReassembledText) != 8 {
		t.Fatalf("reassembly limit not enforced: %+v", obs.Exchange.Request)
	}
	pf.MessageDirection = ""
	pf.PacketTimeUsec++
	obs = tracker.Observe(pf, 2)
	if obs.Exchange.Request.Retransmissions != 1 || len(obs.Exchange.Request.Packets) != 1 {
		t.Fatalf("retransmission/index bounds wrong: %+v", obs.Exchange.Request)
	}
	if !strings.HasPrefix(obs.Exchange.Request.ReassembledText, "GET /lon") {
		t.Fatalf("unexpected bounded payload: %q", obs.Exchange.Request.ReassembledText)
	}
}

func TestTrackerThrottlesNonFinalRevisions(t *testing.T) {
	tracker := New(Options{MaxSessions: 10, MaxTransactionsPerSession: 4, MaxPacketsPerTransaction: 8, MaxReassemblyBytesPerSide: 4096, ResponseWait: 30 * time.Second, RevisionInterval: 10 * time.Second, StorePacketIndex: true})
	mk := func(usec uint64, seq uint32, fin bool) parser.PacketFeature {
		payload := []byte("chunk")
		return parser.PacketFeature{
			PacketTimeUsec: usec, SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "10.0.0.2", DstPort: 80, Proto: "tcp",
			Payload: payload, RawPacket: payload, CapturedLen: uint32(len(payload)), WireLen: uint32(len(payload)),
			TCPSeq: seq, TCPFIN: fin,
		}
	}
	first := mk(1_000_000, 100, false)
	first.MessageDirection = "request"
	first.HTTPMethod = "POST"
	first.Payload = []byte("POST /up HTTP/1.1\r\nHost: example.test\r\n\r\n")
	first.RawPacket = first.Payload
	first.CapturedLen = uint32(len(first.Payload))
	first.WireLen = first.CapturedLen
	obs := tracker.Observe(first, 1)
	tracker.Register(obs, event.ThreatEvent{EventID: "evt-1", EventTime: first.PacketTimeUsec})

	// First follow-up packet always emits revision 2.
	obs = tracker.Observe(mk(2_000_000, 200, false), 2)
	if len(obs.Updates) != 1 || obs.Updates[0].ContextRevision != 2 {
		t.Fatalf("first revision missing: %+v", obs.Updates)
	}
	// Packets inside the interval are throttled.
	for i, usec := range []uint64{3_000_000, 5_000_000, 11_000_000} {
		obs = tracker.Observe(mk(usec, uint32(300+i*100), false), uint64(3+i))
		if len(obs.Updates) != 0 {
			t.Fatalf("revision emitted inside throttle interval at %d usec: %+v", usec, obs.Updates)
		}
	}
	// After the interval a new revision is emitted.
	obs = tracker.Observe(mk(12_500_000, 900, false), 6)
	if len(obs.Updates) != 1 || obs.Updates[0].ContextRevision != 3 || obs.Updates[0].ContextFinal {
		t.Fatalf("post-interval revision wrong: %+v", obs.Updates)
	}
	// Final revisions are always emitted, even inside the interval.
	obs = tracker.Observe(mk(13_000_000, 1000, true), 7)
	if len(obs.Updates) != 1 || obs.Updates[0].ContextRevision != 4 || !obs.Updates[0].ContextFinal {
		t.Fatalf("final revision wrong: %+v", obs.Updates)
	}
}
