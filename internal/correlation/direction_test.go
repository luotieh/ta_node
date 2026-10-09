package correlation

import (
	"testing"

	"ta_node/internal/event"
	"ta_node/internal/parser"
)

func directionPacket() parser.PacketFeature {
	return parser.PacketFeature{Proto: "tcp", SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "10.0.0.2", DstPort: 80, PacketTimeUsec: 1_000_000, TCPSeq: 100}
}

func TestDirectionHTTPContinuationAndImmutableOccurrence(t *testing.T) {
	tr := New(Options{})
	p := directionPacket()
	p.Payload = []byte("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 8\r\n\r\nab")
	p.MessageDirection, p.HTTPMethod = "request", "POST"
	obs := tr.Observe(p, 1)
	if obs.Direction.DirectionSource != "protocol" {
		t.Fatal(obs.Direction)
	}
	tr.Register(obs, event.ThreatEvent{EventID: "old", RawPacket: &event.RawPacketContext{MessageDirection: "unknown"}})
	p.TCPSeq += uint32(len(p.Payload))
	p.MessageDirection, p.HTTPMethod = "", ""
	p.Payload = []byte("cdef")
	p.PacketTimeUsec += 20_000_000
	obs = tr.Observe(p, 2)
	if obs.Direction.MessageDirection != "request" || obs.Direction.DirectionSource != "session" || obs.Direction.TransportDirection != "client_to_server" {
		t.Fatal(obs.Direction)
	}
	for _, ev := range obs.Updates {
		if ev.RawPacket.MessageDirection != "unknown" {
			t.Fatal("historical direction was changed")
		}
	}
	// Bytes extending beyond Content-Length cannot safely be attributed.
	p.TCPSeq += 4
	p.Payload = []byte("ghNEXT")
	if got := tr.Observe(p, 3).Direction; got.MessageDirection != "unknown" {
		t.Fatal(got)
	}
}

func TestDirectionResponseContinuation(t *testing.T) {
	tr := New(Options{})
	p := directionPacket()
	p.SrcIP, p.DstIP = p.DstIP, p.SrcIP
	p.SrcPort, p.DstPort = p.DstPort, p.SrcPort
	p.Payload = []byte("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nab")
	p.MessageDirection = "response"
	tr.Observe(p, 1)
	p.TCPSeq += uint32(len(p.Payload))
	p.MessageDirection = ""
	p.Payload = []byte("cdef")
	got := tr.Observe(p, 2).Direction
	if got.MessageDirection != "response" || got.DirectionSource != "session" || got.TransportDirection != "server_to_client" {
		t.Fatal(got)
	}
}

func TestDirectionDoesNotGuessUnframedOrTruncatedContinuation(t *testing.T) {
	for _, head := range []string{
		"POST / HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: test\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nContent-Length: 8\r\n\r\n",
	} {
		tr := New(Options{})
		p := directionPacket()
		p.Payload, p.MessageDirection, p.HTTPMethod = []byte(head), "request", "POST"
		tr.Observe(p, 1)
		p.TCPSeq += uint32(len(head))
		p.Payload, p.MessageDirection, p.HTTPMethod = []byte("data"), "", ""
		if got := tr.Observe(p, 2).Direction; got.MessageDirection != "unknown" {
			t.Fatalf("guessed %q: %+v", head, got)
		}
	}
	tr := New(Options{})
	p := directionPacket()
	head := "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 8\r\n\r\n"
	p.Payload, p.MessageDirection, p.HTTPMethod = []byte(head), "request", "POST"
	tr.Observe(p, 1)
	p.TCPSeq += uint32(len(head))
	p.Payload, p.MessageDirection, p.HTTPMethod = []byte("data"), "", ""
	p.CapturedLen, p.WireLen = 58, 100
	if got := tr.Observe(p, 2).Direction; got.MessageDirection != "unknown" {
		t.Fatal("truncated packet inferred", got)
	}
}

func TestDirectionHandshakeMidstreamConflictAndReuse(t *testing.T) {
	tr := New(Options{})
	p := directionPacket()
	p.Payload = []byte("encrypted")
	if got := tr.Observe(p, 1).Direction; got.MessageDirection != "unknown" || got.TransportDirection != "unknown" {
		t.Fatal(got)
	}
	// SYN+ACK alone identifies the connection initiator.
	p.Payload = nil
	p.TCPSYN, p.TCPACK, p.MessageDirection = true, true, "response"
	tr.Observe(p, 2)
	p.TCPSYN, p.MessageDirection = false, ""
	p.Payload = []byte("encrypted")
	if got := tr.Observe(p, 3).Direction; got.MessageDirection != "unknown" || got.TransportDirection != "server_to_client" {
		t.Fatal(got)
	}
	p.Payload = nil // pure ACK
	if got := tr.Observe(p, 4).Direction; got.MessageDirection != "unknown" {
		t.Fatal(got)
	}
	p.MessageDirection, p.HTTPMethod, p.Payload = "request", "GET", []byte("GET / HTTP/1.1\r\n\r\n")
	if got := tr.Observe(p, 5).Direction; got.TransportDirection != "unknown" {
		t.Fatal("conflict must disable role inference", got)
	}
	p.MessageDirection, p.HTTPMethod, p.Payload = "", "", []byte("data")
	if got := tr.Observe(p, 6).Direction; got.MessageDirection != "unknown" || got.TransportDirection != "unknown" {
		t.Fatal(got)
	}
	p.TCPSYN, p.TCPACK, p.Payload, p.MessageDirection = true, false, nil, "request"
	p.PacketTimeUsec++
	if got := tr.Observe(p, 7).Direction; got.TransportDirection != "client_to_server" || got.DirectionSource != "handshake" {
		t.Fatal("new connection must reset conflict", got)
	}
}
