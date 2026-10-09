package pipeline

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"ta_node/internal/correlation"
	"ta_node/internal/detector"
	"ta_node/internal/event"
	"ta_node/internal/evidence"
	"ta_node/internal/fingerprint"
	"ta_node/internal/flow"
	"ta_node/internal/intel"
)

type fakeSource struct {
	ch chan gopacket.Packet
}

func TestNewEventDirectionBackfill(t *testing.T) {
	deps, _, q := testDeps(t)
	deps.Tracker = correlation.New(correlation.Options{})
	deps.Fingerprints = fingerprint.New([]fingerprint.PatternRule{{ID: "body", Type: "TEST", Regex: "cdef"}})
	head := "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 8\r\n\r\nab"
	deps.process(buildPacket(t, "10.0.0.1", "10.0.0.2", 40000, 80, 100, head))
	deps.process(buildPacket(t, "10.0.0.1", "10.0.0.2", 40000, 80, 100+uint32(len(head)), "cdef"))
	if len(q.events) != 1 {
		t.Fatalf("events=%d", len(q.events))
	}
	ev := q.events[0]
	if ev.RawPacket.MessageDirection != "request" || ev.RawPacket.DirectionSource != "session" || ev.RawPacket.DirectionConfidence != "medium" || ev.RawPacket.TransportDirection != "client_to_server" {
		t.Fatalf("direction not carried into new event: %+v", ev.RawPacket)
	}
	if ev.RawPacket.Request == nil || ev.RawPacket.Request.PayloadText != "cdef" {
		t.Fatal("trigger continuation missing from request tab")
	}
}

func (s *fakeSource) Packets() <-chan gopacket.Packet { return s.ch }
func (s *fakeSource) Close()                          {}

type fakeQueue struct {
	mu     sync.Mutex
	events []event.ThreatEvent
}

func (q *fakeQueue) Enqueue(ev event.ThreatEvent) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.events = append(q.events, ev)
	return nil
}
func (q *fakeQueue) LoadPending(limit int) ([]event.ThreatEvent, error) { return nil, nil }
func (q *fakeQueue) MarkPushed(eventID string, rev uint64) error        { return nil }
func (q *fakeQueue) MarkFailed(eventID string, rev uint64, m string) error {
	return nil
}

func buildPacket(t *testing.T, srcIP, dstIP string, sport, dport uint16, seq uint32, payloads ...string) gopacket.Packet {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), Seq: seq, ACK: true, PSH: true, Window: 8192}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP(srcIP), DstIP: net.ParseIP(dstIP)}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6}, DstMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1},
		EthernetType: layers.EthernetTypeIPv4}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	payload := "x"
	if len(payloads) > 0 {
		payload = payloads[0]
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte(payload))); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func testDeps(t *testing.T) (Deps, *flow.Aggregator, *fakeQueue) {
	t.Helper()
	intelFile := t.TempDir() + "/intel.yaml"
	if err := os.WriteFile(intelFile, []byte("items: []"), 0644); err != nil {
		t.Fatal(err)
	}
	store, err := intel.NewStore(intelFile)
	if err != nil {
		t.Fatal(err)
	}
	agg := flow.NewAggregator(1000, time.Minute)
	q := &fakeQueue{}
	return Deps{
		Fingerprints: fingerprint.New(nil),
		Intel:        intel.NewMatcher(store),
		Flows:        agg,
		Detector:     detector.New("test-node"),
		Evidence:     evidence.New(false, t.TempDir(), "test-node", false, 0, false),
		Queue:        q,
	}, agg, q
}

func TestFlowHashDirectionInsensitive(t *testing.T) {
	fwd := buildPacket(t, "10.0.0.1", "10.0.0.2", 12345, 80, 1)
	rev := buildPacket(t, "10.0.0.2", "10.0.0.1", 80, 12345, 1)
	if flowHash(fwd) != flowHash(rev) {
		t.Fatal("both directions of a conversation must hash identically")
	}
	other := buildPacket(t, "10.0.0.1", "10.0.0.3", 12345, 80, 1)
	if flowHash(fwd) == flowHash(other) {
		t.Fatal("different flows must not share a hash (test assumption)")
	}
}

func TestRunProcessesAllPackets(t *testing.T) {
	deps, agg, _ := testDeps(t)
	src := &fakeSource{ch: make(chan gopacket.Packet, 64)}
	done := make(chan struct{})
	go func() {
		Run(context.Background(), src, deps, 4)
		close(done)
	}()
	const flows, perFlow = 8, 50
	for i := 0; i < flows*perFlow; i++ {
		flowID := i % flows
		srcIP := "10.0.0.1"
		dstIP := "10.1.0." + strconv.Itoa(flowID)
		src.ch <- buildPacket(t, srcIP, dstIP, 20000+uint16(flowID), 443, uint32(i))
	}
	close(src.ch)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after source close")
	}
	if got := agg.Len(); got != flows {
		t.Fatalf("aggregator tracked %d flows, want %d", got, flows)
	}
}

func TestRunCancelDropsBacklog(t *testing.T) {
	deps, _, _ := testDeps(t)
	src := &fakeSource{ch: make(chan gopacket.Packet)} // never closed
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, src, deps, 2)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}
