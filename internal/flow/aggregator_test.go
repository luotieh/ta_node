package flow

import (
	"testing"
	"time"

	"ta_node/internal/fingerprint"
	"ta_node/internal/intel"
	"ta_node/internal/parser"
)

func pkt(src string) parser.PacketFeature {
	return parser.PacketFeature{SrcIP: src, SrcPort: 1234, DstIP: "10.0.0.1", DstPort: 80, Proto: "tcp", Payload: []byte("abc")}
}

func TestAggregatorReturnsCurrentHitsWithoutAccumulating(t *testing.T) {
	a := NewAggregator(100, time.Minute)
	hit := []fingerprint.FingerprintHit{{RuleID: "r1"}}

	f1 := a.Update(pkt("1.1.1.1"), hit, nil)
	if len(f1.FingerprintHits) != 1 {
		t.Fatalf("expected current packet hits, got %d", len(f1.FingerprintHits))
	}
	// Second packet on the same flow carries no hits; the stored flow must not
	// have accumulated the previous packet's hits.
	f2 := a.Update(pkt("1.1.1.1"), nil, nil)
	if len(f2.FingerprintHits) != 0 {
		t.Fatalf("hits must not accumulate on the stored flow, got %d", len(f2.FingerprintHits))
	}
	if f2.Packets != 2 {
		t.Fatalf("expected packet counter to advance, got %d", f2.Packets)
	}
}

func TestAggregatorCleanupEvictsIdleFlows(t *testing.T) {
	now := time.Unix(1000, 0)
	a := NewAggregator(100, 30*time.Second)
	a.now = func() time.Time { return now }

	a.Update(pkt("1.1.1.1"), nil, nil)
	a.Update(pkt("2.2.2.2"), nil, nil)
	if a.Len() != 2 {
		t.Fatalf("expected 2 flows, got %d", a.Len())
	}

	now = now.Add(time.Minute) // both flows now idle beyond the timeout
	if removed := a.Cleanup(); removed != 2 {
		t.Fatalf("expected 2 evictions, got %d", removed)
	}
	if a.Len() != 0 {
		t.Fatalf("expected empty aggregator, got %d", a.Len())
	}
}

func TestAggregatorAttachesAppContextWithoutPersisting(t *testing.T) {
	a := NewAggregator(100, time.Minute)
	p := pkt("1.1.1.1")
	p.HTTPMethod = "GET"
	p.UserAgent = "evil-bot/1.0"
	p.PayloadSample = "GET /x HTTP/1.1"

	// The triggering packet's app-layer context is attached to the returned
	// feature for event enrichment.
	got := a.Update(p, []fingerprint.FingerprintHit{{RuleID: "r"}}, nil)
	if got.HTTPMethod != "GET" || got.UserAgent != "evil-bot/1.0" || got.PayloadSample != "GET /x HTTP/1.1" {
		t.Fatalf("expected app context on returned feature, got %+v", got)
	}

	// A later packet on the same flow carrying no app-layer context must come
	// back clean: the previous packet's context must NOT have been persisted on
	// the stored flow (memory-safety invariant).
	next := a.Update(pkt("1.1.1.1"), nil, nil)
	if next.HTTPMethod != "" || next.UserAgent != "" || next.PayloadSample != "" {
		t.Fatalf("app context must not persist on the stored flow, got %+v", next)
	}
}

func TestAggregatorCapsLiveFlows(t *testing.T) {
	now := time.Unix(1000, 0)
	a := NewAggregator(1, time.Hour)
	a.now = func() time.Time { return now }

	a.Update(pkt("1.1.1.1"), nil, nil)
	// Second distinct flow exceeds the cap and stays untracked, but detection
	// still gets a usable feature back.
	f := a.Update(pkt("2.2.2.2"), []fingerprint.FingerprintHit{{RuleID: "r"}}, []intel.ThreatIntel{{ID: "i"}})
	if a.Len() != 1 {
		t.Fatalf("expected flow count capped at 1, got %d", a.Len())
	}
	if f.SrcIP != "2.2.2.2" || len(f.FingerprintHits) != 1 || len(f.IntelHits) != 1 {
		t.Fatalf("transient feature should still carry packet data and hits: %+v", f)
	}
}
