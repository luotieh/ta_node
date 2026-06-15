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
