package detector

import (
	"testing"

	"ta_node/internal/fingerprint"
	"ta_node/internal/flow"
	"ta_node/internal/intel"
)

func TestDetectUsesStableEventIDForDuplicateHitsInSameFlow(t *testing.T) {
	det := New("node-1")
	f := flow.FlowFeature{
		FirstTime: 100,
		LastTime:  110,
		SrcIP:     "10.0.0.1",
		SrcPort:   12345,
		DstIP:     "1.2.3.4",
		DstPort:   80,
		Proto:     "tcp",
		Packets:   2,
		Bytes:     200,
		IntelHits: []intel.ThreatIntel{
			{ID: "ioc-1", Type: "ip", Value: "1.2.3.4", Source: "local", Category: "c2", Severity: "high"},
			{ID: "ioc-1", Type: "ip", Value: "1.2.3.4", Source: "local", Category: "c2", Severity: "high"},
		},
	}
	events := det.Detect(f)
	if len(events) != 1 {
		t.Fatalf("expected duplicate intel hits to collapse to 1 event, got %d", len(events))
	}
	firstID := events[0].EventID
	events = det.Detect(f)
	if len(events) != 1 || events[0].EventID != firstID {
		t.Fatalf("event id should be stable across repeated detection, first=%q next=%#v", firstID, events)
	}
}

func TestDetectKeepsDistinctRulesAndIOCs(t *testing.T) {
	det := New("node-1")
	f := flow.FlowFeature{
		FirstTime: 100,
		LastTime:  100,
		SrcIP:     "10.0.0.1",
		SrcPort:   12345,
		DstIP:     "1.2.3.4",
		DstPort:   80,
		Proto:     "tcp",
		FingerprintHits: []fingerprint.FingerprintHit{
			{RuleID: "r1", Type: "MINE", Name: "rule1", MatchFrom: 1, MatchTo: 2},
			{RuleID: "r2", Type: "MINE", Name: "rule2", MatchFrom: 1, MatchTo: 2},
		},
		IntelHits: []intel.ThreatIntel{
			{ID: "ioc-1", Type: "ip", Value: "1.2.3.4", Source: "local", Category: "c2", Severity: "high"},
			{ID: "ioc-2", Type: "domain", Value: "evil.example.com", Source: "local", Category: "malware", Severity: "high"},
		},
	}
	events := det.Detect(f)
	if len(events) != 4 {
		t.Fatalf("expected distinct hits to produce 4 events, got %d", len(events))
	}
	seen := map[string]bool{}
	for _, ev := range events {
		if seen[ev.EventID] {
			t.Fatalf("duplicate event id for distinct hits: %q", ev.EventID)
		}
		seen[ev.EventID] = true
	}
}
