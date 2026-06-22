package detector

import (
	"net"
	"testing"

	"ta_node/internal/event"
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

func TestDetectAttachesAuxiliaryContext(t *testing.T) {
	_, home, _ := net.ParseCIDR("10.0.0.0/8")
	det := New("node-1").
		WithHomeNet([]*net.IPNet{home}).
		WithSensorVersion("test-build")
	f := flow.FlowFeature{
		FirstTime:      1_000_000,  // 1s in usec
		LastTime:       3_500_000,  // 3.5s in usec -> 2500ms duration
		SrcIP:          "10.0.0.5", // local -> outbound
		SrcPort:        40000,
		DstIP:          "1.2.3.4",
		DstPort:        80,
		Proto:          "tcp",
		Packets:        3,
		Bytes:          512,
		HTTPMethod:     "POST",
		HTTPHost:       "evil.example.com",
		HTTPURL:        "http://evil.example.com/upload",
		UserAgent:      "curl/8.0",
		HTTPHeaders:    map[string]string{"content-type": "application/octet-stream"},
		HTTPBodySample: "MZ...",
		PayloadSample:  "POST /upload HTTP/1.1",
		IntelHits: []intel.ThreatIntel{
			{ID: "ioc-1", Type: "domain", Value: "evil.example.com", Source: "hub", Category: "c2", Severity: "high", Description: "known C2", ExpireAt: 4_102_444_800},
		},
	}
	events := det.Detect(f)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Direction != "outbound" {
		t.Errorf("direction: want outbound, got %q", ev.Direction)
	}
	if ev.DurationMs != 2500 {
		t.Errorf("duration_ms: want 2500, got %d", ev.DurationMs)
	}
	if ev.FirstTime != 1_000_000 {
		t.Errorf("first_time: want 1000000, got %d", ev.FirstTime)
	}
	if ev.SchemaVersion != event.SchemaVersion || ev.SensorVersion != "test-build" {
		t.Errorf("version stamps missing: schema=%q sensor=%q", ev.SchemaVersion, ev.SensorVersion)
	}
	if ev.IOCDescription != "known C2" || ev.IOCExpireAt != 4_102_444_800 {
		t.Errorf("ioc metadata missing: desc=%q expire=%d", ev.IOCDescription, ev.IOCExpireAt)
	}
	if ev.App == nil {
		t.Fatal("expected app context, got nil")
	}
	if ev.App.HTTPMethod != "POST" || ev.App.UserAgent != "curl/8.0" || ev.App.HTTPBody != "MZ..." {
		t.Errorf("app context not populated: %+v", ev.App)
	}
	if ev.App.HTTPHeaders["content-type"] != "application/octet-stream" {
		t.Errorf("app headers not populated: %+v", ev.App.HTTPHeaders)
	}
}

func TestDetectDirectionDefaultsUnknownWithoutHomeNet(t *testing.T) {
	det := New("node-1")
	f := flow.FlowFeature{SrcIP: "10.0.0.5", DstIP: "1.2.3.4", Proto: "tcp",
		IntelHits: []intel.ThreatIntel{{ID: "x", Type: "ip", Value: "1.2.3.4", Category: "c2", Severity: "low"}}}
	ev := det.Detect(f)[0]
	if ev.Direction != "unknown" {
		t.Errorf("want unknown without home_net, got %q", ev.Direction)
	}
	if ev.App != nil {
		t.Errorf("want nil app context when no app-layer fields, got %+v", ev.App)
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
