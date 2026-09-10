package detector

import (
	"net"
	"testing"
	"time"

	"ta_node/internal/counter"
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

func TestDetectCreatesDistinctEventIDForEveryPacketHit(t *testing.T) {
	det := New("node-1")
	mk := func(packetTime uint64, packetNumber uint64) flow.FlowFeature {
		return flow.FlowFeature{
			FirstTime: 100, LastTime: packetTime, PacketTimeUsec: packetTime,
			SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "1.2.3.4", DstPort: 80,
			Proto: "tcp", Packets: packetNumber,
			IntelHits: []intel.ThreatIntel{{ID: "ioc-1", Type: "ip", Value: "1.2.3.4", Category: "c2", Severity: "high"}},
		}
	}
	first := det.Detect(mk(1_000, 1))[0]
	second := det.Detect(mk(2_000, 2))[0]
	if first.EventID == second.EventID {
		t.Fatalf("separate packet hits were collapsed into event %q", first.EventID)
	}
	if retry := det.Detect(mk(2_000, 2))[0]; retry.EventID != second.EventID {
		t.Fatalf("retry id changed: first=%q retry=%q", second.EventID, retry.EventID)
	}
}

func TestDetectAttachesRawTriggerPacket(t *testing.T) {
	det := New("node-1")
	f := flow.FlowFeature{
		FirstTime: 1_000_000, LastTime: 2_000_000, PacketTimeUsec: 2_000_000,
		SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "1.2.3.4", DstPort: 80,
		Proto: "tcp", Packets: 2,
		RawPacket:   []byte{0xde, 0xad, 0xbe, 0xef},
		RawPayload:  []byte("POST /x HTTP/1.1\r\n\r\nbody"),
		CapturedLen: 4, TriggerWireLen: 8, MessageDirection: "request",
		IntelHits: []intel.ThreatIntel{{ID: "ioc-1", Type: "ip", Value: "1.2.3.4", Category: "c2", Severity: "high"}},
	}
	ev := det.Detect(f)[0]
	if ev.RawPacket == nil {
		t.Fatal("raw trigger packet missing")
	}
	raw := ev.RawPacket
	if raw.PacketHex != "deadbeef" || raw.PayloadHex != "504f5354202f7820485454502f312e310d0a0d0a626f6479" ||
		raw.PayloadText != string(f.RawPayload) || raw.MessageDirection != "request" {
		t.Fatalf("raw packet views wrong: %+v", raw)
	}
	if raw.CapturedLength != 4 || raw.WireLength != 8 || !raw.CaptureTruncated {
		t.Fatalf("raw packet lengths wrong: %+v", raw)
	}
	if raw.Request == nil || raw.Response != nil {
		t.Fatalf("request/response evidence wrong: %+v", raw)
	}
	if raw.Request.PacketHex != raw.PacketHex || raw.Request.PayloadText != raw.PayloadText || !raw.Request.CaptureTruncated {
		t.Fatalf("nested request evidence wrong: %+v", raw.Request)
	}
	if raw.SessionStartTime != "1970-01-01T00:00:01Z" || raw.CaptureTime != "1970-01-01T00:00:02Z" {
		t.Fatalf("raw packet times wrong: %+v", raw)
	}
	if ev.SchemaVersion != "1.6" {
		t.Fatalf("schema version = %q, want 1.6", ev.SchemaVersion)
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
			{ID: "ioc-1", Type: "domain", Value: "evil.example.com", Source: "hub", Category: "c2", Severity: "high", Description: "known C2", ExpireAt: 4_102_444_800,
				RecommendedAction: "block_and_report",
				Evidence:          &intel.Evidence{Activity: "Camp", Confidence: "high (1 source)", TLP: "white"}},
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
	if ev.RecommendedAction != "block_and_report" {
		t.Errorf("recommended_action not propagated: %q", ev.RecommendedAction)
	}
	if ev.IOCEvidence == nil || ev.IOCEvidence.TLP != "white" || ev.IOCEvidence.Confidence != "high (1 source)" {
		t.Errorf("ioc_evidence not propagated: %+v", ev.IOCEvidence)
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

func TestDetectVolumeRoleAndWireBytes(t *testing.T) {
	det := New("node-1")
	cases := []struct {
		name     string
		srcIP    string
		dstIP    string
		iocType  string
		iocValue string
		want     string
	}{
		{"ip dst is ioc -> to_ioc", "10.0.0.5", "1.2.3.4", "ip", "1.2.3.4", "to_ioc"},
		{"ip src is ioc -> from_ioc", "1.2.3.4", "10.0.0.5", "ip", "1.2.3.4", "from_ioc"},
		{"cidr dst is ioc -> to_ioc", "10.0.0.5", "1.2.3.4", "cidr", "1.2.3.0/24", "to_ioc"},
		{"domain -> to_ioc", "10.0.0.5", "1.2.3.4", "domain", "evil.example.com", "to_ioc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := flow.FlowFeature{
				SrcIP: tc.srcIP, DstIP: tc.dstIP, Proto: "tcp", WireBytes: 4096,
				IntelHits: []intel.ThreatIntel{{ID: "i1", Type: tc.iocType, Value: tc.iocValue, Category: "c2", Severity: "high"}},
			}
			ev := det.Detect(f)[0]
			if ev.VolumeRole != tc.want {
				t.Errorf("volume_role: want %q, got %q", tc.want, ev.VolumeRole)
			}
			if ev.WireBytes != 4096 {
				t.Errorf("wire_bytes: want 4096, got %d", ev.WireBytes)
			}
		})
	}
}

func TestDetectStampsLocalHitCount(t *testing.T) {
	ctr := counter.New(60*time.Second, 100)
	det := New("node-1").WithLocalCounter(ctr, 60)
	mk := func(lastUsec uint64) flow.FlowFeature {
		return flow.FlowFeature{
			LastTime: lastUsec, SrcIP: "10.0.0.5", DstIP: "1.2.3.4", Proto: "tcp",
			IntelHits: []intel.ThreatIntel{{ID: "ioc-1", Type: "ip", Value: "1.2.3.4", Category: "c2", Severity: "high"}},
		}
	}
	// Two hits on the same IOC within the window -> count climbs to 2.
	ev1 := det.Detect(mk(1_000_000))[0]
	if ev1.LocalHitCount != 1 || ev1.LocalWindowSec != 60 || ev1.LocalScope != "node" {
		t.Fatalf("first hit stamps wrong: count=%d window=%d scope=%q", ev1.LocalHitCount, ev1.LocalWindowSec, ev1.LocalScope)
	}
	ev2 := det.Detect(mk(2_000_000))[0]
	if ev2.LocalHitCount != 2 {
		t.Errorf("second hit count: want 2, got %d", ev2.LocalHitCount)
	}
	if ev2.LocalFirstSeen != 1_000_000 {
		t.Errorf("local_first_seen: want 1000000, got %d", ev2.LocalFirstSeen)
	}
}

func TestDetectWithoutCounterLeavesLocalFieldsZero(t *testing.T) {
	det := New("node-1")
	f := flow.FlowFeature{SrcIP: "10.0.0.5", DstIP: "1.2.3.4", Proto: "tcp",
		IntelHits: []intel.ThreatIntel{{ID: "i", Type: "ip", Value: "1.2.3.4", Category: "c2", Severity: "low"}}}
	ev := det.Detect(f)[0]
	if ev.LocalHitCount != 0 || ev.LocalScope != "" {
		t.Errorf("local fields should be unset without a counter: %+v", ev)
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
