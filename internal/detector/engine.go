package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"ta_node/internal/event"
	"ta_node/internal/flow"
)

type Engine struct {
	deviceID string
}

func New(deviceID string) *Engine { return &Engine{deviceID: deviceID} }

func (e *Engine) Detect(f flow.FlowFeature) []event.ThreatEvent {
	var events []event.ThreatEvent
	base := event.ThreatEvent{
		DeviceID:       e.deviceID,
		EventTime:      f.LastTime,
		OccurrenceTime: occurrenceTime(f.LastTime),
		SrcIP:          f.SrcIP,
		SrcPort:        f.SrcPort,
		DstIP:          f.DstIP,
		DstPort:        f.DstPort,
		Proto:          f.Proto,
		Protocol:       f.Proto,
		Direction:      "unknown",
		Flows:          1,
		Packets:        f.Packets,
		Bytes:          f.Bytes,
		EvidenceFile:   f.EvidenceFile,
		PacketTimeUsec: f.PacketTimeUsec,
	}
	seen := map[string]bool{}
	for _, hit := range f.FingerprintHits {
		ev := base
		ev.EventID = stableEventID(f, "fingerprint", hit.RuleID, hit.Type, hit.Name, fmt.Sprintf("%d:%d", hit.MatchFrom, hit.MatchTo))
		if seen[ev.EventID] {
			continue
		}
		seen[ev.EventID] = true
		ev.EventType = hit.Type
		ev.EventName = hit.Name
		ev.Severity = "high"
		ev.Model = "threat_fingerprint"
		ev.ThreatSource = "payload_rule"
		ev.RuleID = hit.RuleID
		ev.ThreatIndex = fmt.Sprintf("%d,%d", hit.MatchFrom, hit.MatchTo)
		ev.PacketTimeUsec = hit.HitTimeUsec
		if hit.EvidenceFile != "" {
			ev.EvidenceFile = hit.EvidenceFile
		}
		events = append(events, ev)
	}
	for _, hit := range f.IntelHits {
		ev := base
		ev.EventID = stableEventID(f, "intel", hit.ID, hit.Type, hit.Value, hit.Source)
		if seen[ev.EventID] {
			continue
		}
		seen[ev.EventID] = true
		ev.EventType = hit.Category
		ev.EventName = hit.Value
		ev.Severity = hit.Severity
		ev.Model = "threat_intel"
		ev.ThreatSource = "intel_" + hit.Type
		ev.IOCType = hit.Type
		ev.IOCValue = hit.Value
		ev.IOCCategory = hit.Category
		ev.IOCID = hit.ID
		ev.IOCSource = hit.Source
		ev.IOCTags = hit.Tags
		events = append(events, ev)
	}
	return events
}

// occurrenceTime renders a microsecond epoch (FlowFeature timestamps are
// time.UnixMicro values) as RFC3339 UTC for the management ingest endpoint,
// which reads "occurrence_time". Returns "" when unset so the server falls
// back to its own receive time.
func occurrenceTime(usec uint64) string {
	if usec == 0 {
		return ""
	}
	return time.UnixMicro(int64(usec)).UTC().Format(time.RFC3339)
}

func stableEventID(f flow.FlowFeature, parts ...string) string {
	keyParts := []string{
		fmt.Sprintf("%d", f.FirstTime),
		f.SrcIP,
		fmt.Sprintf("%d", f.SrcPort),
		f.DstIP,
		fmt.Sprintf("%d", f.DstPort),
		strings.ToLower(f.Proto),
	}
	keyParts = append(keyParts, parts...)
	sum := sha256.Sum256([]byte(strings.Join(keyParts, "|")))
	return "evt-" + hex.EncodeToString(sum[:16])
}
