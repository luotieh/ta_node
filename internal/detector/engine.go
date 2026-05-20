package detector

import (
	"fmt"

	"github.com/google/uuid"

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
		SrcIP:          f.SrcIP,
		SrcPort:        f.SrcPort,
		DstIP:          f.DstIP,
		DstPort:        f.DstPort,
		Proto:          f.Proto,
		Direction:      "unknown",
		Flows:          1,
		Packets:        f.Packets,
		Bytes:          f.Bytes,
		EvidenceFile:   f.EvidenceFile,
		PacketTimeUsec: f.PacketTimeUsec,
	}
	for _, hit := range f.FingerprintHits {
		ev := base
		ev.EventID = uuid.NewString()
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
		ev.EventID = uuid.NewString()
		ev.EventType = hit.Category
		ev.EventName = hit.Value
		ev.Severity = hit.Severity
		ev.Model = "threat_intel"
		ev.ThreatSource = "intel_" + hit.Type
		ev.IOCType = hit.Type
		ev.IOCValue = hit.Value
		ev.IOCCategory = hit.Category
		events = append(events, ev)
	}
	return events
}
