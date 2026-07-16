package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"ta_node/internal/counter"
	"ta_node/internal/event"
	"ta_node/internal/flow"
)

type Engine struct {
	deviceID      string
	homeNet       []*net.IPNet
	sensorVersion string
	localHits     *counter.Window
	localWindow   int
}

func New(deviceID string) *Engine { return &Engine{deviceID: deviceID} }

// WithLocalCounter enables a node-local burst counter. windowSec is recorded on
// events so consumers know the window. A nil counter disables the feature.
// Returns the engine for chaining.
func (e *Engine) WithLocalCounter(c *counter.Window, windowSec int) *Engine {
	e.localHits = c
	e.localWindow = windowSec
	return e
}

// WithHomeNet sets the local network ranges used to classify event Direction
// (inbound/outbound/lateral/external). With no ranges, Direction stays
// "unknown". Returns the engine for chaining.
func (e *Engine) WithHomeNet(nets []*net.IPNet) *Engine {
	e.homeNet = nets
	return e
}

// WithSensorVersion stamps each event with the running build identity. Returns
// the engine for chaining.
func (e *Engine) WithSensorVersion(v string) *Engine {
	e.sensorVersion = v
	return e
}

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
		Direction:      e.direction(f.SrcIP, f.DstIP),
		FirstTime:      f.FirstTime,
		DurationMs:     durationMs(f.FirstTime, f.LastTime),
		Flows:          1,
		Packets:        f.Packets,
		Bytes:          f.Bytes,
		WireBytes:      f.WireBytes,
		App:            appContext(f),
		EvidenceFile:   f.EvidenceFile,
		PacketTimeUsec: f.PacketTimeUsec,
		SchemaVersion:  event.SchemaVersion,
		SensorVersion:  e.sensorVersion,
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
		e.stampLocalHits(&ev, f.LastTime, "fp|"+hit.RuleID)
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
		ev.IOCDescription = hit.Description
		ev.IOCExpireAt = hit.ExpireAt
		ev.RecommendedAction = hit.RecommendedAction
		ev.IOCEvidence = hit.Evidence
		ev.VolumeRole = volumeRole(f, hit.Type, hit.Value)
		localKey := hit.ID
		if localKey == "" {
			localKey = hit.Type + "|" + hit.Value
		}
		e.stampLocalHits(&ev, f.LastTime, "ioc|"+localKey)
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

// stampLocalHits records a hit for key in the node-local burst counter and
// stamps the event with the resulting count/window/first-seen. No-op when the
// counter is disabled. flowTimeUsec drives the counter clock so behavior is
// deterministic under offline PCAP replay.
func (e *Engine) stampLocalHits(ev *event.ThreatEvent, flowTimeUsec uint64, key string) {
	if e.localHits == nil {
		return
	}
	cnt, first := e.localHits.Hit(key, time.UnixMicro(int64(flowTimeUsec)))
	ev.LocalHitCount = cnt
	ev.LocalWindowSec = e.localWindow
	ev.LocalFirstSeen = uint64(first.UnixMicro())
	ev.LocalScope = "node"
}

// volumeRole tags which side of the communication the matched IOC is on, so the
// flow's byte volume reads as toward ("to_ioc") or from ("from_ioc") the IOC.
// Returns "" when it cannot be determined.
func volumeRole(f flow.FlowFeature, iocType, iocValue string) string {
	switch iocType {
	case "ip":
		switch iocValue {
		case f.DstIP:
			return "to_ioc"
		case f.SrcIP:
			return "from_ioc"
		}
	case "cidr":
		if _, n, err := net.ParseCIDR(iocValue); err == nil {
			if n.Contains(net.ParseIP(f.DstIP)) {
				return "to_ioc"
			}
			if n.Contains(net.ParseIP(f.SrcIP)) {
				return "from_ioc"
			}
		}
	case "domain", "url":
		// A domain/url IOC is the contacted host; the internal endpoint is
		// reaching out to it, so this flow's volume is toward the IOC.
		return "to_ioc"
	}
	return ""
}

// direction classifies traffic relative to the configured home network.
func (e *Engine) direction(srcIP, dstIP string) string {
	if len(e.homeNet) == 0 {
		return "unknown"
	}
	srcLocal := ipInNets(srcIP, e.homeNet)
	dstLocal := ipInNets(dstIP, e.homeNet)
	switch {
	case srcLocal && dstLocal:
		return "lateral"
	case srcLocal && !dstLocal:
		return "outbound"
	case !srcLocal && dstLocal:
		return "inbound"
	default:
		return "external"
	}
}

func ipInNets(ipStr string, nets []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// durationMs converts a flow's first/last microsecond timestamps to a duration
// in milliseconds, clamping to 0 if the values are unset or out of order.
func durationMs(firstUsec, lastUsec uint64) uint64 {
	if lastUsec <= firstUsec {
		return 0
	}
	return (lastUsec - firstUsec) / 1000
}

// appContext builds the application-layer evidence block, returning nil when no
// fields are populated so the event omits the "app" object entirely.
func appContext(f flow.FlowFeature) *event.AppContext {
	app := &event.AppContext{
		HTTPMethod:    f.HTTPMethod,
		HTTPHost:      f.HTTPHost,
		HTTPURL:       f.HTTPURL,
		UserAgent:     f.UserAgent,
		HTTPHeaders:   f.HTTPHeaders,
		HTTPBody:      f.HTTPBodySample,
		DNSQuery:      f.DNSQuery,
		DNSQType:      f.DNSQType,
		DNSAnswers:    f.DNSAnswers,
		TLSSNI:        f.SNI,
		PayloadSample: f.PayloadSample,
		ICMPSeq:       f.ICMPSeq,
	}
	if app.HTTPMethod == "" && app.HTTPHost == "" && app.HTTPURL == "" &&
		app.UserAgent == "" && len(app.HTTPHeaders) == 0 && app.HTTPBody == "" &&
		app.DNSQuery == "" && app.DNSQType == 0 && len(app.DNSAnswers) == 0 &&
		app.TLSSNI == "" && app.PayloadSample == "" && app.ICMPSeq == 0 {
		return nil
	}
	return app
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
