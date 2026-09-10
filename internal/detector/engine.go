package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"ta_node/internal/counter"
	"ta_node/internal/event"
	"ta_node/internal/flow"
	"ta_node/internal/intel"
	"ta_node/internal/parser"
)

type Engine struct {
	deviceID      string
	homeNet       []*net.IPNet
	sensorVersion string
	localHits     *counter.Window
	localWindow   int
	evidenceDir   string
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

// WithEvidenceDir sets the base directory for evidence PCAP files, used to
// construct evidence download URLs in events.
func (e *Engine) WithEvidenceDir(dir string) *Engine {
	e.evidenceDir = filepath.Clean(dir)
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
		RawPacket:      rawPacketContext(f),
		EvidenceFile:   f.EvidenceFile,
		PacketTimeUsec: f.PacketTimeUsec,
		SchemaVersion:  event.SchemaVersion,
		SensorVersion:  e.sensorVersion,
		SessionSummary: e.pairSummary(f),
		DataExfil:      e.exfilData(f),
		EvidenceFiles:  e.evidenceList(f),
		AppStats:       e.buildAppStats(f),
		Service:        detectService(f),
	}
	e.fillImpactHints(&base, f)
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
		ev.RuleStats = []event.RuleStat{{RuleID: hit.RuleID, RuleName: hit.Name, HitCount: uint64(ev.LocalHitCount), FirstSeenUsec: ev.LocalFirstSeen, LastSeenUsec: f.LastTime, Severity: "high"}}
		ev.ActionHints = e.actionHints(&ev)
		ev.SeverityBasis = e.scoreSeverity(&ev, "threat_fingerprint")
		events = append(events, ev)
	}
	payloadFeatures := e.buildPayloadFeatures(f)
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
		ev.IOCStats = []event.IOCStat{{IOCValue: hit.Value, IOCType: hit.Type, HitCount: uint64(ev.LocalHitCount), FirstSeenUsec: ev.LocalFirstSeen, LastSeenUsec: f.LastTime, ThreatSource: hit.Source, Confidence: e.iocConfidence(hit), ExpireAtUsec: hit.ExpireAt}}
		ev.ActionHints = e.actionHints(&ev)
		ev.SeverityBasis = e.scoreSeverity(&ev, "threat_intel")
		events = append(events, ev)
	}
	for i := range events {
		events[i].PayloadFeatures = payloadFeatures
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

// pairSummary extracts bidirectional session counters from the flow's pair
// stats, returning nil when no peer flow has been observed yet.
func (e *Engine) pairSummary(f flow.FlowFeature) *event.SessionSummary {
	if f.PairStats == nil {
		return nil
	}
	ps := f.PairStats
	if ps.ClientPackets == 0 && ps.ServerPackets == 0 {
		return nil
	}
	hitCount := uint64(len(f.FingerprintHits) + len(f.IntelHits))
	return &event.SessionSummary{
		FirstTimeUsec:   ps.FirstTime,
		LastTimeUsec:    ps.LastTime,
		ClientPackets:   ps.ClientPackets,
		ServerPackets:   ps.ServerPackets,
		ClientWireBytes: ps.ClientWireBytes,
		ServerWireBytes: ps.ServerWireBytes,
		HitCount:        hitCount,
	}
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

// volumeRole tags which side of the communication the matched IOC is on. When
// bidirectional pair stats are available, it distinguishes upload (client bytes
// dominate → data exfiltration) from download (server bytes dominate → payload
// delivery). Returns "" when it cannot be determined.
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
		return "to_ioc"
	}
	if f.PairStats == nil {
		return ""
	}
	cb := f.PairStats.ClientBytes
	sb := f.PairStats.ServerBytes
	switch {
	case cb > 0 && sb == 0:
		return "client_only"
	case sb > 0 && cb == 0:
		return "server_only"
	case sb > 0 && cb/sb >= 10:
		return "upload_to_ioc"
	case cb > 0 && sb/cb >= 10:
		return "download_from_ioc"
	default:
		return "bidirectional"
	}
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

func rawPacketContext(f flow.FlowFeature) *event.RawPacketContext {
	if len(f.RawPacket) == 0 {
		return nil
	}
	wireLen := f.TriggerWireLen
	if wireLen < f.CapturedLen {
		wireLen = f.CapturedLen
	}
	direction := f.MessageDirection
	if direction == "" {
		direction = "unknown"
	}
	message := &event.RawMessageContext{
		CaptureTime:      eventTime(f.PacketTimeUsec),
		CaptureTimeUsec:  f.PacketTimeUsec,
		PacketSequence:   f.PacketSequence,
		PacketHex:        hex.EncodeToString(f.RawPacket),
		PayloadHex:       hex.EncodeToString(f.RawPayload),
		PayloadText:      parser.PayloadText(f.RawPayload),
		CapturedLength:   f.CapturedLen,
		WireLength:       wireLen,
		CaptureTruncated: f.CapturedLen > 0 && wireLen > f.CapturedLen,
	}
	raw := &event.RawPacketContext{
		SessionStartTime:     eventTime(f.FirstTime),
		SessionStartTimeUsec: f.FirstTime,
		CaptureTime:          message.CaptureTime,
		CaptureTimeUsec:      message.CaptureTimeUsec,
		PacketSequence:       message.PacketSequence,
		MessageDirection:     direction,
		PacketHex:            message.PacketHex,
		PayloadHex:           message.PayloadHex,
		PayloadText:          message.PayloadText,
		CapturedLength:       message.CapturedLength,
		WireLength:           message.WireLength,
		CaptureTruncated:     message.CaptureTruncated,
	}
	if direction == "request" {
		raw.Request = message
	} else if direction == "response" {
		raw.Response = message
	}
	return raw
}

func eventTime(usec uint64) string {
	if usec == 0 {
		return ""
	}
	return time.UnixMicro(int64(usec)).UTC().Format(time.RFC3339Nano)
}

// --- schema 1.6: 量化报告辅助方法 ---

// evidenceList wraps the event's evidence PCAP file as a structured evidence record.
func (e *Engine) evidenceList(f flow.FlowFeature) []event.EvidenceFile {
	if f.EvidenceFile == "" {
		return nil
	}
	rel := f.EvidenceFile
	if e.evidenceDir != "" {
		rel = strings.TrimPrefix(rel, e.evidenceDir)
		rel = strings.TrimPrefix(rel, "/")
	}
	name := filepath.Base(rel)
	urlPath := "/api/v1/evidence/" + rel
	return []event.EvidenceFile{{
		ID:          f.EvidenceFile,
		Name:        name,
		Type:        "pcap",
		PathRef:     urlPath,
		Description: "触发包 PCAP 证据",
	}}
}

// exfilData builds data exfiltration statistics from bidirectional pair stats.
func (e *Engine) exfilData(f flow.FlowFeature) *event.DataExfil {
	if f.PairStats == nil {
		return nil
	}
	ps := f.PairStats
	if ps.ClientWireBytes == 0 && ps.ServerWireBytes == 0 {
		return nil
	}
	d := &event.DataExfil{
		TotalWireBytes: ps.ClientWireBytes + ps.ServerWireBytes,
		TotalPackets:   ps.ClientPackets + ps.ServerPackets,
		Dest:           f.DstIP,
		DestPort:       uint32(f.DstPort),
	}
	if ps.ServerWireBytes == 0 && ps.ClientWireBytes > 0 {
		d.ObservedEntries = ps.ClientPackets
	}
	if ps.ServerWireBytes > 0 && ps.ClientWireBytes == 0 {
		d.ObservedEntries = ps.ServerPackets
	}
	return d
}

// fillImpactHints populates observable impact clues from the flow's context.
func (e *Engine) fillImpactHints(ev *event.ThreatEvent, f flow.FlowFeature) {
	h := &event.ImpactHints{}
	if f.Packets > 0 {
		h.AffectedEntries = f.Packets
	}
	if ev.Proto == "tcp" && ev.DurationMs > 5000 {
		h.LatencyObservedMs = ev.DurationMs
		h.LatencyDegraded = true
	}
	if f.PairStats != nil && f.PairStats.ClientWireBytes > f.PairStats.ServerWireBytes*10 && f.PairStats.ServerWireBytes > 0 {
		h.ObservedIntent = "exfiltration"
		h.IntentBasis = "单向大流量：客户端字节远超服务端"
	}
	if h.LatencyDegraded || h.ObservedIntent != "" || h.AffectedEntries > 0 {
		ev.ImpactHints = h
	}
}

// actionHints derives recommended actions from the event's threat context.
func (e *Engine) actionHints(ev *event.ThreatEvent) []event.ActionHint {
	var hints []event.ActionHint
	if ev.IOCType == "ip" {
		hints = append(hints, event.ActionHint{
			Action:   "block_ip",
			Priority: "immediate",
			Reason:   "命中 IP 型 IOC: " + ev.IOCValue,
		})
	}
	if ev.IOCType == "domain" || ev.IOCType == "url" {
		hints = append(hints, event.ActionHint{
			Action:   "block_domain",
			Priority: "immediate",
			Reason:   "命中域名型 IOC: " + ev.IOCValue,
		})
	}
	if ev.RecommendedAction != "" {
		hints = append(hints, event.ActionHint{
			Action:   ev.RecommendedAction,
			Priority: "followup",
			Reason:   "情报推荐动作",
		})
	}
	if ev.Severity == "critical" {
		hints = append(hints, event.ActionHint{
			Action:      "save_evidence",
			Priority:    "immediate",
			Reason:      "严重级别事件，需保存证据",
			EvidenceRef: ev.EvidenceFile,
		})
	}
	return hints
}

// scoreSeverity computes a 0–100 severity score with human-readable reasons.
func (e *Engine) scoreSeverity(ev *event.ThreatEvent, model string) *event.SeverityBasis {
	score := 0
	var reasons []string

	switch ev.Severity {
	case "critical":
		score += 40
		reasons = append(reasons, "严重级别 IOC/规则")
	case "high":
		score += 25
		reasons = append(reasons, "高级别 IOC/规则")
	case "medium":
		score += 15
		reasons = append(reasons, "中级别 IOC/规则")
	default:
		score += 5
	}

	if model == "threat_intel" && ev.IOCEvidence != nil {
		score += 15
		reasons = append(reasons, "情报源置信度: "+ev.IOCEvidence.Confidence)
	}

	if ev.LocalHitCount > 10 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("窗口内高频命中 %d 次", ev.LocalHitCount))
	} else if ev.LocalHitCount > 1 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("窗口内命中 %d 次", ev.LocalHitCount))
	}

	if ev.IOCCategory != "" && ev.IOCCategory != "network_activity" {
		score += 10
		reasons = append(reasons, "威胁类型: "+ev.IOCCategory)
	}

	if ev.EventType == "c2" {
		score += 10
		reasons = append(reasons, "C2 命令与控制通信")
	}

	if ev.DataExfil != nil && ev.DataExfil.TotalWireBytes > 0 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("观测到双向流量 %.1f KB", float64(ev.DataExfil.TotalWireBytes)/1024))
	}

	if score > 100 {
		score = 100
	}
	return &event.SeverityBasis{Score: score, Reasons: reasons}
}

// iocConfidence extracts a human-readable confidence string from an IOC's evidence.
func (e *Engine) iocConfidence(hit intel.ThreatIntel) string {
	if hit.Evidence != nil && hit.Evidence.Confidence != "" {
		return hit.Evidence.Confidence
	}
	return ""
}

// buildPayloadFeatures aggregates fingerprint hits within the current packet
// by classification label, producing a per-event payload feature summary.
func (e *Engine) buildPayloadFeatures(f flow.FlowFeature) []event.PayloadFeature {
	type classAgg struct {
		count      int
		totalReqs  int
		confidence int
		sample     string
	}
	aggs := map[string]*classAgg{}
	totalReqs := 0
	if f.HTTPMethod != "" || f.HTTPURL != "" || f.HTTPStatusCode > 0 {
		totalReqs = 1
	}
	for _, hit := range f.FingerprintHits {
		c := hit.Class
		if c == "" {
			c = hit.Type
		}
		a := aggs[c]
		if a == nil {
			a = &classAgg{totalReqs: totalReqs}
			aggs[c] = a
		}
		a.count++
		if hit.Confidence > a.confidence {
			a.confidence = hit.Confidence
		}
		if a.sample == "" && hit.Sample != "" {
			a.sample = hit.Sample
		}
	}
	if len(aggs) == 0 {
		return nil
	}
	out := make([]event.PayloadFeature, 0, len(aggs))
	for name, a := range aggs {
		conf := a.confidence
		if conf == 0 {
			conf = 80
		}
		out = append(out, event.PayloadFeature{
			Name:          name,
			Count:         uint64(a.count),
			TotalRequests: uint64(a.totalReqs),
			Sample:        a.sample,
			Confidence:    conf,
		})
	}
	return out
}

// buildAppStats extracts application-layer context from the triggering packet
// as window-scoped endpoint statistics.
func (e *Engine) buildAppStats(f flow.FlowFeature) *event.AppStats {
	if f.HTTPMethod == "" && f.HTTPURL == "" && f.HTTPHost == "" && f.HTTPStatusCode == 0 {
		return nil
	}
	as := &event.AppStats{
		WindowStartUsec: f.FirstTime,
		WindowEndUsec:   f.LastTime,
		RequestCount:    1,
	}
	if f.HTTPStatusCode > 0 {
		as.ResponseCount = 1
		if f.HTTPStatusCode >= 400 && f.HTTPStatusCode < 500 {
			as.HTTP4xxCount = 1
		} else if f.HTTPStatusCode >= 500 {
			as.HTTP5xxCount = 1
		}
	}
	dur := durationMs(f.FirstTime, f.LastTime)
	if dur > 0 {
		as.P95LatencyMs = dur
		as.MaxLatencyMs = dur
	}
	if f.HTTPURL != "" {
		ep := event.AppEndpoint{
			Method: f.HTTPMethod,
			Path:   f.HTTPURL,
			Host:   f.HTTPHost,
			Count:  1,
		}
		if f.UserAgent != "" {
			ep.UserAgents = []string{f.UserAgent}
		}
		if f.HTTPBodySample != "" {
			ep.SampleBody = f.HTTPBodySample
		}
		as.Endpoints = []event.AppEndpoint{ep}
	}
	return as
}

// detectService identifies the application-layer protocol based on parsed
// payload evidence; falls back to well-known port mapping when no payload is
// present (e.g. bare TCP SYN handshake packets).
func detectService(f flow.FlowFeature) string {
	if f.HTTPMethod != "" {
		return "HTTP"
	}
	if f.DNSQuery != "" {
		return "DNS"
	}
	if f.SNI != "" {
		return "HTTPS"
	}
	switch f.DstPort {
	case 80, 8080, 8000, 8888:
		return "HTTP"
	case 443, 8443:
		return "HTTPS"
	case 53:
		return "DNS"
	case 22:
		return "SSH"
	case 21:
		return "FTP"
	case 25, 587:
		return "SMTP"
	case 110, 995:
		return "POP3"
	case 143, 993:
		return "IMAP"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 27017:
		return "MongoDB"
	default:
		return ""
	}
}

func stableEventID(f flow.FlowFeature, parts ...string) string {
	packetOrdinal := f.PacketSequence
	if packetOrdinal == 0 {
		// Preserve deterministic IDs for callers/tests that construct a feature
		// directly instead of going through Aggregator.Update.
		packetOrdinal = f.Packets
	}
	keyParts := []string{
		fmt.Sprintf("%d", f.FirstTime),
		// A new event ID is created for every packet occurrence. This prevents
		// SQLite's UNIQUE(event_id) guard from collapsing repeated hits in the
		// same long-lived flow, while retries of the same occurrence remain
		// idempotent.
		fmt.Sprintf("%d", f.PacketTimeUsec),
		fmt.Sprintf("%d", packetOrdinal),
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
