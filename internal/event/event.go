package event

import "ta_node/internal/intel"

// SchemaVersion identifies the event payload layout. Bump it whenever fields
// are added or their meaning changes so downstream consumers (AI analysis /
// management ingest) can adapt to format evolution.
const SchemaVersion = "1.6"

// AppContext carries application-layer evidence from the packet that triggered
// the event. All fields are best-effort and may be empty depending on protocol.
type AppContext struct {
	HTTPMethod  string            `json:"http_method,omitempty"`
	HTTPHost    string            `json:"http_host,omitempty"`
	HTTPURL     string            `json:"http_url,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	HTTPHeaders map[string]string `json:"http_headers,omitempty"`
	HTTPBody    string            `json:"http_body_sample,omitempty"`

	DNSQuery   string   `json:"dns_query,omitempty"`
	DNSQType   uint16   `json:"dns_qtype,omitempty"`
	DNSAnswers []string `json:"dns_answers,omitempty"`

	// TLSSNI is the server_name from the TLS ClientHello of an HTTPS flow,
	// carried so an analyst/AI can see which domain an encrypted hit was for.
	TLSSNI string `json:"tls_sni,omitempty"`

	PayloadSample string `json:"payload_sample,omitempty"`
	ICMPSeq       uint32 `json:"icmp_seq,omitempty"`
}

// RawMessageContext is one captured side of an application exchange. It can be
// embedded as request/response evidence without changing the legacy flat
// RawPacketContext fields consumed by older management endpoints.
type RawMessageContext struct {
	CaptureTime      string `json:"capture_time,omitempty"`
	CaptureTimeUsec  uint64 `json:"capture_time_usec,omitempty"`
	PacketSequence   uint64 `json:"packet_sequence,omitempty"`
	PacketHex        string `json:"packet_hex"`
	PayloadHex       string `json:"payload_hex,omitempty"`
	PayloadText      string `json:"payload_text,omitempty"`
	CapturedLength   uint32 `json:"captured_length,omitempty"`
	WireLength       uint32 `json:"wire_length,omitempty"`
	CaptureTruncated bool   `json:"capture_truncated,omitempty"`
	TCPSeq           uint32 `json:"tcp_seq,omitempty"`
	TCPAck           uint32 `json:"tcp_ack,omitempty"`
	Retransmission   bool   `json:"retransmission,omitempty"`
}

// RawPacketContext is the immutable packet evidence for this event occurrence.
// Request and Response support a tabbed management UI. The flat packet fields
// remain populated for backward compatibility and describe the packet that
// directly triggered the event. A counterpart is never guessed or borrowed.
type RawPacketContext struct {
	SessionStartTime     string             `json:"session_start_time,omitempty"`
	SessionStartTimeUsec uint64             `json:"session_start_time_usec,omitempty"`
	CaptureTime          string             `json:"capture_time,omitempty"`
	CaptureTimeUsec      uint64             `json:"capture_time_usec,omitempty"`
	PacketSequence       uint64             `json:"packet_sequence,omitempty"`
	MessageDirection     string             `json:"message_direction,omitempty"`
	PacketHex            string             `json:"packet_hex"`
	PayloadHex           string             `json:"payload_hex,omitempty"`
	PayloadText          string             `json:"payload_text,omitempty"`
	CapturedLength       uint32             `json:"captured_length,omitempty"`
	WireLength           uint32             `json:"wire_length,omitempty"`
	CaptureTruncated     bool               `json:"capture_truncated,omitempty"`
	Request              *RawMessageContext `json:"request,omitempty"`
	Response             *RawMessageContext `json:"response,omitempty"`
}

// ExchangeMessageContext is a bounded, reassembled view of one side of an
// application transaction. Packets preserves the captured fragments that were
// retained within the configured limits; complete session evidence belongs in
// the referenced PCAP rather than an unbounded event JSON document.
type ExchangeMessageContext struct {
	CaptureStartTimeUsec uint64              `json:"capture_start_time_usec,omitempty"`
	CaptureEndTimeUsec   uint64              `json:"capture_end_time_usec,omitempty"`
	PacketCount          uint64              `json:"packet_count,omitempty"`
	CapturedBytes        uint64              `json:"captured_bytes,omitempty"`
	WireBytes            uint64              `json:"wire_bytes,omitempty"`
	Retransmissions      uint64              `json:"retransmissions,omitempty"`
	ReassembledHex       string              `json:"reassembled_hex,omitempty"`
	ReassembledText      string              `json:"reassembled_text,omitempty"`
	Truncated            bool                `json:"truncated,omitempty"`
	ReassemblyIncomplete bool                `json:"reassembly_incomplete,omitempty"`
	Packets              []RawMessageContext `json:"packets,omitempty"`
}

// ExchangeContext links the request and response evidence for one protocol
// transaction. ResponseStatus is pending, complete, or not_captured.
type ExchangeContext struct {
	Request        *ExchangeMessageContext `json:"request,omitempty"`
	Response       *ExchangeMessageContext `json:"response,omitempty"`
	ResponseStatus string                  `json:"response_status,omitempty"`
}

// SessionSummary contains bounded bidirectional counters for the canonical
// conversation that owns an event occurrence.
type SessionSummary struct {
	FirstTimeUsec   uint64 `json:"first_time_usec,omitempty"`
	LastTimeUsec    uint64 `json:"last_time_usec,omitempty"`
	ClientPackets   uint64 `json:"client_packets,omitempty"`
	ServerPackets   uint64 `json:"server_packets,omitempty"`
	ClientWireBytes uint64 `json:"client_wire_bytes,omitempty"`
	ServerWireBytes uint64 `json:"server_wire_bytes,omitempty"`
	HitCount        uint64 `json:"hit_count,omitempty"`
	Midstream       bool   `json:"midstream,omitempty"`
}

type ThreatEvent struct {
	EventID   string `json:"event_id"`
	DeviceID  string `json:"device_id"`
	EventTime uint64 `json:"event_time"`

	EventType string `json:"event_type"`
	EventName string `json:"event_name"`
	Severity  string `json:"severity"`
	Model     string `json:"model"`

	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
	Proto   string `json:"proto"`

	Direction    string `json:"direction"`
	ThreatSource string `json:"threat_source"`

	IOCType        string   `json:"ioc_type,omitempty"`
	IOCValue       string   `json:"ioc_value,omitempty"`
	IOCCategory    string   `json:"ioc_category,omitempty"`
	IOCID          string   `json:"ioc_id,omitempty"`
	IOCSource      string   `json:"ioc_source,omitempty"`
	IOCTags        []string `json:"ioc_tags,omitempty"`
	IOCDescription string   `json:"ioc_description,omitempty"`
	IOCExpireAt    int64    `json:"ioc_expire_at,omitempty"`

	RecommendedAction string          `json:"recommended_action,omitempty"`
	IOCEvidence       *intel.Evidence `json:"ioc_evidence,omitempty"`

	RuleID      string `json:"rule_id,omitempty"`
	ThreatIndex string `json:"threat_index,omitempty"`

	FirstTime  uint64 `json:"first_time,omitempty"`
	DurationMs uint64 `json:"duration_ms,omitempty"`
	Flows      uint64 `json:"flows"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	// WireBytes is the on-wire data size of this communication (L2-L4 headers
	// included); Bytes is payload only. VolumeRole tags which side of the
	// communication the matched IOC is on, so this flow's volume reads as
	// "to_ioc" (data toward the IOC, e.g. exfiltration) or "from_ioc" (data
	// from the IOC, e.g. payload download). Empty when not an IOC hit or
	// undetermined.
	WireBytes  uint64 `json:"wire_bytes,omitempty"`
	VolumeRole string `json:"volume_role,omitempty"`

	App *AppContext `json:"app,omitempty"`
	// RawPacket is populated for every newly generated packet hit and is pushed
	// unchanged through the durable queue to the management endpoint.
	RawPacket *RawPacketContext `json:"raw_packet,omitempty"`

	// SessionID groups both directions of one bounded connection; TransactionID
	// groups one request/response exchange. EventID remains unique per hit.
	SessionID       string           `json:"session_id,omitempty"`
	TransactionID   string           `json:"transaction_id,omitempty"`
	ContextRevision uint64           `json:"context_revision,omitempty"`
	ContextFinal    bool             `json:"context_final,omitempty"`
	Exchange        *ExchangeContext `json:"exchange,omitempty"`
	SessionSummary  *SessionSummary  `json:"session_summary,omitempty"`

	// Local* are a NODE-SCOPED, approximate burst signal: how many times this
	// threat key (IOC/rule) fired on THIS node within LocalWindowSec. It is a
	// triage hint, not an authoritative count — global/long-window counting
	// belongs on the management side (see task plan §7.1).
	LocalHitCount  int    `json:"local_hit_count,omitempty"`
	LocalWindowSec int    `json:"local_window_sec,omitempty"`
	LocalFirstSeen uint64 `json:"local_first_seen,omitempty"`
	LocalScope     string `json:"local_scope,omitempty"`

	EvidenceFile   string         `json:"evidence_file,omitempty"`
	PacketTimeUsec uint64         `json:"packet_time_usec,omitempty"`
	RawFeature     map[string]any `json:"raw_feature,omitempty"`

	SchemaVersion string `json:"schema_version,omitempty"`
	SensorVersion string `json:"sensor_version,omitempty"`

	// Aliases consumed by the management ingest endpoint
	// (/internal/event/push -> LyEventToDeepSOC): it reads "protocol" (not
	// "proto") and "occurrence_time" (not "event_time").
	Protocol       string `json:"protocol,omitempty"`
	OccurrenceTime string `json:"occurrence_time,omitempty"`

	// --- schema 1.6: 量化报告字段 ---

	AppStats       *AppStats       `json:"app_stats,omitempty"`
	PayloadFeatures []PayloadFeature `json:"payload_features,omitempty"`
	DataExfil      *DataExfil      `json:"data_exfil,omitempty"`
	IOCStats       []IOCStat       `json:"ioc_stats,omitempty"`
	RuleStats      []RuleStat      `json:"rule_stats,omitempty"`
	ImpactHints    *ImpactHints    `json:"impact_hints,omitempty"`
	ActionHints    []ActionHint    `json:"action_hints,omitempty"`
	EvidenceFiles  []EvidenceFile  `json:"evidence_files,omitempty"`
	SeverityBasis  *SeverityBasis  `json:"severity_basis,omitempty"`
	Service        string          `json:"service,omitempty"`
}

// --- 1.6 支撑类型 ---

// AppStats holds per-endpoint application-layer aggregation within the node's local window.
type AppStats struct {
	WindowStartUsec uint64      `json:"window_start_usec"`
	WindowEndUsec   uint64      `json:"window_end_usec"`
	RequestCount    uint64      `json:"request_count"`
	ResponseCount   uint64      `json:"response_count,omitempty"`
	HTTP4xxCount    uint64      `json:"http_4xx_count,omitempty"`
	HTTP5xxCount    uint64      `json:"http_5xx_count,omitempty"`
	P95LatencyMs    uint64      `json:"p95_latency_ms,omitempty"`
	MaxLatencyMs    uint64      `json:"max_latency_ms,omitempty"`
	Endpoints       []AppEndpoint `json:"endpoints,omitempty"`
}

type AppEndpoint struct {
	Method      string   `json:"method,omitempty"`
	Path        string   `json:"path,omitempty"`
	Host        string   `json:"host,omitempty"`
	Count       uint64   `json:"count"`
	UserAgents  []string `json:"user_agents,omitempty"`
	SampleBody  string   `json:"sample_request_body,omitempty"`
}

// PayloadFeature describes one category of malicious payload found in the window.
type PayloadFeature struct {
	Name          string `json:"name"`
	Count         uint64 `json:"count"`
	TotalRequests uint64 `json:"total_requests"`
	Sample        string `json:"sample,omitempty"`
	Confidence    int    `json:"confidence"`
	EvidenceRef   string `json:"evidence_ref,omitempty"`
}

// DataExfil reports observed exfiltration patterns within the window.
type DataExfil struct {
	TotalWireBytes    uint64            `json:"total_wire_bytes"`
	TotalPackets      uint64            `json:"total_packets"`
	Dest              string            `json:"dest,omitempty"`
	DestPort          uint32            `json:"dest_port,omitempty"`
	Encrypted         bool              `json:"encrypted,omitempty"`
	SensitiveKeywords []SensitiveKeyword `json:"sensitive_keywords,omitempty"`
	ObservedEntries   uint64            `json:"observed_entries,omitempty"`
}

type SensitiveKeyword struct {
	Keyword string `json:"keyword"`
	Count   uint64 `json:"count"`
	Sample  string `json:"sample,omitempty"`
}

// IOCStat reports per-IOC window-level statistics.
type IOCStat struct {
	IOCValue      string   `json:"ioc_value"`
	IOCType       string   `json:"ioc_type"`
	HitCount      uint64   `json:"hit_count"`
	FirstSeenUsec uint64   `json:"first_seen_usec"`
	LastSeenUsec  uint64   `json:"last_seen_usec"`
	ThreatSource  string   `json:"threat_source,omitempty"`
	Confidence    string   `json:"confidence,omitempty"`
	MatchedRules  []string `json:"matched_rules,omitempty"`
	ExpireAtUsec  int64    `json:"expire_at_usec,omitempty"`
}

// RuleStat reports per-rule window-level statistics.
type RuleStat struct {
	RuleID        string `json:"rule_id"`
	RuleName      string `json:"rule_name,omitempty"`
	HitCount      uint64 `json:"hit_count"`
	FirstSeenUsec uint64 `json:"first_seen_usec"`
	LastSeenUsec  uint64 `json:"last_seen_usec"`
	Severity      string `json:"severity,omitempty"`
	EvidenceRef   string `json:"evidence_ref,omitempty"`
}

// ImpactHints carries observable impact clues — facts only, no conclusions.
type ImpactHints struct {
	ErrorRatePercent   float64 `json:"error_rate_percent,omitempty"`
	LatencyDegraded    bool    `json:"latency_degraded,omitempty"`
	LatencyBaselineMs  uint64  `json:"latency_baseline_ms,omitempty"`
	LatencyObservedMs  uint64  `json:"latency_observed_ms,omitempty"`
	AffectedEntries    uint64  `json:"affected_entries,omitempty"`
	ObservedIntent     string  `json:"observed_intent,omitempty"`
	IntentBasis        string  `json:"intent_basis,omitempty"`
}

// ActionHint suggests an observable response action.
type ActionHint struct {
	Action      string `json:"action"`
	Priority    string `json:"priority"`
	Reason      string `json:"reason,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// EvidenceFile metadata for an attached artifact.
type EvidenceFile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	PathRef     string `json:"path_ref,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Size        uint64 `json:"size,omitempty"`
	Description string `json:"description,omitempty"`
}

// SeverityBasis explains the scoring rationale.
type SeverityBasis struct {
	Score   int      `json:"score"`
	Reasons []string `json:"reasons"`
}
