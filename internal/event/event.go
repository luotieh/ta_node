package event

import "ta_node/internal/intel"

// SchemaVersion identifies the event payload layout. Bump it whenever fields
// are added or their meaning changes so downstream consumers (AI analysis /
// management ingest) can adapt to format evolution.
const SchemaVersion = "1.3"

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
}
