package event

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

	IOCType     string `json:"ioc_type,omitempty"`
	IOCValue    string `json:"ioc_value,omitempty"`
	IOCCategory string `json:"ioc_category,omitempty"`

	RuleID      string `json:"rule_id,omitempty"`
	ThreatIndex string `json:"threat_index,omitempty"`

	Flows   uint64 `json:"flows"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`

	EvidenceFile   string         `json:"evidence_file,omitempty"`
	PacketTimeUsec uint64         `json:"packet_time_usec,omitempty"`
	RawFeature     map[string]any `json:"raw_feature,omitempty"`
}
