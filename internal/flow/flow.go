package flow

import (
	"ta_node/internal/fingerprint"
	"ta_node/internal/intel"
)

type FlowFeature struct {
	FirstTime uint64 `json:"first_time"`
	LastTime  uint64 `json:"last_time"`
	SrcIP     string `json:"src_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   uint16 `json:"dst_port"`
	Proto     string `json:"proto"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`

	HTTPHost string `json:"http_host,omitempty"`
	HTTPURL  string `json:"http_url,omitempty"`
	DNSQuery string `json:"dns_query,omitempty"`

	FingerprintHits []fingerprint.FingerprintHit `json:"fingerprint_hits,omitempty"`
	IntelHits       []intel.ThreatIntel          `json:"intel_hits,omitempty"`
	EvidenceFile    string                       `json:"evidence_file,omitempty"`
	PacketTimeUsec  uint64                       `json:"packet_time_usec,omitempty"`
}
