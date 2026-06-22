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

	// Application-layer context from the triggering packet. These are attached
	// only to the FlowFeature returned by Aggregator.Update (not persisted on
	// the stored flow) so per-flow memory stays bounded.
	HTTPMethod     string            `json:"http_method,omitempty"`
	UserAgent      string            `json:"user_agent,omitempty"`
	HTTPHeaders    map[string]string `json:"http_headers,omitempty"`
	HTTPBodySample string            `json:"http_body_sample,omitempty"`
	DNSQType       uint16            `json:"dns_qtype,omitempty"`
	DNSAnswers     []string          `json:"dns_answers,omitempty"`
	PayloadSample  string            `json:"payload_sample,omitempty"`
	ICMPSeq        uint32            `json:"icmp_seq,omitempty"`

	FingerprintHits []fingerprint.FingerprintHit `json:"fingerprint_hits,omitempty"`
	IntelHits       []intel.ThreatIntel          `json:"intel_hits,omitempty"`
	EvidenceFile    string                       `json:"evidence_file,omitempty"`
	PacketTimeUsec  uint64                       `json:"packet_time_usec,omitempty"`
}
