package flow

import (
	"bytes"
	"fmt"
	"net"

	"ta_node/internal/fingerprint"
	"ta_node/internal/intel"
)

// PairKey returns a deterministic canonical key from two IP:port endpoints.
// Sorting by binary IP comparison ensures forward and reverse directions of the
// same conversation produce the same key.
func PairKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) string {
	a := net.ParseIP(srcIP)
	b := net.ParseIP(dstIP)
	if bytes.Compare(a, b) > 0 || (bytes.Equal(a, b) && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}
	return fmt.Sprintf("%s:%d-%s:%d-%s", srcIP, srcPort, dstIP, dstPort, proto)
}

// IsForward reports whether the given source endpoint is the "smaller" side of
// the pair, i.e. the packet flows in the same direction as the canonical key.
func IsForward(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) bool {
	directKey := fmt.Sprintf("%s:%d-%s:%d-%s", srcIP, srcPort, dstIP, dstPort, proto)
	return PairKey(srcIP, srcPort, dstIP, dstPort, proto) == directKey
}

// PairStats holds bidirectional traffic counters for a conversation (client ↔
// server), where client is the side with the smaller IP (or smaller port when
// IPs are equal).
type PairStats struct {
	ClientPackets   uint64 `json:"client_packets"`
	ServerPackets   uint64 `json:"server_packets"`
	ClientBytes     uint64 `json:"client_bytes"`
	ServerBytes     uint64 `json:"server_bytes"`
	ClientWireBytes uint64 `json:"client_wire_bytes"`
	ServerWireBytes uint64 `json:"server_wire_bytes"`
	FirstTime       uint64 `json:"first_time"`
	LastTime        uint64 `json:"last_time"`
}

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
	// WireBytes accumulates original on-wire packet lengths (L2-L4 headers
	// included); Bytes counts payload only.
	WireBytes uint64 `json:"wire_bytes,omitempty"`

	HTTPHost string `json:"http_host,omitempty"`
	HTTPURL  string `json:"http_url,omitempty"`
	DNSQuery string `json:"dns_query,omitempty"`
	SNI      string `json:"tls_sni,omitempty"`

	// Application-layer context from the triggering packet. These are attached
	// only to the FlowFeature returned by Aggregator.Update (not persisted on
	// the stored flow) so per-flow memory stays bounded.
	HTTPMethod     string            `json:"http_method,omitempty"`
	UserAgent      string            `json:"user_agent,omitempty"`
	HTTPHeaders    map[string]string `json:"http_headers,omitempty"`
	HTTPBodySample string            `json:"http_body_sample,omitempty"`
	HTTPStatusCode uint16            `json:"http_status_code,omitempty"`
	DNSQType       uint16            `json:"dns_qtype,omitempty"`
	DNSAnswers     []string          `json:"dns_answers,omitempty"`
	PayloadSample  string            `json:"payload_sample,omitempty"`
	ICMPSeq        uint32            `json:"icmp_seq,omitempty"`
	// Trigger-packet evidence is attached only to the returned feature and is
	// never retained in the aggregator's long-lived flow table.
	RawPacket        []byte `json:"-"`
	RawPayload       []byte `json:"-"`
	CapturedLen      uint32 `json:"captured_len,omitempty"`
	TriggerWireLen   uint32 `json:"trigger_wire_len,omitempty"`
	MessageDirection string `json:"message_direction,omitempty"`
	PacketSequence   uint64 `json:"-"`

	FingerprintHits []fingerprint.FingerprintHit `json:"fingerprint_hits,omitempty"`
	IntelHits       []intel.ThreatIntel          `json:"intel_hits,omitempty"`
	EvidenceFile    string                       `json:"evidence_file,omitempty"`
	PacketTimeUsec  uint64                       `json:"packet_time_usec,omitempty"`

	PairStats *PairStats `json:"pair_stats,omitempty"`
}
