package parser

import (
	"bytes"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketFeature struct {
	PacketTimeUsec uint64 `json:"packet_time_usec"`

	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
	Proto   string `json:"proto"`

	HTTPHost   string `json:"http_host,omitempty"`
	HTTPURL    string `json:"http_url,omitempty"`
	HTTPMethod string `json:"http_method,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	HTTPHeader []byte `json:"-"`
	HTTPBody   []byte `json:"-"`

	DNSQuery   string   `json:"dns_query,omitempty"`
	DNSQType   uint16   `json:"dns_qtype,omitempty"`
	DNSAnswers []string `json:"dns_answers,omitempty"`

	ICMPPayloadLen uint32 `json:"icmp_payload_len,omitempty"`
	ICMPSeq        uint32 `json:"icmp_seq,omitempty"`

	Payload       []byte `json:"-"`
	PayloadSample string `json:"payload_sample,omitempty"`
	EvidenceFile  string `json:"evidence_file,omitempty"`
	Packet        gopacket.Packet
}

func Parse(packet gopacket.Packet) (PacketFeature, error) {
	pf := PacketFeature{Packet: packet}
	if ts := packet.Metadata().Timestamp; !ts.IsZero() {
		pf.PacketTimeUsec = uint64(ts.UnixMicro())
	} else {
		pf.PacketTimeUsec = uint64(time.Now().UnixMicro())
	}
	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ip := ip4.(*layers.IPv4)
		pf.SrcIP = ip.SrcIP.String()
		pf.DstIP = ip.DstIP.String()
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ip := ip6.(*layers.IPv6)
		pf.SrcIP = ip.SrcIP.String()
		pf.DstIP = ip.DstIP.String()
	} else {
		return pf, ErrNoNetwork
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		pf.Proto = "tcp"
		pf.SrcPort = uint16(tcp.SrcPort)
		pf.DstPort = uint16(tcp.DstPort)
		pf.Payload = append([]byte(nil), tcp.Payload...)
		if len(pf.Payload) > 0 {
			pf.PayloadSample = samplePayload(pf.Payload)
		}
		parseHTTP(&pf)
		return pf, nil
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		pf.Proto = "udp"
		pf.SrcPort = uint16(udp.SrcPort)
		pf.DstPort = uint16(udp.DstPort)
		pf.Payload = append([]byte(nil), udp.Payload...)
		parseDNS(packet, &pf)
		return pf, nil
	}
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		pf.Proto = "icmp"
		pf.Payload = append([]byte(nil), icmp.Payload...)
		pf.ICMPPayloadLen = uint32(len(icmp.Payload))
		if len(icmp.Payload) >= 6 {
			pf.ICMPSeq = uint32(icmp.Payload[4])<<8 | uint32(icmp.Payload[5])
		}
	}
	if len(pf.Payload) > 0 {
		pf.PayloadSample = samplePayload(pf.Payload)
	}
	return pf, nil
}

func parseDNS(packet gopacket.Packet, pf *PacketFeature) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns := dnsLayer.(*layers.DNS)
	if len(dns.Questions) > 0 {
		q := dns.Questions[0]
		pf.DNSQuery = strings.TrimSuffix(string(q.Name), ".")
		pf.DNSQType = uint16(q.Type)
	}
	for _, a := range dns.Answers {
		switch {
		case a.IP != nil:
			pf.DNSAnswers = append(pf.DNSAnswers, a.IP.String())
		case len(a.CNAME) > 0:
			pf.DNSAnswers = append(pf.DNSAnswers, strings.TrimSuffix(string(a.CNAME), "."))
		}
	}
}

func parseHTTP(pf *PacketFeature) {
	if len(pf.Payload) == 0 {
		return
	}
	method, path, ok := httpRequestLine(pf.Payload)
	if !ok {
		return
	}
	pf.HTTPMethod = method
	pf.HTTPURL = path
	header, body, _ := bytes.Cut(pf.Payload, []byte("\r\n\r\n"))
	pf.HTTPHeader = append([]byte(nil), header...)
	if body != nil {
		pf.HTTPBody = append([]byte(nil), body...)
	}
	for _, line := range strings.Split(string(header), "\r\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "host":
			pf.HTTPHost = strings.TrimSpace(v)
			if !strings.HasPrefix(pf.HTTPURL, "http://") && !strings.HasPrefix(pf.HTTPURL, "https://") {
				pf.HTTPURL = "http://" + pf.HTTPHost + path
			}
		case "user-agent":
			pf.UserAgent = strings.TrimSpace(v)
		}
	}
}

func httpRequestLine(payload []byte) (string, string, bool) {
	line, _, _ := bytes.Cut(payload, []byte("\r\n"))
	parts := strings.Fields(string(line))
	if len(parts) < 2 {
		return "", "", false
	}
	switch parts[0] {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS":
		return parts[0], parts[1], true
	default:
		return "", "", false
	}
}

func samplePayload(payload []byte) string {
	if len(payload) > 64 {
		payload = payload[:64]
	}
	if printable(payload) {
		return string(payload)
	}
	return hex.EncodeToString(payload)
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 9 || (c > 13 && c < 32) {
			return false
		}
	}
	return true
}

func IsIP(s string) bool { return net.ParseIP(s) != nil }

func Uint16(s string) uint16 {
	v, _ := strconv.ParseUint(s, 10, 16)
	return uint16(v)
}
