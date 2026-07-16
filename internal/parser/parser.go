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
	// WireLen is the packet's original on-wire length (bytes), used to report
	// communication data size including L2-L4 headers, distinct from the
	// payload-only byte accounting.
	WireLen uint32 `json:"wire_len,omitempty"`

	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
	Proto   string `json:"proto"`

	HTTPHost       string            `json:"http_host,omitempty"`
	HTTPURL        string            `json:"http_url,omitempty"`
	HTTPMethod     string            `json:"http_method,omitempty"`
	UserAgent      string            `json:"user_agent,omitempty"`
	HTTPHeader     []byte            `json:"-"`
	HTTPBody       []byte            `json:"-"`
	HTTPHeaders    map[string]string `json:"http_headers,omitempty"`
	HTTPBodySample string            `json:"http_body_sample,omitempty"`

	DNSQuery   string   `json:"dns_query,omitempty"`
	DNSQType   uint16   `json:"dns_qtype,omitempty"`
	DNSAnswers []string `json:"dns_answers,omitempty"`

	// SNI is the TLS ClientHello server_name (a domain), extracted from HTTPS
	// handshakes so encrypted flows can still match domain IOCs even when the
	// preceding DNS query was not observed.
	SNI string `json:"tls_sni,omitempty"`

	ICMPPayloadLen uint32 `json:"icmp_payload_len,omitempty"`
	ICMPSeq        uint32 `json:"icmp_seq,omitempty"`

	Payload       []byte `json:"-"`
	PayloadSample string `json:"payload_sample,omitempty"`
	EvidenceFile  string `json:"evidence_file,omitempty"`
	Packet        gopacket.Packet
}

func Parse(packet gopacket.Packet) (PacketFeature, error) {
	pf := PacketFeature{Packet: packet}
	md := packet.Metadata()
	if ts := md.Timestamp; !ts.IsZero() {
		pf.PacketTimeUsec = uint64(ts.UnixMicro())
	} else {
		pf.PacketTimeUsec = uint64(time.Now().UnixMicro())
	}
	// Prefer the original on-wire length; fall back to captured bytes when the
	// capture source does not populate it.
	if md.Length > 0 {
		pf.WireLen = uint32(md.Length)
	} else {
		pf.WireLen = uint32(len(packet.Data()))
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
		parseTLS(&pf)
		if pf.SrcPort == 53 || pf.DstPort == 53 {
			parseDNSOverTCP(&pf)
		}
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
	fillDNS(dnsLayer.(*layers.DNS), pf)
}

// fillDNS copies query name/type and answers (IPs and CNAME targets) from a
// decoded DNS message onto pf. Shared by the UDP and TCP/53 paths.
func fillDNS(dns *layers.DNS, pf *PacketFeature) {
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

// parseDNSOverTCP decodes a DNS message carried over TCP (RFC 7766): a 2-byte
// big-endian length prefix followed by the DNS message. Only a message fully
// contained in this packet is parsed; one split across TCP segments is skipped.
func parseDNSOverTCP(pf *PacketFeature) {
	p := pf.Payload
	if len(p) < 2 {
		return
	}
	n := int(p[0])<<8 | int(p[1])
	if n <= 0 || 2+n > len(p) {
		return
	}
	var dns layers.DNS
	if err := dns.DecodeFromBytes(p[2:2+n], gopacket.NilDecodeFeedback); err != nil {
		return
	}
	fillDNS(&dns, pf)
}

// parseTLS extracts the SNI (server_name) from a TLS ClientHello if the TCP
// payload begins with one, so domain IOCs can match encrypted flows.
func parseTLS(pf *PacketFeature) {
	if host, ok := tlsClientHelloSNI(pf.Payload); ok {
		pf.SNI = host
	}
}

// tlsClientHelloSNI parses a single-packet TLS ClientHello and returns the
// server_name (host_name) extension value. Every field length is bounds-checked
// so malformed or truncated input never panics; a ClientHello split across TCP
// segments is not reassembled and yields (\"\", false).
func tlsClientHelloSNI(p []byte) (string, bool) {
	// TLS record header: content_type(1)=0x16 handshake, version(2), length(2).
	if len(p) < 5 || p[0] != 0x16 {
		return "", false
	}
	hs := p[5:]
	// Handshake header: msg_type(1)=0x01 ClientHello, length(3).
	if len(hs) < 4 || hs[0] != 0x01 {
		return "", false
	}
	b := hs[4:]
	// client_version(2) + random(32).
	if len(b) < 34 {
		return "", false
	}
	b = b[34:]
	// session_id: length(1) + id.
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return "", false
	}
	b = b[1+int(b[0]):]
	// cipher_suites: length(2) + suites.
	if len(b) < 2 {
		return "", false
	}
	csLen := int(b[0])<<8 | int(b[1])
	if len(b) < 2+csLen {
		return "", false
	}
	b = b[2+csLen:]
	// compression_methods: length(1) + methods.
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return "", false
	}
	b = b[1+int(b[0]):]
	// extensions: length(2) + extensions.
	if len(b) < 2 {
		return "", false
	}
	extTotal := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) > extTotal {
		b = b[:extTotal]
	}
	for len(b) >= 4 {
		extType := int(b[0])<<8 | int(b[1])
		extLen := int(b[2])<<8 | int(b[3])
		b = b[4:]
		if len(b) < extLen {
			return "", false
		}
		ext := b[:extLen]
		b = b[extLen:]
		if extType != 0x0000 { // server_name
			continue
		}
		// server_name_list: length(2), entries of name_type(1)+name_len(2)+name.
		if len(ext) < 2 {
			return "", false
		}
		listLen := int(ext[0])<<8 | int(ext[1])
		ext = ext[2:]
		if len(ext) > listLen {
			ext = ext[:listLen]
		}
		for len(ext) >= 3 {
			nameType := ext[0]
			nameLen := int(ext[1])<<8 | int(ext[2])
			ext = ext[3:]
			if len(ext) < nameLen {
				return "", false
			}
			name := ext[:nameLen]
			ext = ext[nameLen:]
			if nameType == 0x00 && nameLen > 0 { // host_name
				return strings.TrimSuffix(string(name), "."), true
			}
		}
		return "", false
	}
	return "", false
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
	if len(body) > 0 {
		pf.HTTPBody = append([]byte(nil), body...)
		pf.HTTPBodySample = samplePayload(body)
	}
	for _, line := range strings.Split(string(header), "\r\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch key {
		case "host":
			pf.HTTPHost = val
			if !strings.HasPrefix(pf.HTTPURL, "http://") && !strings.HasPrefix(pf.HTTPURL, "https://") {
				pf.HTTPURL = "http://" + pf.HTTPHost + path
			}
		case "user-agent":
			pf.UserAgent = val
		}
		// Capture a safe allowlist of headers for AI analysis. Sensitive
		// credential headers (cookie/authorization/...) are deliberately
		// excluded so they are never pushed off the node.
		if safeHTTPHeaders[key] {
			if pf.HTTPHeaders == nil {
				pf.HTTPHeaders = map[string]string{}
			}
			pf.HTTPHeaders[key] = val
		}
	}
}

// safeHTTPHeaders is the allowlist of request headers that are forwarded with
// events. Anything not listed here (Cookie, Authorization, Proxy-Authorization,
// etc.) is dropped to avoid exfiltrating credentials.
var safeHTTPHeaders = map[string]bool{
	"host":             true,
	"referer":          true,
	"content-type":     true,
	"content-length":   true,
	"x-forwarded-for":  true,
	"accept":           true,
	"accept-language":  true,
	"origin":           true,
	"x-requested-with": true,
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
