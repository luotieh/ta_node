package parser

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseRetainsExactRawPacketEvidence(t *testing.T) {
	payload := []byte("POST /upload HTTP/1.1\r\nHost: evil.example.com\r\n\r\nhello")
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(1, 2, 3, 4)}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, Seq: 1, ACK: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), buf.Bytes()...)
	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	ts := time.Unix(100, 123_456_000)
	pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp: ts, CaptureLength: len(raw), Length: len(raw) + 20,
	}

	pf, err := Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pf.RawPacket, raw) || !bytes.Equal(pf.Payload, payload) {
		t.Fatalf("raw evidence changed: packet=%x payload=%x", pf.RawPacket, pf.Payload)
	}
	if pf.CapturedLen != uint32(len(raw)) || pf.WireLen != uint32(len(raw)+20) {
		t.Fatalf("capture lengths wrong: captured=%d wire=%d", pf.CapturedLen, pf.WireLen)
	}
	if pf.PacketTimeUsec != uint64(ts.UnixMicro()) || pf.MessageDirection != "request" {
		t.Fatalf("packet metadata wrong: time=%d direction=%q", pf.PacketTimeUsec, pf.MessageDirection)
	}
	if PayloadText(pf.Payload) != string(payload) {
		t.Fatalf("printable payload text not retained: %q", PayloadText(pf.Payload))
	}
	if PayloadText([]byte{0xff, 0x00}) != "" {
		t.Fatal("binary payload must not be exposed as invalid text")
	}
}

func TestParseHTTPClassifiesResponse(t *testing.T) {
	pf := PacketFeature{Payload: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")}
	parseHTTP(&pf)
	if pf.MessageDirection != "response" {
		t.Fatalf("direction = %q, want response", pf.MessageDirection)
	}
}

// buildClientHello assembles a minimal but well-formed TLS ClientHello record
// carrying a single server_name (host_name) extension.
func buildClientHello(sni string) []byte {
	server := []byte(sni)
	snEntry := []byte{0x00} // name_type = host_name
	snEntry = append(snEntry, byte(len(server)>>8), byte(len(server)))
	snEntry = append(snEntry, server...)

	snList := []byte{byte(len(snEntry) >> 8), byte(len(snEntry))}
	snList = append(snList, snEntry...)

	ext := []byte{0x00, 0x00} // extension type = server_name
	ext = append(ext, byte(len(snList)>>8), byte(len(snList)))
	ext = append(ext, snList...)

	exts := []byte{byte(len(ext) >> 8), byte(len(ext))}
	exts = append(exts, ext...)

	body := []byte{0x03, 0x03}                  // client_version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id length 0
	body = append(body, 0x00, 0x02, 0x00, 0x2f) // cipher_suites: len 2 + one suite
	body = append(body, 0x01, 0x00)             // compression_methods: len 1 + null
	body = append(body, exts...)

	hs := []byte{0x01} // handshake type = ClientHello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01} // record: handshake, TLS 1.0 record version
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))
	rec = append(rec, hs...)
	return rec
}

func TestTLSClientHelloSNI(t *testing.T) {
	host, ok := tlsClientHelloSNI(buildClientHello("evil.example.com"))
	if !ok || host != "evil.example.com" {
		t.Fatalf("want evil.example.com/true, got %q/%v", host, ok)
	}

	// Non-handshake record (application data) must not parse.
	if _, ok := tlsClientHelloSNI([]byte{0x17, 0x03, 0x03, 0x00, 0x00}); ok {
		t.Error("application-data record should not yield an SNI")
	}
	// Empty / tiny inputs.
	if _, ok := tlsClientHelloSNI(nil); ok {
		t.Error("nil payload should be false")
	}

	// Every truncation prefix must be handled without panicking.
	full := buildClientHello("verylong.subdomain.example.com")
	for i := 0; i <= len(full); i++ {
		_, _ = tlsClientHelloSNI(full[:i]) // must not panic
	}
}

func TestParseTLSSetsSNI(t *testing.T) {
	pf := PacketFeature{Payload: buildClientHello("c2.example.com")}
	parseTLS(&pf)
	if pf.SNI != "c2.example.com" {
		t.Fatalf("SNI = %q, want c2.example.com", pf.SNI)
	}
}

func TestParseDNSOverTCP(t *testing.T) {
	dns := &layers.DNS{ID: 1, QDCount: 1, RD: true,
		Questions: []layers.DNSQuestion{{Name: []byte("tcp.example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	buf := gopacket.NewSerializeBuffer()
	if err := dns.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
		t.Fatal(err)
	}
	msg := buf.Bytes()

	// Full message with a correct 2-byte length prefix.
	pf := PacketFeature{Payload: append([]byte{byte(len(msg) >> 8), byte(len(msg))}, msg...)}
	parseDNSOverTCP(&pf)
	if pf.DNSQuery != "tcp.example.com" {
		t.Fatalf("DNSQuery = %q, want tcp.example.com", pf.DNSQuery)
	}

	// Segmented: length prefix claims more bytes than are present -> skipped.
	pf2 := PacketFeature{Payload: append([]byte{0xff, 0xff}, msg...)}
	parseDNSOverTCP(&pf2)
	if pf2.DNSQuery != "" {
		t.Errorf("segmented message should be skipped, got DNSQuery=%q", pf2.DNSQuery)
	}
}
