package detector

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"

	"ta_node/internal/flow"
	"ta_node/internal/parser"
)

func TestRawPacketInEvent(t *testing.T) {
	// 构造到IOC IP 192.185.86.177:443的TCP SYN包
	srcIP := net.ParseIP("172.16.100.16")
	dstIP := net.ParseIP("192.185.86.177")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ip := &layers.IPv4{SrcIP: srcIP, DstIP: dstIP, Protocol: layers.IPProtocolTCP, Version: 4, IHL: 5, TTL: 64, Length: 40}
	tcp := &layers.TCP{SrcPort: 54321, DstPort: 443, SYN: true, Seq: 1000, Window: 65535, DataOffset: 5}
	tcp.SetNetworkLayerForChecksum(ip)
	gopacket.SerializeLayers(buf, opts, ip, tcp)

	data := buf.Bytes()
	pkt := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.NoCopy)

	pf, err := parser.Parse(pkt)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	t.Logf("Parse OK - Direction=%q RawPacket=%d bytes Payload=%d bytes SYN=%v ACK=%v",
		pf.MessageDirection, len(pf.RawPacket), len(pf.Payload), pf.TCPSYN, pf.TCPACK)

	eng := New("test-node")
	f := flow.FlowFeature{
		FirstTime:        pf.PacketTimeUsec,
		LastTime:         pf.PacketTimeUsec,
		PacketTimeUsec:   pf.PacketTimeUsec,
		SrcIP:            pf.SrcIP,
		SrcPort:          pf.SrcPort,
		DstIP:            pf.DstIP,
		DstPort:          pf.DstPort,
		Proto:            pf.Proto,
		Packets:          1,
		RawPacket:        pf.RawPacket,
		RawPayload:       pf.Payload,
		CapturedLen:      pf.CapturedLen,
		TriggerWireLen:   pf.WireLen,
		MessageDirection: pf.MessageDirection,
	}

	events := eng.Detect(f)
	if len(events) != 0 {
		t.Logf("Warning: detected %d events (no IOC matching in this test)", len(events))
	}

	if f.RawPacket == nil || len(f.RawPacket) == 0 {
		t.Error("RawPacket should not be empty")
	}

	// Directly test rawPacketContext
	rc := rawPacketContext(f)
	if rc == nil {
		t.Fatal("rawPacketContext returned nil - RawPacket is empty or zero")
	}
	t.Logf("PacketHex=%d bytes PayloadHex=%d bytes Direction=%s Request=%v Response=%v",
		len(rc.PacketHex), len(rc.PayloadHex), rc.MessageDirection, rc.Request != nil, rc.Response != nil)

	if len(rc.PacketHex) == 0 {
		t.Error("PacketHex should not be empty")
	}
	if rc.Request == nil && rc.Response == nil {
		t.Error("Request or Response should be set for TCP SYN (direction=request)")
	}
}
