package capture

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestNewPCAPReaderReadsPackets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pcap")
	createTestPcap(t, path, 3)

	r, err := NewPCAPReader(path, "")
	if err != nil {
		t.Fatalf("NewPCAPReader: %v", err)
	}
	defer r.Close()

	count := 0
	for pkt := range r.Packets() {
		if pkt == nil {
			t.Fatal("nil packet")
		}
		if len(pkt.Data()) == 0 {
			t.Fatal("empty packet data")
		}
		meta := pkt.Metadata()
		if meta.Timestamp.IsZero() {
			t.Error("timestamp not set")
		}
		count++
	}
	if count != 3 {
		t.Fatalf("expected 3 packets, got %d", count)
	}
}

func TestNewPCAPReaderNonexistentFile(t *testing.T) {
	_, err := NewPCAPReader("/nonexistent/test.pcap", "")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestPCAPReaderClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pcap")
	createTestPcap(t, path, 1)

	r, err := NewPCAPReader(path, "")
	if err != nil {
		t.Fatalf("NewPCAPReader: %v", err)
	}
	// Consume packets first
	for range r.Packets() {
	}
	r.Close()
	// Second close should be safe (file already closed by Close or goroutine)
	r.Close()
}

func TestPCAPReaderEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pcap")
	createTestPcap(t, path, 0)

	r, err := NewPCAPReader(path, "")
	if err != nil {
		t.Fatalf("NewPCAPReader: %v", err)
	}
	count := 0
	for range r.Packets() {
		count++
	}
	if count != 0 {
		t.Fatalf("expected 0 packets, got %d", count)
	}
}

func createTestPcap(t *testing.T, path string, count int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < count; i++ {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		ip := &layers.IPv4{
			SrcIP:    netParse("10.0.0.1"),
			DstIP:    netParse("10.0.0.2"),
			Protocol: layers.IPProtocolTCP,
			Version:  4,
			IHL:      5,
			TTL:      64,
			Length:   40,
		}
		tcp := &layers.TCP{
			SrcPort:    12345,
			DstPort:    80,
			SYN:        true,
			Seq:        uint32(1000 + i),
			Window:     65535,
			DataOffset: 5,
		}
		tcp.SetNetworkLayerForChecksum(ip)
		if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
			t.Fatal(err)
		}

		ts := time.Unix(1000000+int64(i), 0)
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     ts,
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}, buf.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
}

func netParse(s string) net.IP {
	return net.ParseIP(s).To4()
}
