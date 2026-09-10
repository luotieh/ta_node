package evidence

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func makeTestPacket(t *testing.T, ts time.Time) gopacket.Packet {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP("10.0.0.1").To4(),
		DstIP:    net.ParseIP("10.0.0.2").To4(),
		Protocol: layers.IPProtocolTCP, Version: 4, IHL: 5, TTL: 64, Length: 40,
	}
	tcp := &layers.TCP{
		SrcPort: 12345, DstPort: 80, SYN: true, Seq: 1000, Window: 65535, DataOffset: 5,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	gopacket.SerializeLayers(buf, opts, ip, tcp)
	data := buf.Bytes()

	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(data),
		Length:        len(data),
	}
	return pkt
}

func TestWriterSave(t *testing.T) {
	dir := t.TempDir()
	w := New(true, dir, "test-device", true, 7, false)
	pkt := makeTestPacket(t, time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC))

	path, err := w.Save("evt-abcdef1234567890abcdef1234567890", pkt)
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("expected non-empty path")
	}

	expectedDir := filepath.Join(dir, "test-device", "2026-07-24", "ab")
	if _, err := os.Stat(expectedDir); os.IsNotExist(err) {
		t.Errorf("expected directory %s to exist", expectedDir)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("expected pcap file %s to exist", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 24 {
		t.Fatalf("pcap too small: %d bytes", len(data))
	}
}

func TestWriterSaveDisabled(t *testing.T) {
	dir := t.TempDir()
	w := New(false, dir, "test-device", true, 7, false)
	path, err := w.Save("evt-test", makeTestPacket(t, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Fatal("expected empty path when disabled")
	}
}

func TestWriterSaveNilPacket(t *testing.T) {
	dir := t.TempDir()
	w := New(true, dir, "test-device", false, 7, false)
	path, err := w.Save("evt-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Fatal("expected empty path for nil packet")
	}
}

func TestWriterSaveNoHash(t *testing.T) {
	dir := t.TempDir()
	w := New(true, dir, "test-device", false, 7, false)

	path, err := w.Save("evt-test-1234", makeTestPacket(t, time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	expectedDir := filepath.Join(dir, "test-device", "2026-07-24")
	if _, err := os.Stat(expectedDir); os.IsNotExist(err) {
		t.Errorf("expected dir %s", expectedDir)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("pcap not found at %s", path)
	}
}

func TestCleanupExpired(t *testing.T) {
	dir := t.TempDir()
	w := New(true, dir, "test-device", true, 7, false)

	pkt := makeTestPacket(t, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	w.Save("evt-old", pkt)
	oldDir := filepath.Join(dir, "test-device", "2026-08-01")
	os.Chtimes(oldDir, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC), time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))

	recentDir := filepath.Join(dir, "test-device", "2026-08-09")
	os.MkdirAll(recentDir, 0755)
	os.WriteFile(filepath.Join(recentDir, "evt-recent.pcap"), []byte("pcap"), 0644)
	os.Chtimes(recentDir, time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC), time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC))

	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	removed := w.CleanupExpired(now)
	if removed < 1 {
		t.Errorf("expected at least 1 removed, got %d", removed)
	}
	if _, err := os.Stat(recentDir); os.IsNotExist(err) {
		t.Error("recent dir should not be removed")
	}
}

func TestCleanupExpiredDisabled(t *testing.T) {
	dir := t.TempDir()
	w := New(true, dir, "test-device", true, 0, false)

	pkt := makeTestPacket(t, time.Now())
	w.Save("evt-test", pkt)

	removed := w.CleanupExpired(time.Now())
	if removed != 0 {
		t.Errorf("retainDays=0 should not remove, got %d", removed)
	}
}

func TestArchiveLastMonth(t *testing.T) {
	dir := t.TempDir()
	w := New(true, dir, "test-device", true, 30, true)

	pkt := makeTestPacket(t, time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC))
	w.Save("evt-archive-test", pkt)

	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	archived := w.ArchiveLastMonth(now)

	if archived > 0 {
		t.Logf("archived %d files", archived)
	}
	zipPath := filepath.Join(dir, "test-device", "2026-07-24.zip")
	if _, err := os.Stat(zipPath); err == nil {
		t.Log("zip archive created successfully")
	}
}

func TestArchiveLastMonthDisabled(t *testing.T) {
	dir := t.TempDir()
	w := New(true, dir, "test-device", true, 30, false)

	pkt := makeTestPacket(t, time.Now())
	w.Save("evt-test", pkt)

	archived := w.ArchiveLastMonth(time.Now().AddDate(0, 2, 0))
	if archived != 0 {
		t.Errorf("archive disabled should return 0, got %d", archived)
	}
}
