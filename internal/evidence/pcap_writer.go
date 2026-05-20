package evidence

import (
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Writer struct {
	enabled  bool
	baseDir  string
	deviceID string
}

func New(enabled bool, baseDir, deviceID string) *Writer {
	return &Writer{enabled: enabled, baseDir: baseDir, deviceID: deviceID}
}

func (w *Writer) Save(eventID string, packet gopacket.Packet) (string, error) {
	if !w.enabled || packet == nil {
		return "", nil
	}
	ts := packet.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	dir := filepath.Join(w.baseDir, w.deviceID, ts.Format("2006-01-02"))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, eventID+".pcap")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	link := layers.LinkTypeEthernet
	if packet.LinkLayer() == nil {
		link = layers.LinkTypeRaw
	}
	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(1600, link); err != nil {
		return "", err
	}
	return path, pw.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
}
