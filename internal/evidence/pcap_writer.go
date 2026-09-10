package evidence

import (
	"archive/zip"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Writer struct {
	enabled     bool
	baseDir     string
	deviceID    string
	hashDir     bool
	retainDays  int
	archiveMtly bool
}

func New(enabled bool, baseDir, deviceID string, hashDir bool, retainDays int, archiveMonthly bool) *Writer {
	return &Writer{
		enabled: enabled, baseDir: baseDir, deviceID: deviceID,
		hashDir: hashDir, retainDays: retainDays, archiveMtly: archiveMonthly,
	}
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
	if w.hashDir && len(eventID) >= 6 {
		dir = filepath.Join(dir, eventID[4:6])
	}
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

// CleanupExpired removes date directories older than retainDays.
// Returns count of removed directories.
func (w *Writer) CleanupExpired(now time.Time) int {
	if w.retainDays <= 0 {
		return 0
	}
	devDir := filepath.Join(w.baseDir, w.deviceID)
	entries, err := os.ReadDir(devDir)
	if err != nil {
		return 0
	}
	cutoff := now.AddDate(0, 0, -w.retainDays)
	removed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dirTime, err := time.Parse("2006-01-02", e.Name())
		if err != nil {
			continue
		}
		if dirTime.Before(cutoff) {
			dateDir := filepath.Join(devDir, e.Name())
			if err := os.RemoveAll(dateDir); err != nil {
				log.Printf("evidence: remove expired %s failed: %v", e.Name(), err)
			} else {
				removed++
			}
		}
	}
	if removed > 0 {
		log.Printf("evidence: removed %d expired date directories", removed)
	}
	return removed
}

// ArchiveLastMonth compresses last month's date directories into zip archives,
// then removes the original directories. Returns count of archived files.
func (w *Writer) ArchiveLastMonth(now time.Time) int {
	if !w.archiveMtly {
		return 0
	}
	devDir := filepath.Join(w.baseDir, w.deviceID)
	entries, err := os.ReadDir(devDir)
	if err != nil {
		return 0
	}
	lastMonth := time.Date(now.Year(), now.Month()-1, 1, 0, 0, 0, 0, now.Location())
	thisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	totalArchived := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dirTime, err := time.Parse("2006-01-02", e.Name())
		if err != nil {
			continue
		}
		if dirTime.Before(lastMonth) || dirTime.After(thisMonth) {
			continue
		}
		dateDir := filepath.Join(devDir, e.Name())
		zipPath := dateDir + ".zip"
		count := archiveDir(dateDir, zipPath)
		if count > 0 {
			log.Printf("evidence: archived %s -> %s (%d files)", e.Name(), filepath.Base(zipPath), count)
			totalArchived += count
		}
		if err := os.RemoveAll(dateDir); err != nil {
			log.Printf("evidence: remove archived %s failed: %v", e.Name(), err)
		}
	}
	return totalArchived
}

// archiveDir compresses dir into zipPath. Returns file count.
func archiveDir(dir, zipPath string) int {
	f, err := os.Create(zipPath)
	if err != nil {
		return 0
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()

	count := 0
	base := filepath.Base(dir)
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		zf, err := zw.Create(filepath.Join(base, rel))
		if err != nil {
			return err
		}
		rf, err := os.Open(path)
		if err != nil {
			return err
		}
		defer rf.Close()
		_, err = io.Copy(zf, rf)
		count++
		return err
	})
	if err != nil {
		log.Printf("evidence: archive walk %s: %v", dir, err)
	}
	return count
}
