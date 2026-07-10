package iocwatch

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ta_node/internal/intel"
)

func newStore(t *testing.T) *intel.Store {
	t.Helper()
	s, err := intel.NewStore(filepath.Join(t.TempDir(), "intel.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

const sampleYAML = `items:
- id: otx-1
  type: domain
  value: evil.example.com
  category: c2
  severity: high
  recommended_action: block_and_report
  evidence: {activity: Camp, tlp: white}
  enabled: true
`

func newWatcher(store *intel.Store, dir string) *Watcher {
	w := New(store, dir, time.Second, 100000)
	w.staleAfter = 0 // 测试里立即判定坏 zip 为 failed
	return w
}

func TestScanImportsAndMoves(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	writeZip(t, filepath.Join(dir, "feed-1.zip"), map[string]string{"a.yaml": sampleYAML})
	newWatcher(store, dir).scanOnce()

	if len(store.List()) != 1 {
		t.Fatalf("want 1 item imported, got %d", len(store.List()))
	}
	it := store.List()[0]
	if it.Evidence == nil || it.Evidence.TLP != "white" || it.RecommendedAction != "block_and_report" {
		t.Errorf("rich fields lost: %+v", it)
	}
	if _, err := os.Stat(filepath.Join(dir, "processed", "feed-1.zip")); err != nil {
		t.Errorf("zip not moved to processed/: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "feed-1.zip")); !os.IsNotExist(err) {
		t.Error("original zip should be gone")
	}
}

func TestDuplicateDeliveryNoDoubleCount(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	writeZip(t, filepath.Join(dir, "feed.zip"), map[string]string{"a.yaml": sampleYAML})
	w := newWatcher(store, dir)
	w.scanOnce()
	w.scanOnce() // 第二次已移走 -> 无新增
	if len(store.List()) != 1 {
		t.Fatalf("want 1 item, got %d", len(store.List()))
	}
}

func TestSameValueDifferentIDDeduped(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	body := `items:
- {id: otx-a, type: domain, value: dup.example.com, enabled: true}
- {id: otx-b, type: domain, value: dup.example.com, enabled: true}
`
	writeZip(t, filepath.Join(dir, "dup.zip"), map[string]string{"a.yaml": body})
	newWatcher(store, dir).scanOnce()
	if len(store.List()) != 1 {
		t.Fatalf("want 1 deduped item, got %d", len(store.List()))
	}
}

func TestBadZipGoesToFailed(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	bad := filepath.Join(dir, "broken.zip")
	if err := os.WriteFile(bad, []byte("this is not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	newWatcher(store, dir).scanOnce() // staleAfter=0 -> 立即判失败
	if len(store.List()) != 0 {
		t.Errorf("bad zip must not change rule set, got %d", len(store.List()))
	}
	if _, err := os.Stat(filepath.Join(dir, "failed", "broken.zip")); err != nil {
		t.Errorf("bad zip not moved to failed/: %v", err)
	}
}

func TestHalfWrittenSkippedThenImported(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	// 先造一个完整 zip，再截断成半写；用近期 mtime + 较大 staleAfter 使其被跳过
	full := filepath.Join(dir, "wip.zip")
	writeZip(t, full, map[string]string{"a.yaml": sampleYAML})
	data, _ := os.ReadFile(full)
	if err := os.WriteFile(full, data[:len(data)/2], 0o644); err != nil {
		t.Fatal(err)
	}
	w := New(store, dir, time.Second, 100000) // staleAfter 默认较大
	w.scanOnce()
	if len(store.List()) != 0 {
		t.Fatalf("half-written zip must be skipped, got %d", len(store.List()))
	}
	if _, err := os.Stat(full); err != nil {
		t.Fatalf("half-written zip should remain in place: %v", err)
	}
	// 补齐后再扫描
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatal(err)
	}
	w.scanOnce()
	if len(store.List()) != 1 {
		t.Fatalf("want 1 item after completion, got %d", len(store.List()))
	}
}
