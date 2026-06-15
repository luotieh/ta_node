package intel

import (
	"os"
	"path/filepath"
	"testing"
)

func writeIntelFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDirMergesYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	writeIntelFile(t, filepath.Join(dir, "a.yaml"), `items:
  - {id: a1, type: ip, value: "1.1.1.1", enabled: true}
  - {id: a2, type: ip, value: "2.2.2.2", enabled: true}
`)
	writeIntelFile(t, filepath.Join(dir, "b.yml"), `items:
  - {id: b1, type: domain, value: "evil.test", enabled: true}
`)
	items, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 items across .yaml and .yml files, got %d", len(items))
	}
}

func TestLoadDirMalformedFails(t *testing.T) {
	dir := t.TempDir()
	writeIntelFile(t, filepath.Join(dir, "good.yaml"), "items:\n  - {id: a, type: ip, value: \"1.1.1.1\", enabled: true}\n")
	writeIntelFile(t, filepath.Join(dir, "bad.yaml"), "items: [unterminated\n")
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected LoadDir to fail on a malformed file")
	}
}

func TestLoadDirEmpty(t *testing.T) {
	if items, err := LoadDir(t.TempDir()); err != nil || items != nil {
		t.Fatalf("empty dir: want nil/nil, got %v / %v", items, err)
	}
	if items, err := LoadDir(""); err != nil || items != nil {
		t.Fatalf("empty path: want nil/nil, got %v / %v", items, err)
	}
}

func TestStoreOverlayMergeAndPrecedence(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "intel.yaml")
	overlayDir := filepath.Join(dir, "intel.d")
	if err := os.MkdirAll(overlayDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeIntelFile(t, filepath.Join(overlayDir, "feed.yaml"), `items:
  - {id: shared, type: ip, value: "9.9.9.9", source: feed, enabled: true}
  - {id: feed-only, type: domain, value: "bad.test", source: feed, enabled: true}
`)
	writeIntelFile(t, primary, `items:
  - {id: shared, type: ip, value: "1.1.1.1", source: local, enabled: true}
`)

	store, err := NewStoreWithDir(primary, overlayDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Stats().Total; got != 2 {
		t.Fatalf("expected 2 merged IOCs (shared + feed-only), got %d", got)
	}
	if it, _ := store.Get("shared"); it.Value != "1.1.1.1" || it.Source != "local" {
		t.Fatalf("primary file should win on id conflict, got %#v", it)
	}
	if _, ok := store.Get("feed-only"); !ok {
		t.Fatal("overlay-only IOC missing from merged view")
	}

	// Overlay IOCs are read-only through the store API.
	if err := store.Delete("feed-only"); err == nil {
		t.Fatal("expected deleting an overlay-only IOC to be rejected")
	}

	// Writes target only the primary file; overlay items are never written back.
	if _, err := store.Add(ThreatIntel{ID: "added", Type: "ip", Value: "8.8.8.8", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(primary)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("primary file should hold only writable items (shared+added), got %d: %#v", len(got), got)
	}
}

func TestStoreReloadPicksUpNewOverlayFile(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "intel.yaml")
	overlayDir := filepath.Join(dir, "intel.d")
	if err := os.MkdirAll(overlayDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeIntelFile(t, primary, "items: []\n")

	store, err := NewStoreWithDir(primary, overlayDir)
	if err != nil {
		t.Fatal(err)
	}
	if store.Stats().Total != 0 {
		t.Fatalf("expected empty store, got %d", store.Stats().Total)
	}

	// Drop in a new feed file and reload — the incremental-add workflow.
	writeIntelFile(t, filepath.Join(overlayDir, "new.yaml"), `items:
  - {id: n1, type: ip, value: "3.3.3.3", enabled: true}
`)
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get("n1"); !ok {
		t.Fatal("reload did not pick up the newly added overlay file")
	}
}
