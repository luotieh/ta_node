package iocsync

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// zipWith builds a zip whose rules.yaml lists n domain IOCs starting at `from`.
func zipWith(t *testing.T, path string, from, n int) {
	t.Helper()
	var b strings.Builder
	b.WriteString("items:\n")
	for i := from; i < from+n; i++ {
		fmt.Fprintf(&b, "- {id: gw-%d, type: domain, value: d%d.example.com, category: c2, enabled: true}\n", i, i)
	}
	writeZip(t, path, map[string]string{"rules.yaml": b.String()})
}

func TestSyncOnceImportsAllNew(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	zipWith(t, filepath.Join(dir, "a.zip"), 0, 25)
	s := New(store, dir, 10, 100000)
	added, err := s.SyncOnce()
	if err != nil {
		t.Fatal(err)
	}
	// No per-day cap: every new rule is imported in one pass.
	if added != 25 || len(store.List()) != 25 {
		t.Fatalf("want 25 added/total, got added=%d total=%d", added, len(store.List()))
	}
}

func TestSyncOnceSkipsAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	// Pre-seed the main file with d0..d4 (canonical keys already present).
	for i := 0; i < 5; i++ {
		if _, err := store.Add(intel.ThreatIntel{ID: fmt.Sprintf("local-%d", i), Type: "domain", Value: fmt.Sprintf("d%d.example.com", i), Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	zipWith(t, filepath.Join(dir, "a.zip"), 0, 10) // d0..d9
	s := New(store, dir, 10, 100000)

	added, err := s.SyncOnce()
	if err != nil {
		t.Fatal(err)
	}
	if added != 5 || len(store.List()) != 10 { // only d5..d9 are new
		t.Fatalf("want 5 added / 10 total, got added=%d total=%d", added, len(store.List()))
	}
	// Re-delivery of the same zip: main file is the cursor, so nothing new.
	added2, err := s.SyncOnce()
	if err != nil {
		t.Fatal(err)
	}
	if added2 != 0 || len(store.List()) != 10 {
		t.Fatalf("want 0 added on re-run, got added=%d total=%d", added2, len(store.List()))
	}
}

func TestSyncOnceDedupsAcrossCandidates(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	// same value under two ids -> imported as one indicator
	body := "items:\n" +
		"- {id: a, type: domain, value: dup.example.com, enabled: true}\n" +
		"- {id: b, type: domain, value: DUP.example.com., enabled: true}\n"
	writeZip(t, filepath.Join(dir, "a.zip"), map[string]string{"r.yaml": body})
	s := New(store, dir, 10, 100000)
	added, _ := s.SyncOnce()
	if added != 1 || len(store.List()) != 1 {
		t.Fatalf("want 1 deduped, got added=%d total=%d", added, len(store.List()))
	}
}

func TestSyncOnceBadZipSkipped(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	if err := os.WriteFile(filepath.Join(dir, "bad.zip"), []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipWith(t, filepath.Join(dir, "good.zip"), 0, 3)
	s := New(store, dir, 10, 100000)
	added, err := s.SyncOnce()
	if err != nil {
		t.Fatalf("SyncOnce should not fail on a bad zip: %v", err)
	}
	if added != 3 {
		t.Fatalf("want 3 added from good zip, got %d", added)
	}
	// bad zip stays (retain window not exceeded), good zip stays too
	if _, err := os.Stat(filepath.Join(dir, "bad.zip")); err != nil {
		t.Errorf("bad zip should remain in place: %v", err)
	}
}

func TestCleanupRemovesOldZips(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	old := filepath.Join(dir, "old.zip")
	recent := filepath.Join(dir, "recent.zip")
	zipWith(t, old, 0, 1)
	zipWith(t, recent, 100, 1)
	past := time.Now().AddDate(0, 0, -15)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	recentT := time.Now().AddDate(0, 0, -5)
	if err := os.Chtimes(recent, recentT, recentT); err != nil {
		t.Fatal(err)
	}
	s := New(store, dir, 10, 100000)
	if _, err := s.SyncOnce(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("15-day-old zip should have been removed")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Error("5-day-old zip should remain")
	}
}
