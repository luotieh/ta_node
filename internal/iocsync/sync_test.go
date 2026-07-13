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

func TestSyncOnceLimitsToDaily(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	zipWith(t, filepath.Join(dir, "a.zip"), 0, 25)
	s := New(store, dir, 10, 10, 100000)
	added, err := s.SyncOnce()
	if err != nil {
		t.Fatal(err)
	}
	if added != 10 || len(store.List()) != 10 {
		t.Fatalf("want 10 added/total, got added=%d total=%d", added, len(store.List()))
	}
}

func TestSyncOnceCursorContinuesNextDay(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	zipWith(t, filepath.Join(dir, "a.zip"), 0, 25)
	s := New(store, dir, 10, 10, 100000)
	// day 1: +10, day 2: +10 (next batch, since first 10 now in main file), day 3: +5
	if a, _ := s.SyncOnce(); a != 10 {
		t.Fatalf("day1 added=%d", a)
	}
	if a, _ := s.SyncOnce(); a != 10 {
		t.Fatalf("day2 added=%d", a)
	}
	if a, _ := s.SyncOnce(); a != 5 {
		t.Fatalf("day3 added=%d", a)
	}
	if a, _ := s.SyncOnce(); a != 0 {
		t.Fatalf("day4 added=%d (all consumed)", a)
	}
	if len(store.List()) != 25 {
		t.Fatalf("want 25 total, got %d", len(store.List()))
	}
}

func TestSyncOnceDedupsAcrossCandidates(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	// same value under two ids -> counts as one toward the limit
	body := "items:\n" +
		"- {id: a, type: domain, value: dup.example.com, enabled: true}\n" +
		"- {id: b, type: domain, value: DUP.example.com., enabled: true}\n"
	writeZip(t, filepath.Join(dir, "a.zip"), map[string]string{"r.yaml": body})
	s := New(store, dir, 10, 10, 100000)
	added, _ := s.SyncOnce()
	if added != 1 || len(store.List()) != 1 {
		t.Fatalf("want 1 deduped, got added=%d total=%d", added, len(store.List()))
	}
}

func TestSyncOnceInsufficient(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	zipWith(t, filepath.Join(dir, "a.zip"), 0, 4)
	s := New(store, dir, 10, 10, 100000)
	added, _ := s.SyncOnce()
	if added != 4 {
		t.Fatalf("want 4 added, got %d", added)
	}
}

func TestSyncOnceBadZipSkipped(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	if err := os.WriteFile(filepath.Join(dir, "bad.zip"), []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipWith(t, filepath.Join(dir, "good.zip"), 0, 3)
	s := New(store, dir, 10, 10, 100000)
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
	s := New(store, dir, 10, 10, 100000)
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

func TestNextDailyTime(t *testing.T) {
	loc := time.UTC
	mk := func(h, m int) time.Time { return time.Date(2026, 7, 13, h, m, 0, 0, loc) }
	cases := []struct {
		now      time.Time
		wantDay  int
		wantHour int
	}{
		{mk(0, 30), 13, 1}, // before 1am -> today 1am
		{mk(1, 0), 14, 1},  // exactly 1am -> next day (strictly after)
		{mk(13, 0), 14, 1}, // after 1am -> next day
	}
	for _, c := range cases {
		got := NextDailyTime(c.now, 1)
		if got.Day() != c.wantDay || got.Hour() != c.wantHour || got.Minute() != 0 {
			t.Errorf("NextDailyTime(%v,1)=%v, want day=%d hour=%d", c.now, got, c.wantDay, c.wantHour)
		}
	}
}
