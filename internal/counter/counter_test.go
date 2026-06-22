package counter

import (
	"testing"
	"time"
)

func TestWindowCountsWithinWindowAndExpires(t *testing.T) {
	w := New(60*time.Second, 100)
	base := time.Unix(1000, 0)

	if c, _ := w.Hit("k", base); c != 1 {
		t.Fatalf("first hit count: want 1, got %d", c)
	}
	if c, _ := w.Hit("k", base.Add(10*time.Second)); c != 2 {
		t.Fatalf("second hit count: want 2, got %d", c)
	}
	// A hit far outside the window drops the earlier two; only this one remains.
	c, first := w.Hit("k", base.Add(200*time.Second))
	if c != 1 {
		t.Fatalf("after window expiry: want 1, got %d", c)
	}
	if !first.Equal(base.Add(200 * time.Second)) {
		t.Fatalf("first-seen should be the surviving stamp, got %v", first)
	}
}

func TestWindowFirstSeenIsEarliestInWindow(t *testing.T) {
	w := New(60*time.Second, 100)
	base := time.Unix(1000, 0)
	w.Hit("k", base)
	_, first := w.Hit("k", base.Add(30*time.Second))
	if !first.Equal(base) {
		t.Fatalf("first-seen: want %v, got %v", base, first)
	}
}

func TestWindowKeysAreIndependent(t *testing.T) {
	w := New(60*time.Second, 100)
	base := time.Unix(1000, 0)
	w.Hit("a", base)
	w.Hit("a", base)
	if c, _ := w.Hit("b", base); c != 1 {
		t.Fatalf("distinct key should start at 1, got %d", c)
	}
}

func TestWindowEvictsIdleWhenFull(t *testing.T) {
	w := New(60*time.Second, 1)
	base := time.Unix(1000, 0)
	w.Hit("a", base)
	// "a" is now idle; a new key past the window triggers eviction of "a".
	if c, _ := w.Hit("b", base.Add(120*time.Second)); c != 1 {
		t.Fatalf("want fresh count 1 for new key, got %d", c)
	}
	if w.Len() != 1 {
		t.Fatalf("map must stay capped at 1, got %d", w.Len())
	}
}

func TestCleanupRemovesIdleKeys(t *testing.T) {
	w := New(60*time.Second, 100)
	base := time.Unix(1000, 0)
	w.Hit("a", base)
	w.Hit("b", base)
	if removed := w.Cleanup(base.Add(120 * time.Second)); removed != 2 {
		t.Fatalf("expected 2 evictions, got %d", removed)
	}
	if w.Len() != 0 {
		t.Fatalf("expected empty counter, got %d", w.Len())
	}
}
