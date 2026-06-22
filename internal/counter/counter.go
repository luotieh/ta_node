// Package counter provides a bounded, sliding-window hit counter used to expose
// a LOCAL (node-scoped) burst signal on events. It is deliberately approximate
// and memory-bounded: a hint for AI triage on this node, NOT an authoritative
// count. Global / long-window counting belongs on the management side, which
// can deduplicate across all nodes (see the task plan, §7.1).
package counter

import (
	"sync"
	"time"
)

// defaultMaxStamps bounds per-key memory: under a flood a key retains at most
// this many recent timestamps, so the reported count becomes a floor rather
// than exact.
const defaultMaxStamps = 1024

// Window counts hits per key within a trailing time window. It is safe for
// concurrent use and never grows past maxKeys entries.
type Window struct {
	mu        sync.Mutex
	window    time.Duration
	maxKeys   int
	maxStamps int
	entries   map[string]*entry
}

type entry struct {
	stamps []time.Time
}

// New builds a Window. Non-positive arguments fall back to sane defaults
// (60s window / 100,000 keys).
func New(window time.Duration, maxKeys int) *Window {
	if window <= 0 {
		window = time.Minute
	}
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &Window{
		window:    window,
		maxKeys:   maxKeys,
		maxStamps: defaultMaxStamps,
		entries:   map[string]*entry{},
	}
}

// Hit records a hit for key at time now and returns the number of hits within
// the trailing window (including this one) and the earliest hit still in the
// window. now is supplied by the caller (driven by packet/flow time) so the
// counter behaves deterministically under offline PCAP replay.
func (w *Window) Hit(key string, now time.Time) (count int, firstSeen time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()

	cutoff := now.Add(-w.window)
	e := w.entries[key]
	if e == nil {
		if len(w.entries) >= w.maxKeys {
			w.evictIdleLocked(cutoff)
			if len(w.entries) >= w.maxKeys {
				// Still at capacity: don't grow the map, just report this hit.
				return 1, now
			}
		}
		e = &entry{}
		w.entries[key] = e
	}
	e.stamps = pruneBefore(e.stamps, cutoff)
	e.stamps = append(e.stamps, now)
	if len(e.stamps) > w.maxStamps {
		e.stamps = e.stamps[len(e.stamps)-w.maxStamps:]
	}
	return len(e.stamps), e.stamps[0]
}

// Cleanup removes keys whose most recent hit is older than the window relative
// to now, returning the number evicted. Optional: Hit already evicts lazily
// when the map is full.
func (w *Window) Cleanup(now time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.evictIdleLocked(now.Add(-w.window))
}

// Len reports the number of tracked keys.
func (w *Window) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.entries)
}

func (w *Window) evictIdleLocked(cutoff time.Time) int {
	removed := 0
	for k, e := range w.entries {
		if len(e.stamps) == 0 || !e.stamps[len(e.stamps)-1].After(cutoff) {
			delete(w.entries, k)
			removed++
		}
	}
	return removed
}

// pruneBefore drops leading timestamps at or before cutoff (outside the window)
// and compacts in place so the old backing array is not retained.
func pruneBefore(stamps []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(stamps) && !stamps[i].After(cutoff) {
		i++
	}
	if i == 0 {
		return stamps
	}
	n := copy(stamps, stamps[i:])
	return stamps[:n]
}
