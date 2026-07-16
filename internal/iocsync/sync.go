package iocsync

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"ta_node/internal/intel"
)

// Syncer performs the daily incremental IOC sync: it scans dir for gateway
// *.zip packs, adds every rule not already in the store, then removes zips
// older than retainDays. The store's own dedup (by canonical type/value) makes
// the main file the consumption cursor. There is no per-day cap: how much the
// gateway delivers is controlled upstream by the threat-aggregation platform.
type Syncer struct {
	store      *intel.Store
	dir        string
	retainDays int
	maxItems   int
}

func New(store *intel.Store, dir string, retainDays, maxItems int) *Syncer {
	return &Syncer{store: store, dir: dir, retainDays: retainDays, maxItems: maxItems}
}

// SyncOnce scans dir, imports every "new" IOC (canonical key not in the main
// file) into the store, then prunes zips older than retainDays. It returns the
// number of IOCs added. Bad/half-written zips are logged and skipped; a scan
// error never shrinks the rule set. retainDays <= 0 disables cleanup.
func (s *Syncer) SyncOnce() (int, error) {
	paths, err := filepath.Glob(filepath.Join(s.dir, "*.zip"))
	if err != nil {
		return 0, err
	}
	sort.Strings(paths)

	// The main file is the cursor: an IOC already present is not "new".
	seen := map[string]bool{}
	for _, it := range s.store.List() {
		seen[intel.CanonicalKey(it)] = true
	}

	var candidates []intel.ThreatIntel
	scanned := 0
	for _, p := range paths {
		if info, statErr := os.Stat(p); statErr != nil || info.IsDir() {
			continue
		}
		items, exErr := extractItems(p, s.maxItems)
		if exErr != nil {
			log.Printf("iocsync: skip %s: %v", filepath.Base(p), exErr)
			continue
		}
		scanned++
		for _, it := range items {
			k := intel.CanonicalKey(it)
			if seen[k] {
				continue
			}
			seen[k] = true
			candidates = append(candidates, it)
		}
	}

	if len(candidates) > 0 {
		if err := s.store.UpsertDedup(candidates); err != nil {
			return 0, err
		}
	}
	removed := s.cleanupOldZips(time.Now())
	log.Printf("iocsync: added %d new IOC(s) from %d zip(s); removed %d expired zip(s)", len(candidates), scanned, removed)
	return len(candidates), nil
}

// cleanupOldZips removes *.zip in dir whose mtime is older than retainDays.
func (s *Syncer) cleanupOldZips(now time.Time) int {
	if s.retainDays <= 0 {
		return 0
	}
	paths, err := filepath.Glob(filepath.Join(s.dir, "*.zip"))
	if err != nil {
		return 0
	}
	cutoff := now.AddDate(0, 0, -s.retainDays)
	removed := 0
	for _, p := range paths {
		info, statErr := os.Stat(p)
		if statErr != nil || info.IsDir() {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(p); err != nil {
				log.Printf("iocsync: remove old zip %s failed: %v", filepath.Base(p), err)
				continue
			}
			removed++
		}
	}
	return removed
}
