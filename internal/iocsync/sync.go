package iocsync

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// isYAML reports whether path has a .yaml or .yml extension.
func isYAML(path string) bool {
	n := strings.ToLower(path)
	return strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")
}

// SyncOnce scans dir for *.zip and *.yaml/*.yml files, imports every "new" IOC
// (canonical key not in the main file) into the store, then prunes files older
// than retainDays. It returns the number of IOCs added. Bad/half-written files
// are logged and skipped; a scan error never shrinks the rule set. retainDays
// <= 0 disables cleanup.
func (s *Syncer) SyncOnce() (int, error) {
	zipPaths, _ := filepath.Glob(filepath.Join(s.dir, "*.zip"))
	yamlPaths, _ := filepath.Glob(filepath.Join(s.dir, "*.yaml"))
	ymlPaths, _ := filepath.Glob(filepath.Join(s.dir, "*.yml"))
	allPaths := append(append(zipPaths, yamlPaths...), ymlPaths...)
	sort.Strings(allPaths)

	// The main file is the cursor: an IOC already present is not "new".
	seen := map[string]bool{}
	for _, it := range s.store.List() {
		seen[intel.CanonicalKey(it)] = true
	}

	var candidates []intel.ThreatIntel
	scanned := 0
	for _, p := range allPaths {
		if info, statErr := os.Stat(p); statErr != nil || info.IsDir() {
			continue
		}
		var items []intel.ThreatIntel
		var exErr error
		if isYAML(p) {
			items, exErr = extractPlainYAML(p)
		} else {
			items, exErr = extractItems(p, s.maxItems)
		}
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
	removed := s.cleanupOldFiles(time.Now())
	log.Printf("iocsync: added %d new IOC(s) from %d file(s); removed %d expired file(s)", len(candidates), scanned, removed)
	return len(candidates), nil
}

// cleanupOldFiles removes *.zip and *.yaml/*.yml files in dir whose mtime is
// older than retainDays.
func (s *Syncer) cleanupOldFiles(now time.Time) int {
	if s.retainDays <= 0 {
		return 0
	}
	zipPaths, _ := filepath.Glob(filepath.Join(s.dir, "*.zip"))
	yamlPaths, _ := filepath.Glob(filepath.Join(s.dir, "*.yaml"))
	ymlPaths, _ := filepath.Glob(filepath.Join(s.dir, "*.yml"))
	allPaths := append(append(zipPaths, yamlPaths...), ymlPaths...)

	cutoff := now.AddDate(0, 0, -s.retainDays)
	removed := 0
	for _, p := range allPaths {
		info, statErr := os.Stat(p)
		if statErr != nil || info.IsDir() {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(p); err != nil {
				log.Printf("iocsync: remove old file %s failed: %v", filepath.Base(p), err)
				continue
			}
			removed++
		}
	}
	return removed
}
