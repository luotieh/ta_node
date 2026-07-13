package iocsync

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"ta_node/internal/intel"
)

// Watcher polls dir for gateway-delivered *.zip IOC packs and merges their
// rules into the store. Processed packs move to dir/processed, unrecoverable
// ones to dir/failed; a pack that cannot be opened yet (still being written) is
// left in place and retried on the next scan until it grows stale.
type Watcher struct {
	store      *intel.Store
	dir        string
	interval   time.Duration
	maxItems   int
	staleAfter time.Duration
}

// New builds a Watcher. staleAfter (how long an unreadable zip may sit before
// it is treated as corrupt rather than half-written) defaults to max(2*interval,
// 30s).
func New(store *intel.Store, dir string, interval time.Duration, maxItems int) *Watcher {
	stale := 2 * interval
	if stale < 30*time.Second {
		stale = 30 * time.Second
	}
	return &Watcher{store: store, dir: dir, interval: interval, maxItems: maxItems, staleAfter: stale}
}

// Run scans immediately then every interval until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) {
	w.scanOnce()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.scanOnce()
		}
	}
}

func (w *Watcher) scanOnce() {
	paths, err := filepath.Glob(filepath.Join(w.dir, "*.zip"))
	if err != nil {
		log.Printf("iocsync: glob %s failed: %v", w.dir, err)
		return
	}
	sort.Strings(paths)
	for _, p := range paths {
		if info, err := os.Stat(p); err != nil || info.IsDir() {
			continue
		}
		w.processZip(p)
	}
}

func (w *Watcher) processZip(path string) {
	items, err := extractItems(path, w.maxItems)
	if errors.Is(err, errIncomplete) {
		// Half-written: leave in place and retry — unless it has sat unreadable
		// long enough to be considered corrupt.
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > w.staleAfter {
			log.Printf("iocsync: %s unreadable for >%s, moving to failed/", filepath.Base(path), w.staleAfter)
			w.moveTo(path, "failed")
		}
		return
	}
	if err != nil {
		log.Printf("iocsync: %s parse failed: %v", filepath.Base(path), err)
		w.moveTo(path, "failed")
		return
	}
	if err := w.store.UpsertDedup(items); err != nil {
		log.Printf("iocsync: %s upsert failed: %v", filepath.Base(path), err)
		w.moveTo(path, "failed")
		return
	}
	log.Printf("iocsync: imported %d IOC items from %s", len(items), filepath.Base(path))
	w.moveTo(path, "processed")
}

// moveTo relocates path into dir/sub, creating it and suffixing on name clash so
// a re-delivered filename never overwrites an earlier pack.
func (w *Watcher) moveTo(path, sub string) {
	dst := filepath.Join(w.dir, sub)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		log.Printf("iocsync: mkdir %s failed: %v", dst, err)
		return
	}
	target := filepath.Join(dst, filepath.Base(path))
	if _, err := os.Stat(target); err == nil {
		target = filepath.Join(dst, fmt.Sprintf("%d-%s", time.Now().UnixNano(), filepath.Base(path)))
	}
	if err := os.Rename(path, target); err != nil {
		log.Printf("iocsync: move %s -> %s failed: %v", path, target, err)
	}
}
