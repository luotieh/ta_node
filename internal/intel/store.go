package intel

import (
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Store holds the active IOC set. It separates two sources:
//
//   - primary: the writable file at path. Add/Delete/Sync/SyncSource/
//     UpsertMany/PruneExpired all mutate this set and persist it atomically.
//   - overlay: read-only files loaded from dir (intel_dir). These are bulk or
//     incremental feeds dropped in as separate files and loaded concurrently;
//     splitting a large IOC list across many files keeps each one small and
//     lets a new file be added without editing the others.
//
// items is the merged read view used for matching, List and Stats. On an ID
// collision the primary (locally managed) entry wins over an overlay feed.
type Store struct {
	mu      sync.RWMutex
	items   map[string]ThreatIntel
	primary map[string]ThreatIntel
	overlay map[string]ThreatIntel
	path    string
	dir     string
	version int64
}

// NewStore opens a store backed by a single writable file.
func NewStore(path string) (*Store, error) { return NewStoreWithDir(path, "") }

// NewStoreWithDir opens a store backed by a writable file plus a read-only
// overlay directory of additional IOC files (either may be empty).
func NewStoreWithDir(path, dir string) (*Store, error) {
	s := &Store{
		items:   map[string]ThreatIntel{},
		primary: map[string]ThreatIntel{},
		overlay: map[string]ThreatIntel{},
		path:    path,
		dir:     dir,
	}
	if path != "" || dir != "" {
		if err := s.Reload(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Reload() error {
	overlayItems, err := LoadDir(s.dir)
	if err != nil {
		return err
	}
	var primaryItems []ThreatIntel
	if s.path != "" {
		primaryItems, err = LoadFile(s.path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			primaryItems = nil
		}
	}
	now := time.Now().Unix()
	overlay := make(map[string]ThreatIntel, len(overlayItems))
	for _, it := range overlayItems {
		normalize(&it, now)
		overlay[it.ID] = it
	}
	primary := make(map[string]ThreatIntel, len(primaryItems))
	for _, it := range primaryItems {
		normalize(&it, now)
		primary[it.ID] = it
	}
	s.mu.Lock()
	s.overlay = overlay
	s.primary = primary
	s.rebuildItemsLocked()
	s.version++
	s.mu.Unlock()
	return nil
}

func (s *Store) List() []ThreatIntel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ThreatIntel, 0, len(s.items))
	for _, it := range s.items {
		out = append(out, it)
	}
	return out
}

func (s *Store) Get(id string) (ThreatIntel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	it, ok := s.items[id]
	return it, ok
}

func (s *Store) Version() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func (s *Store) Add(it ThreatIntel) (ThreatIntel, error) {
	now := time.Now().Unix()
	normalize(&it, now)
	s.mu.Lock()
	s.primary[it.ID] = it
	s.rebuildItemsLocked()
	s.version++
	items := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return it, SaveFileAtomic(s.path, items)
	}
	return it, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	if _, ok := s.primary[id]; !ok {
		_, inOverlay := s.overlay[id]
		s.mu.Unlock()
		if inOverlay {
			return errors.New("intel is provided by a read-only overlay file; edit the file in intel_dir to remove it")
		}
		return errors.New("intel not found")
	}
	delete(s.primary, id)
	s.rebuildItemsLocked()
	s.version++
	items := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, items)
	}
	return nil
}

func (s *Store) Sync(items []ThreatIntel) error {
	now := time.Now().Unix()
	next := map[string]ThreatIntel{}
	for _, it := range items {
		normalize(&it, now)
		next[it.ID] = it
	}
	s.mu.Lock()
	s.primary = next
	s.rebuildItemsLocked()
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, saved)
	}
	return nil
}

func (s *Store) UpsertMany(items []ThreatIntel) error {
	now := time.Now().Unix()
	s.mu.Lock()
	for _, it := range items {
		createdAt := it.CreatedAt
		normalize(&it, now)
		if existing, ok := s.items[it.ID]; ok && createdAt == 0 {
			it.CreatedAt = existing.CreatedAt
		}
		s.primary[it.ID] = it
	}
	s.rebuildItemsLocked()
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, saved)
	}
	return nil
}

func (s *Store) SyncSource(source string, items []ThreatIntel) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return errors.New("source required")
	}
	now := time.Now().Unix()
	normalized := make([]ThreatIntel, 0, len(items))
	for _, it := range items {
		it.Source = source
		normalize(&it, now)
		normalized = append(normalized, it)
	}
	s.mu.Lock()
	for id, it := range s.primary {
		if it.Source == source {
			delete(s.primary, id)
		}
	}
	for _, it := range normalized {
		s.primary[it.ID] = it
	}
	s.rebuildItemsLocked()
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, saved)
	}
	return nil
}

func (s *Store) Stats() StoreStats {
	now := time.Now().Unix()
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := StoreStats{
		Total:    len(s.items),
		ByType:   map[string]int{},
		BySource: map[string]int{},
		Version:  s.version,
	}
	for _, it := range s.items {
		if it.Enabled {
			stats.Enabled++
		}
		if it.ExpireAt > 0 && it.ExpireAt < now {
			stats.Expired++
		}
		stats.ByType[strings.ToLower(it.Type)]++
		stats.BySource[it.Source]++
		if it.UpdatedAt > stats.LastUpdatedAt {
			stats.LastUpdatedAt = it.UpdatedAt
		}
	}
	return stats
}

func (s *Store) PruneExpired(now int64) int {
	s.mu.Lock()
	deleted := 0
	for id, it := range s.primary {
		if it.ExpireAt > 0 && it.ExpireAt < now {
			delete(s.primary, id)
			deleted++
		}
	}
	// Drop expired overlay items from the in-memory view too. This is not
	// persisted (overlay files are read-only and re-read on the next reload),
	// but keeps the active set and stats accurate between reloads.
	for id, it := range s.overlay {
		if it.ExpireAt > 0 && it.ExpireAt < now {
			delete(s.overlay, id)
			deleted++
		}
	}
	if deleted == 0 {
		s.mu.Unlock()
		return 0
	}
	s.rebuildItemsLocked()
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		if err := SaveFileAtomic(s.path, saved); err != nil {
			return deleted
		}
	}
	return deleted
}

// rebuildItemsLocked refreshes the merged read view. Primary (writable) entries
// win over overlay feeds on an ID collision.
func (s *Store) rebuildItemsLocked() {
	items := make(map[string]ThreatIntel, len(s.overlay)+len(s.primary))
	for id, it := range s.overlay {
		items[id] = it
	}
	for id, it := range s.primary {
		items[id] = it
	}
	s.items = items
}

// snapshotLocked returns the writable (primary) items for persistence. Overlay
// feeds are never written back to the primary file.
func (s *Store) snapshotLocked() []ThreatIntel {
	items := make([]ThreatIntel, 0, len(s.primary))
	for _, item := range s.primary {
		items = append(items, item)
	}
	return items
}

func normalize(it *ThreatIntel, now int64) {
	it.Type = strings.ToLower(strings.TrimSpace(it.Type))
	it.Value = strings.TrimSpace(it.Value)
	it.Source = strings.TrimSpace(it.Source)
	if it.ID == "" {
		it.ID = "ioc-" + uuid.NewString()
	}
	if it.Source == "" {
		it.Source = "local"
	}
	if it.Severity == "" {
		it.Severity = "medium"
	}
	if it.CreatedAt == 0 {
		it.CreatedAt = now
	}
	it.UpdatedAt = now
}
