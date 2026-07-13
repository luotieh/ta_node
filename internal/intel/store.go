package intel

import (
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Store holds the active IOC set, backed by a single writable file at path.
// Add/Delete/Sync/SyncSource/UpsertMany/UpsertDedup/PruneExpired all mutate the
// set and persist it atomically. items is the read view used for matching,
// List and Stats.
type Store struct {
	mu      sync.RWMutex
	items   map[string]ThreatIntel
	path    string
	version int64
}

// NewStore opens a store backed by a single writable file (path may be "").
func NewStore(path string) (*Store, error) {
	s := &Store{items: map[string]ThreatIntel{}, path: path}
	if path != "" {
		if err := s.Reload(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Reload() error {
	var loaded []ThreatIntel
	if s.path != "" {
		var err error
		loaded, err = LoadFile(s.path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			loaded = nil
		}
	}
	now := time.Now().Unix()
	items := make(map[string]ThreatIntel, len(loaded))
	for _, it := range loaded {
		normalize(&it, now)
		items[it.ID] = it
	}
	s.mu.Lock()
	s.items = items
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
	s.items[it.ID] = it
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return it, SaveFileAtomic(s.path, saved)
	}
	return it, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	if _, ok := s.items[id]; !ok {
		s.mu.Unlock()
		return errors.New("intel not found")
	}
	delete(s.items, id)
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, saved)
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
	s.items = next
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
		s.items[it.ID] = it
	}
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
	for id, it := range s.items {
		if it.Source == source {
			delete(s.items, id)
		}
	}
	for _, it := range normalized {
		s.items[it.ID] = it
	}
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
	for id, it := range s.items {
		if it.ExpireAt > 0 && it.ExpireAt < now {
			delete(s.items, id)
			deleted++
		}
	}
	if deleted == 0 {
		s.mu.Unlock()
		return 0
	}
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

func (s *Store) snapshotLocked() []ThreatIntel {
	items := make([]ThreatIntel, 0, len(s.items))
	for _, item := range s.items {
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

// canonicalValue normalizes an IOC value for identity comparison, mirroring the
// matcher's indexing so two entries that would match the same traffic collapse
// to one key.
func canonicalValue(t, v string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "ip":
		if c := canonicalIP(v); c != "" {
			return c
		}
	case "domain":
		return canonicalDomain(v)
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// CanonicalKey identifies an IOC by (type, normalized value) rather than id, so
// the same indicator delivered under different feed ids is deduped. Exported so
// the iocsync feed can dedup candidates against the store.
func CanonicalKey(it ThreatIntel) string {
	return strings.ToLower(strings.TrimSpace(it.Type)) + "|" + canonicalValue(it.Type, it.Value)
}

// UpsertDedup merges a feed batch into the set with (type,value) dedup:
//   - within the batch, entries with the same canonical key collapse, keeping
//     the one with the newest incoming updated_at;
//   - against the existing set, an incoming entry whose canonical key already
//     exists reuses that entry's id (in-place update) instead of adding a
//     duplicate row for the same indicator.
//
// It bumps the version (matcher picks it up on the next packet) and persists
// atomically. An empty effective batch is a no-op.
func (s *Store) UpsertDedup(items []ThreatIntel) error {
	batch := map[string]ThreatIntel{}
	for _, it := range items {
		k := CanonicalKey(it)
		if ex, ok := batch[k]; ok && ex.UpdatedAt >= it.UpdatedAt {
			continue
		}
		batch[k] = it
	}
	if len(batch) == 0 {
		return nil
	}
	now := time.Now().Unix()
	s.mu.Lock()
	existing := make(map[string]string, len(s.items))
	for id, it := range s.items {
		existing[CanonicalKey(it)] = id
	}
	for k, it := range batch {
		if id, ok := existing[k]; ok {
			it.ID = id
		}
		createdAt := it.CreatedAt
		normalize(&it, now)
		if prev, ok := s.items[it.ID]; ok && createdAt == 0 {
			it.CreatedAt = prev.CreatedAt
		}
		s.items[it.ID] = it
	}
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, saved)
	}
	return nil
}
