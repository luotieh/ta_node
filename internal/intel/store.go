package intel

import (
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Store struct {
	mu      sync.RWMutex
	items   map[string]ThreatIntel
	path    string
	version int64
}

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
	items, err := LoadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.mu.Lock()
			s.items = map[string]ThreatIntel{}
			s.version++
			s.mu.Unlock()
			return nil
		}
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = map[string]ThreatIntel{}
	now := time.Now().Unix()
	for _, it := range items {
		normalize(&it, now)
		s.items[it.ID] = it
	}
	s.version++
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
	items := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return it, SaveFileAtomic(s.path, items)
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
