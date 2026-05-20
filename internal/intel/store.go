package intel

import (
	"errors"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Store struct {
	mu    sync.RWMutex
	items map[string]ThreatIntel
	path  string
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

func (s *Store) Add(it ThreatIntel) (ThreatIntel, error) {
	now := time.Now().Unix()
	normalize(&it, now)
	s.mu.Lock()
	s.items[it.ID] = it
	items := make([]ThreatIntel, 0, len(s.items))
	for _, item := range s.items {
		items = append(items, item)
	}
	s.mu.Unlock()
	if s.path != "" {
		return it, SaveFile(s.path, items)
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
	items := make([]ThreatIntel, 0, len(s.items))
	for _, item := range s.items {
		items = append(items, item)
	}
	s.mu.Unlock()
	if s.path != "" {
		return SaveFile(s.path, items)
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
	s.mu.Unlock()
	if s.path != "" {
		return SaveFile(s.path, items)
	}
	return nil
}

func normalize(it *ThreatIntel, now int64) {
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
