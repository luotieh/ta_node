package queue

import (
	"context"
	"fmt"
	"hash/fnv"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"ta_node/internal/event"
)

// maxShards bounds the shard count; composite pending IDs reserve 6 bits for
// the shard index.
const maxShards = 64
const shardShift = 6

// ShardedQueue routes events by FNV-1a hash of the event ID across N
// independent databases, so writes proceed concurrently instead of
// serializing on one writer connection. Shard 0 is the base path itself,
// which keeps pre-sharding databases readable and drainable without
// migration.
type ShardedQueue struct {
	shards []*SQLiteQueue
}

// Open creates (or opens) a sharded queue. n<=1 keeps the legacy single-file
// layout with identical behavior.
func Open(path, backend string, n int) (*ShardedQueue, error) {
	if n < 1 {
		n = 1
	}
	if n > maxShards {
		return nil, fmt.Errorf("storage.shards must be between 1 and %d", maxShards)
	}
	s := &ShardedQueue{}
	for i := 0; i < n; i++ {
		p := path
		if i > 0 {
			p = path + ".shard" + strconv.Itoa(i)
		}
		q, err := OpenSQLite(p, backend)
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		s.shards = append(s.shards, q)
	}
	return s, nil
}

// shardPaths returns the base database plus any sibling shard files, so
// read-only tooling works regardless of the configured shard count.
func shardPaths(path string) []string {
	paths := []string{path}
	matches, _ := filepath.Glob(path + ".shard*")
	for _, m := range matches {
		suffix := m[len(path)+len(".shard"):]
		if _, err := strconv.Atoi(suffix); err == nil && suffix != "" {
			paths = append(paths, m)
		}
	}
	return paths
}

func (s *ShardedQueue) shard(eventID string) *SQLiteQueue {
	if len(s.shards) == 1 {
		return s.shards[0]
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(eventID))
	return s.shards[int(h.Sum32()%uint32(len(s.shards)))]
}

// Enqueue routes by event ID; all context revisions of one event share a
// shard, and shards write concurrently.
func (s *ShardedQueue) Enqueue(ev event.ThreatEvent) error {
	return s.shard(ev.EventID).Enqueue(ev)
}

// PendingIDs merges per-shard pendings by creation time. With multiple shards
// the returned IDs are composite (row ID shifted, shard index in low bits)
// and must be passed back to LoadEvent.
func (s *ShardedQueue) PendingIDs(limit int) ([]int64, error) {
	if len(s.shards) == 1 {
		return s.shards[0].PendingIDs(limit)
	}
	if limit <= 0 {
		limit = 100
	}
	type entry struct {
		id      int64
		created int64
		shard   int
	}
	var all []entry
	for i, sh := range s.shards {
		rows, err := sh.pendingEntries(limit)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			all = append(all, entry{id: r.id, created: r.created, shard: i})
		}
	}
	sort.Slice(all, func(a, b int) bool {
		if all[a].created != all[b].created {
			return all[a].created < all[b].created
		}
		return all[a].id < all[b].id
	})
	if len(all) > limit {
		all = all[:limit]
	}
	out := make([]int64, len(all))
	for i, e := range all {
		out[i] = e.id<<shardShift | int64(e.shard)
	}
	return out, nil
}

func (s *ShardedQueue) LoadEvent(id int64) (event.ThreatEvent, error) {
	if len(s.shards) == 1 {
		return s.shards[0].LoadEvent(id)
	}
	return s.shards[id&(maxShards-1)].LoadEvent(id >> shardShift)
}

func (s *ShardedQueue) LoadPending(limit int) ([]event.ThreatEvent, error) {
	ids, err := s.PendingIDs(limit)
	if err != nil {
		return nil, err
	}
	var out []event.ThreatEvent
	for _, id := range ids {
		ev, err := s.LoadEvent(id)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}

func (s *ShardedQueue) MarkPushed(eventID string, contextRevision uint64) error {
	return s.shard(eventID).MarkPushed(eventID, contextRevision)
}

func (s *ShardedQueue) MarkFailed(eventID string, contextRevision uint64, errMsg string) error {
	return s.shard(eventID).MarkFailed(eventID, contextRevision, errMsg)
}

func (s *ShardedQueue) SetMaxRetry(n int) {
	for _, sh := range s.shards {
		sh.SetMaxRetry(n)
	}
}

func (s *ShardedQueue) Activate() error {
	for _, sh := range s.shards {
		if err := sh.Activate(); err != nil {
			return err
		}
	}
	return nil
}

func (s *ShardedQueue) RecoverArchives() error {
	for _, sh := range s.shards {
		if err := sh.RecoverArchives(); err != nil {
			return err
		}
	}
	return nil
}

// Archive fans out over the shards; segment file names are UUIDs, so a shared
// archive directory never collides.
func (s *ShardedQueue) Archive(ctx context.Context, dir string, before time.Time, limit int) (int, error) {
	total := 0
	for _, sh := range s.shards {
		n, err := sh.Archive(ctx, dir, before, limit)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (s *ShardedQueue) Collect(limit int) (int, error) {
	total := 0
	for _, sh := range s.shards {
		n, err := sh.Collect(limit)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// Stats aggregates across shards. AvailableBytes comes from the first shard;
// all shards share one directory and filesystem.
func (s *ShardedQueue) Stats() (StorageStats, error) {
	var out StorageStats
	for i, sh := range s.shards {
		st, err := sh.Stats()
		if err != nil {
			return out, err
		}
		out.PageBytes += st.PageBytes
		out.ReusableBytes += st.ReusableBytes
		out.FileBytes += st.FileBytes
		out.ArchiveSegments += st.ArchiveSegments
		if i == 0 {
			out.AvailableBytes = st.AvailableBytes
			out.Backend = st.Backend
		}
	}
	out.Shards = len(s.shards)
	return out, nil
}

func (s *ShardedQueue) Close() error {
	var first error
	for _, sh := range s.shards {
		if err := sh.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
