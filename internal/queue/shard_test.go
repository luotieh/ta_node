package queue

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"ta_node/internal/event"
)

func shardTestEvent(id string, revision uint64) event.ThreatEvent {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = byte(i)
	}
	return event.ThreatEvent{
		EventID: id, EventTime: 1700000000000000, ContextRevision: revision,
		Model: "test", SrcIP: "192.0.2.1", DstIP: "203.0.113.9",
		RawPacket: &event.RawPacketContext{MessageDirection: "request", PacketHex: hex.EncodeToString(raw)},
	}
}

func TestShardedQueueRoutesAndReads(t *testing.T) {
	base := filepath.Join(t.TempDir(), "events.db")
	q, err := Open(base, "v2", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for i := 0; i < 64; i++ {
		id := fmt.Sprintf("evt-%d", i)
		for revision := uint64(1); revision <= 2; revision++ {
			if err := q.Enqueue(shardTestEvent(id, revision)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if paths := shardPaths(base); len(paths) < 2 {
		t.Fatalf("expected sibling shard files, got %v", paths)
	}
	ids, err := q.PendingIDs(200)
	if err != nil || len(ids) != 128 {
		t.Fatalf("pending = %d, %v; want 128", len(ids), err)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		ev, err := q.LoadEvent(id)
		if err != nil {
			t.Fatalf("composite id did not resolve: %v", err)
		}
		seen[queueRecordID(ev.EventID, ev.ContextRevision)] = true
	}
	if len(seen) != 128 {
		t.Fatalf("unique records = %d, want 128", len(seen))
	}
	// Revisions of one event share a shard, so status updates route identically.
	if err := q.MarkPushed("evt-1", 1); err != nil {
		t.Fatal(err)
	}
	if err := q.MarkPushed("evt-1", 2); err != nil {
		t.Fatal(err)
	}
	if ids, err = q.PendingIDs(200); err != nil || len(ids) != 126 {
		t.Fatalf("pending after mark = %d, %v; want 126", len(ids), err)
	}
	logs, err := RecentPushLogs(base, 50)
	if err != nil || len(logs) == 0 {
		t.Fatalf("push logs not merged across shards: %d, %v", len(logs), err)
	}
	part, err := ReadPacketRange(base, "evt-1", 0, 16)
	if err != nil {
		t.Fatalf("packet range not found across shards: %v", err)
	}
	if part.TotalLength != 64 || part.Length != 16 {
		t.Fatalf("unexpected range: %+v", part)
	}
	stats, err := q.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Shards != 4 {
		t.Fatalf("stats shards = %d, want 4", stats.Shards)
	}
}

func TestShardedQueueDrainsLegacyBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "events.db")
	single, err := NewSQLite(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := single.Enqueue(shardTestEvent("legacy-1", 1)); err != nil {
		t.Fatal(err)
	}
	if err := single.Close(); err != nil {
		t.Fatal(err)
	}
	q, err := Open(base, "v2", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	ids, err := q.PendingIDs(10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range ids {
		ev, err := q.LoadEvent(id)
		if err != nil {
			t.Fatal(err)
		}
		if ev.EventID == "legacy-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("pre-sharding row in the base file was not picked up")
	}
}

func TestShardedQueueConcurrentEnqueue(t *testing.T) {
	base := filepath.Join(t.TempDir(), "events.db")
	q, err := Open(base, "v2", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 400)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := q.Enqueue(shardTestEvent(fmt.Sprintf("g%d-%d", g, i), 1)); err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent enqueue failed: %v", err)
	}
	ids, err := q.PendingIDs(500)
	if err != nil || len(ids) != 400 {
		t.Fatalf("pending = %d, %v; want 400", len(ids), err)
	}
}
