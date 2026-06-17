package push

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"ta_node/internal/event"
	"ta_node/internal/queue"
)

func TestPushFailureKeepsEvent(t *testing.T) {
	q, err := queue.NewSQLite(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	ev := event.ThreatEvent{EventID: "e1", EventTime: 1}
	if err := q.Enqueue(ev); err != nil {
		t.Fatal(err)
	}
	client := NewClient("http://127.0.0.1:1/api/events", "", time.Millisecond)
	drain(context.Background(), q, client, 10)
	pending, err := q.LoadPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("event should remain pending after push failure, got %d", len(pending))
	}
}
