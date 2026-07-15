package queue

import (
	"path/filepath"
	"testing"

	"ta_node/internal/event"
)

func TestSQLiteQueue(t *testing.T) {
	q, err := NewSQLite(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	ev := event.ThreatEvent{EventID: "e1", EventTime: 1, Model: "test"}
	if err := q.Enqueue(ev); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(ev); err != nil {
		t.Fatal(err)
	}
	pending, err := q.LoadPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected deduped pending event, got %d", len(pending))
	}
	if err := q.MarkFailed("e1", "boom"); err != nil {
		t.Fatal(err)
	}
	pending, err = q.LoadPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("failed event should remain retryable, got %d", len(pending))
	}
	if err := q.MarkPushed("e1"); err != nil {
		t.Fatal(err)
	}
	pending, err = q.LoadPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pushed event should be hidden, got %d", len(pending))
	}
}

func TestSQLiteQueueMaxRetry(t *testing.T) {
	q, err := NewSQLite(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	q.SetMaxRetry(2)
	if err := q.Enqueue(event.ThreatEvent{EventID: "e1", EventTime: 1}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		pending, err := q.LoadPending(10)
		if err != nil {
			t.Fatal(err)
		}
		if len(pending) != 1 {
			t.Fatalf("retry %d: expected event retryable, got %d", i, len(pending))
		}
		if err := q.MarkFailed("e1", "boom"); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := q.LoadPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("event at retry cap should be abandoned, got %d", len(pending))
	}

	q.SetMaxRetry(0)
	pending, err = q.LoadPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("max_retry=0 should retry without limit, got %d", len(pending))
	}
}
