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
	ev := event.ThreatEvent{EventID: "e1", EventTime: 1, Model: "test", RawPacket: &event.RawPacketContext{
		MessageDirection: "request", PacketHex: "deadbeef", PayloadHex: "504f5354", PayloadText: "POST",
	}}
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
	if pending[0].RawPacket == nil || pending[0].RawPacket.PacketHex != "deadbeef" || pending[0].RawPacket.PayloadText != "POST" {
		t.Fatalf("raw packet evidence was not durable in the queue: %+v", pending[0].RawPacket)
	}
	if err := q.MarkFailed("e1", 1, "boom"); err != nil {
		t.Fatal(err)
	}
	pending, err = q.LoadPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("failed event should remain retryable, got %d", len(pending))
	}
	if err := q.MarkPushed("e1", 1); err != nil {
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
		if err := q.MarkFailed("e1", 1, "boom"); err != nil {
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

func TestSQLiteQueueKeepsIndependentContextRevisions(t *testing.T) {
	q, err := NewSQLite(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	first := event.ThreatEvent{EventID: "e1", EventTime: 1, ContextRevision: 1}
	second := event.ThreatEvent{EventID: "e1", EventTime: 1, ContextRevision: 2, ContextFinal: true}
	if err := q.Enqueue(first); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(second); err != nil {
		t.Fatal(err)
	}
	pending, err := q.LoadPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 || pending[0].ContextRevision != 1 || pending[1].ContextRevision != 2 {
		t.Fatalf("context revisions were not queued independently: %+v", pending)
	}
	if err := q.MarkPushed("e1", 2); err != nil {
		t.Fatal(err)
	}
	pending, err = q.LoadPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ContextRevision != 1 {
		t.Fatalf("marking revision 2 changed another revision: %+v", pending)
	}
}

func TestRecentPushLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs.db")
	q, err := NewSQLite(path)
	if err != nil {
		t.Fatal(err)
	}

	ev := event.ThreatEvent{
		EventID: "evt-test-001", EventTime: 1785000000000000, EventName: "test-ioc",
		Severity: "high", IOCType: "ip", IOCValue: "1.2.3.4", Model: "threat_intel",
		SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "1.2.3.4", DstPort: 80,
		RawPacket: &event.RawPacketContext{PacketHex: "abcd"},
	}
	q.Enqueue(ev)
	q.Close()

	logs, err := RecentPushLogs(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) < 1 {
		t.Fatal("expected at least 1 push log entry")
	}
	log := logs[0]
	if log.EventName != "test-ioc" {
		t.Errorf("event_name = %q, want test-ioc", log.EventName)
	}
	if log.Status != "pending" {
		t.Errorf("status = %q, want pending", log.Status)
	}
	if log.IOCValue != "1.2.3.4" {
		t.Errorf("ioc_value = %q, want 1.2.3.4", log.IOCValue)
	}
	if log.SrcIP != "10.0.0.1" {
		t.Errorf("src_ip = %q, want 10.0.0.1", log.SrcIP)
	}
	if log.RawPacket == nil || log.RawPacket.PacketHex != "abcd" {
		t.Error("raw_packet lost in push log")
	}
}

func TestRecentPushLogsEmptyPath(t *testing.T) {
	_, err := RecentPushLogs("/nonexistent/queue.db", 10)
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestPushStatusName(t *testing.T) {
	if name := pushStatusName(0); name != "pending" {
		t.Errorf("status 0 = %q, want pending", name)
	}
	if name := pushStatusName(2); name != "pushed" {
		t.Errorf("status 2 = %q, want pushed", name)
	}
	if name := pushStatusName(3); name != "failed" {
		t.Errorf("status 3 = %q, want failed", name)
	}
	if name := pushStatusName(99); name != "unknown" {
		t.Errorf("status 99 = %q, want unknown", name)
	}
}

func TestSQLiteQueueEnablesWAL(t *testing.T) {
	q, err := NewSQLite(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	var mode string
	if err := q.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	// WAL keeps read-only API readers and the maintenance worker from blocking
	// event enqueue with SQLITE_BUSY under concurrent load.
	if mode != "wal" {
		t.Fatalf("journal_mode = %s, want wal", mode)
	}
}
