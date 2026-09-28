package queue

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"ta_node/internal/event"
)

func seedCRUDQueue(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.db")
	q, err := NewSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	events := []event.ThreatEvent{
		{EventID: "ev-pushed", EventTime: 1_000_000, EventName: "pushed.example.com", Severity: "high", IOCType: "domain", IOCValue: "pushed.example.com", SrcIP: "10.0.0.1", DstIP: "8.8.8.8"},
		{EventID: "ev-failed", EventTime: 2_000_000, EventName: "failed.example.com", Severity: "medium", IOCType: "domain", IOCValue: "failed.example.com", SrcIP: "10.0.0.2", DstIP: "1.1.1.1"},
		{EventID: "ev-pending", EventTime: 3_000_000, EventName: "pending.example.com", Severity: "low", IOCType: "domain", IOCValue: "pending.example.com"},
		{EventID: "ev-pushed", EventTime: 4_000_000, ContextRevision: 2, ContextFinal: true, EventName: "pushed.example.com", Severity: "high", IOCType: "domain", IOCValue: "pushed.example.com"},
	}
	for _, ev := range events {
		if err := q.Enqueue(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.MarkPushed("ev-pushed", 1); err != nil {
		t.Fatal(err)
	}
	if err := q.MarkPushed("ev-pushed", 2); err != nil {
		t.Fatal(err)
	}
	if err := q.MarkFailed("ev-failed", 1, "boom"); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestListPushLogsFiltersAndPagination(t *testing.T) {
	path := seedCRUDQueue(t)

	logs, hasMore, err := ListPushLogs(path, PushLogQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if hasMore {
		t.Fatal("unexpected has_more on full listing")
	}
	if len(logs) != 3 {
		t.Fatalf("want 3 deduped events, got %d: %+v", len(logs), logs)
	}
	byID := map[string]PushLog{}
	for _, l := range logs {
		byID[l.EventID] = l
	}
	if got := byID["ev-pushed"].ContextRevision; got != 2 {
		t.Fatalf("latest revision not kept, got %d", got)
	}
	if got := byID["ev-pushed"].Status; got != "pushed" {
		t.Fatalf("ev-pushed status = %q", got)
	}
	if l := byID["ev-failed"]; l.Status != "failed" || l.RetryCount != 1 || l.LastError != "boom" {
		t.Fatalf("ev-failed log = %+v", l)
	}

	logs, _, err = ListPushLogs(path, PushLogQuery{Limit: 50, Status: "failed"})
	if err != nil || len(logs) != 1 || logs[0].EventID != "ev-failed" {
		t.Fatalf("status filter logs=%+v err=%v", logs, err)
	}
	logs, _, err = ListPushLogs(path, PushLogQuery{Limit: 50, Search: "failed.example.com"})
	if err != nil || len(logs) != 1 || logs[0].EventID != "ev-failed" {
		t.Fatalf("ioc search logs=%+v err=%v", logs, err)
	}
	logs, _, err = ListPushLogs(path, PushLogQuery{Limit: 50, Search: "10.0.0.1"})
	if err != nil || len(logs) != 1 || logs[0].EventID != "ev-pushed" {
		t.Fatalf("ip search logs=%+v err=%v", logs, err)
	}
	logs, _, err = ListPushLogs(path, PushLogQuery{Limit: 50, Search: "ev-pend"})
	if err != nil || len(logs) != 1 || logs[0].EventID != "ev-pending" {
		t.Fatalf("id search logs=%+v err=%v", logs, err)
	}

	page1, more1, err := ListPushLogs(path, PushLogQuery{Limit: 2})
	if err != nil || !more1 || len(page1) != 2 {
		t.Fatalf("page1 len=%d more=%v err=%v", len(page1), more1, err)
	}
	page2, more2, err := ListPushLogs(path, PushLogQuery{Limit: 2, Offset: 2})
	if err != nil || more2 || len(page2) != 1 {
		t.Fatalf("page2 len=%d more=%v err=%v", len(page2), more2, err)
	}
	seen := map[string]bool{page2[0].EventID: true}
	for _, l := range page1 {
		if seen[l.EventID] {
			t.Fatalf("pages overlap on %s", l.EventID)
		}
	}

	if _, _, err = ListPushLogs(path, PushLogQuery{Status: "bogus"}); err == nil {
		t.Fatal("expected error for unknown status")
	}
}

func TestRequeueAndDeleteEvent(t *testing.T) {
	path := seedCRUDQueue(t)

	n, err := RequeueEvent(path, "ev-failed")
	if err != nil || n != 1 {
		t.Fatalf("requeue n=%d err=%v", n, err)
	}
	logs, _, err := ListPushLogs(path, PushLogQuery{Limit: 50, Status: "pending"})
	if err != nil || len(logs) != 2 {
		t.Fatalf("pending after requeue: logs=%+v err=%v", logs, err)
	}
	for _, l := range logs {
		if l.EventID == "ev-failed" && (l.RetryCount != 0 || l.LastError != "") {
			t.Fatalf("requeue did not reset retry state: %+v", l)
		}
	}

	if n, err = RequeueEvent(path, "ev-pushed"); err != nil || n != 2 {
		t.Fatalf("requeue both revisions n=%d err=%v", n, err)
	}
	if _, err = RequeueEvent(path, "ev-missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("requeue missing event err=%v", err)
	}

	if n, err = DeleteEvent(path, "ev-pushed"); err != nil || n != 2 {
		t.Fatalf("delete n=%d err=%v", n, err)
	}
	logs, _, err = ListPushLogs(path, PushLogQuery{Limit: 50})
	if err != nil || len(logs) != 2 {
		t.Fatalf("after delete: logs=%+v err=%v", logs, err)
	}
	if _, err = DeleteEvent(path, "ev-pushed"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("delete missing event err=%v", err)
	}
	logs, _, err = ListPushLogs(path, PushLogQuery{Limit: 50, Search: "pushed.example.com"})
	if err != nil || len(logs) != 0 {
		t.Fatalf("deleted event still searchable: logs=%+v err=%v", logs, err)
	}
}
