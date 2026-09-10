package push

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ta_node/internal/event"
	"ta_node/internal/queue"
)

func TestPushEventIncludesRawPacketEvidence(t *testing.T) {
	var received event.ThreatEvent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode pushed event: %v", err)
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ev := event.ThreatEvent{EventID: "e1", EventTime: 1, RawPacket: &event.RawPacketContext{
		MessageDirection: "request", PacketHex: "deadbeef", PayloadHex: "504f5354", PayloadText: "POST",
	}}
	if err := NewClient(srv.URL, "", time.Second).PushEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if received.RawPacket == nil || received.RawPacket.PacketHex != "deadbeef" || received.RawPacket.PayloadText != "POST" {
		t.Fatalf("management payload lost raw packet evidence: %+v", received.RawPacket)
	}
}

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

func TestPushEventIncludesAPIKey(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ev := event.ThreatEvent{EventID: "e1", EventTime: 1}
	if err := NewClient(srv.URL, "test-api-key", time.Second).PushEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if gotKey != "test-api-key" {
		t.Errorf("API key = %q, want test-api-key", gotKey)
	}
}

func TestPushEventServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ev := event.ThreatEvent{EventID: "e1", EventTime: 1}
	err := NewClient(srv.URL, "", time.Second).PushEvent(context.Background(), ev)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestDrainSuccess(t *testing.T) {
	q, err := queue.NewSQLite(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	ev := event.ThreatEvent{EventID: "e1", EventTime: 1}
	q.Enqueue(ev)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "", time.Second)
	drain(context.Background(), q, client, 10)

	pending, err := q.LoadPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending after success drain, got %d", len(pending))
	}
}
