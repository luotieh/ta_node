package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"ta_node/internal/config"
	"ta_node/internal/event"
	"ta_node/internal/intel"
	"ta_node/internal/queue"
)

func TestStorageDetailsAuthRangeAndSummary(t *testing.T) {
	cfg := config.Default()
	cfg.Event.QueueDB = filepath.Join(t.TempDir(), "queue.db")
	cfg.Server.Token = "secret"
	store, err := intel.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	q, err := queue.NewSQLite(cfg.Event.QueueDB)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err = q.Enqueue(event.ThreatEvent{EventID: "test", EventTime: 1, ContextRevision: 2, RawPacket: &event.RawPacketContext{PacketHex: strings.Repeat("abcd", 200)}}); err != nil {
		t.Fatal(err)
	}
	srv := New(store, cfg, "")
	srv.SetStorageStats(q.Stats)
	request := func(url, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, url, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w
	}
	if w := request("/api/v1/push/event?event_id=test&revision=2", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("/api/v1/push/event?event_id=test&revision=2", "secret"); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(strings.Repeat("abcd", 200))) {
		t.Fatalf("detail %d %s", w.Code, w.Body.String())
	}
	w := request("/api/v1/push/event?event_id=test&revision=2&offset=1&length=2", "secret")
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"packet_hex":"cdab"`)) {
		t.Fatalf("range %d %s", w.Code, w.Body.String())
	}
	w = request("/api/v1/push/logs?summary=1", "")
	if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte(strings.Repeat("abcd", 10))) {
		t.Fatal("summary loaded payload")
	}
	if w = request("/api/v1/storage", "secret"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w = request("/api/v1/push/event?event_id=missing", "secret"); w.Code != 404 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestOldConfigFormPreservesStorage(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.ArchiveDir = "/data/archives"
	cfg.Storage.HighWaterBytes = 1000000
	store, _ := intel.NewStore("")
	srv := New(store, cfg, filepath.Join(t.TempDir(), "node.yaml"))
	submitted := cfg
	submitted.Storage = config.StorageConfig{}
	body, _ := json.Marshal(map[string]any{"config": submitted})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/config", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if srv.cfg.Storage != cfg.Storage {
		t.Fatal("old form erased storage settings")
	}
}
