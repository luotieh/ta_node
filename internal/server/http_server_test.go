package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ta_node/internal/config"
	"ta_node/internal/event"
	"ta_node/internal/intel"
	"ta_node/internal/queue"
)

func TestConfigPageAndAPI(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "ta_node.yaml")
	intelPath := filepath.Join(dir, "intel.yaml")
	if err := intel.SaveFile(intelPath, nil); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Intel.IntelFile = intelPath
	store, err := intel.NewStore(intelPath)
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, cfg, configPath)

	pageReq := httptest.NewRequest(http.MethodGet, "/config", nil)
	pageRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(pageRec, pageReq)
	if pageRec.Code != http.StatusOK {
		t.Fatalf("config page status = %d", pageRec.Code)
	}
	if !bytes.Contains(pageRec.Body.Bytes(), []byte("ta_node 配置")) {
		t.Fatalf("config page body missing title: %s", pageRec.Body.String())
	}

	cfg.Node.DeviceID = "node-web"
	body, err := json.Marshal(map[string]any{"config": cfg})
	if err != nil {
		t.Fatal(err)
	}
	saveReq := httptest.NewRequest(http.MethodPost, "/api/v1/config", bytes.NewReader(body))
	saveRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(saveRec, saveReq)
	if saveRec.Code != http.StatusOK {
		t.Fatalf("save status = %d body=%s", saveRec.Code, saveRec.Body.String())
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Node.DeviceID != "node-web" {
		t.Fatalf("config was not saved, got device id %q", loaded.Node.DeviceID)
	}
}

func TestIntelAPIsAndAuth(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "ta_node.yaml")
	intelPath := filepath.Join(dir, "intel.yaml")
	if err := intel.SaveFile(intelPath, nil); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Intel.IntelFile = intelPath
	cfg.Server.Token = "secret"
	store, err := intel.NewStore(intelPath)
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, cfg, configPath)

	body := bytes.NewBufferString(`{"source":"Threat Intel Hub","items":[{"id":"hub-ip","type":"ip","value":"1.2.3.4","enabled":true}]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/intel/sync-source", body)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", rec.Code)
	}

	body = bytes.NewBufferString(`{"source":"Threat Intel Hub","items":[{"id":"hub-ip","type":"ip","value":"1.2.3.4","enabled":true}]}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/intel/sync-source", body)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sync-source status = %d body=%s", rec.Code, rec.Body.String())
	}

	body = bytes.NewBufferString(`{"items":[{"id":"local-domain","type":"domain","value":"evil.example.com","source":"local","enabled":true}]}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/intel/batch-upsert", body)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch-upsert status = %d body=%s", rec.Code, rec.Body.String())
	}

	stix := `{"objects":[{"type":"indicator","pattern":"[url:value = 'http://bad.example.com/a']","labels":["phishing"],"confidence":80}]}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/intel/stix?source=Threat%20Intel%20Hub", bytes.NewBufferString(stix))
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("stix status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/intel/stats", nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"total":3`)) {
		t.Fatalf("stats status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"status":"ok"`)) {
		t.Fatalf("health status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPushLogsAPI(t *testing.T) {
	dir := t.TempDir()
	queuePath := filepath.Join(dir, "events.db")
	q, err := queue.NewSQLite(queuePath)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Enqueue(event.ThreatEvent{EventID: "ev-1", EventTime: 123, EventName: "evil.example.com", Severity: "high", IOCType: "domain", IOCValue: "evil.example.com", RawPacket: &event.RawPacketContext{
		MessageDirection: "request", PacketHex: "deadbeef", PayloadHex: "504f5354", PayloadText: "POST",
		Request:  &event.RawMessageContext{PacketHex: "deadbeef", PayloadHex: "504f5354", PayloadText: "POST"},
		Response: &event.RawMessageContext{PacketHex: "cafe", PayloadHex: "48545450", PayloadText: "HTTP/1.1 200 OK"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := q.MarkFailed("ev-1", 1, "network error"); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Event.QueueDB = queuePath
	store, err := intel.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, cfg, filepath.Join(dir, "ta_node.yaml"))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/push/logs", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"status":"failed"`)) || !bytes.Contains(rec.Body.Bytes(), []byte("network error")) || !bytes.Contains(rec.Body.Bytes(), []byte(`"packet_hex":"deadbeef"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"response":{"packet_hex":"cafe"`)) {
		t.Fatalf("push logs status=%d body=%s", rec.Code, rec.Body.String())
	}

	pageReq := httptest.NewRequest(http.MethodGet, "/config", nil)
	pageRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(pageRec, pageReq)
	page := pageRec.Body.Bytes()
	if pageRec.Code != http.StatusOK ||
		!bytes.Contains(page, []byte("packet-toggle")) ||
		!bytes.Contains(page, []byte("展开原始报文")) ||
		!bytes.Contains(page, []byte("请求报文")) ||
		!bytes.Contains(page, []byte("响应报文")) ||
		!bytes.Contains(page, []byte("未捕获到对应报文")) ||
		!bytes.Contains(page, []byte("HEX 内容较长，已隐藏")) ||
		!bytes.Contains(page, []byte(`pending: "待上报"`)) ||
		!bytes.Contains(page, []byte("form {\n      display: block;")) {
		t.Fatalf("config page missing packet expander: status=%d", pageRec.Code)
	}
}

func TestIntelListWithPagination(t *testing.T) {
	dir := t.TempDir()
	intelPath := filepath.Join(dir, "intel.yaml")
	if err := intel.SaveFile(intelPath, nil); err != nil {
		t.Fatal(err)
	}
	store, err := intel.NewStore(intelPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		store.Add(intel.ThreatIntel{ID: "ioc-" + string(rune('a'+i)), Type: "ip", Value: "10.0.0." + string(rune('1'+i)), Category: "c2", Enabled: true})
	}

	cfg := config.Default()
	cfg.Intel.IntelFile = intelPath
	s := New(store, cfg, filepath.Join(dir, "ta_node.yaml"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/intel?offset=0&limit=3", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d", rec.Code)
	}
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	items, ok := resp["items"].([]any)
	if !ok || len(items) != 3 {
		t.Fatalf("expected 3 items, got %v", resp)
	}
	total := int(resp["total"].(float64))
	if total != 5 {
		t.Fatalf("total = %d, want 5", total)
	}
}

func TestEvidenceDownload404(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Evidence.PCAPDir = filepath.Join(dir, "evidence")
	store, _ := intel.NewStore("")
	s := New(store, cfg, "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/nonexistent.pcap", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestEvidenceDownloadPathTraversal(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Evidence.PCAPDir = filepath.Join(dir, "evidence")
	store, _ := intel.NewStore("")
	s := New(store, cfg, "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/..%2F..%2Fetc%2Fpasswd", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400/404 for path traversal, got %d", rec.Code)
	}
}

func TestIntelAddAndDelete(t *testing.T) {
	dir := t.TempDir()
	intelPath := filepath.Join(dir, "intel.yaml")
	if err := intel.SaveFile(intelPath, nil); err != nil {
		t.Fatal(err)
	}
	store, err := intel.NewStore(intelPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Intel.IntelFile = intelPath
	s := New(store, cfg, "")

	body := bytes.NewBufferString(`{"type":"ip","value":"10.0.0.99","category":"c2","severity":"high","enabled":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/intel", body)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("add status=%d body=%s", rec.Code, rec.Body.String())
	}

	var addResp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &addResp)
	id := addResp["id"].(string)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/intel", nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var listResp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &listResp)
	items := listResp["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected 1 item after add, got %d", len(items))
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/intel/"+id, nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rec.Code)
	}
}

func TestIOCSyncNotAvailable(t *testing.T) {
	cfg := config.Default()
	store, _ := intel.NewStore("")
	s := New(store, cfg, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/intel/iocsync", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMethodNotAllowed(t *testing.T) {
	cfg := config.Default()
	store, _ := intel.NewStore("")
	s := New(store, cfg, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestNotFound(t *testing.T) {
	cfg := config.Default()
	store, _ := intel.NewStore("")
	s := New(store, cfg, "")

	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}
