package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ta_node/internal/config"
	"ta_node/internal/intel"
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
