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
