package server

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ta_node/internal/buildinfo"
	"ta_node/internal/config"
	"ta_node/internal/intel"
	"ta_node/internal/iocsync"
	"ta_node/internal/queue"
)

type Server struct {
	store        *intel.Store
	cfg          config.Config
	configPath   string
	mu           sync.RWMutex
	mux          *http.ServeMux
	syncOnceFunc func() (int, error)
	storageStats func() (queue.StorageStats, error)
	detailSlots  chan struct{}
}

func New(store *intel.Store, cfg config.Config, configPath string) *Server {
	s := &Server{store: store, cfg: cfg, configPath: configPath, mux: http.NewServeMux(), detailSlots: make(chan struct{}, 2)}
	s.routes()
	return s
}

func (s *Server) SetStorageStats(fn func() (queue.StorageStats, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storageStats = fn
}

func (s *Server) SetIOCSyncer(syncer *iocsync.Syncer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncOnceFunc = syncer.SyncOnce
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.Handler())
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleConfigPage)
	s.mux.HandleFunc("/config", s.handleConfigPage)
	s.mux.HandleFunc("/api/v1/config", s.handleConfig)
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/push/logs", s.handlePushLogs)
	s.mux.HandleFunc("/api/v1/push/event", s.handleEventDetail)
	s.mux.HandleFunc("/api/v1/storage", s.handleStorageStats)
	s.mux.HandleFunc("/api/v1/intel", s.handleIntel)
	s.mux.HandleFunc("/api/v1/intel/", s.handleIntelID)
	s.mux.HandleFunc("/api/v1/evidence/", s.handleEvidenceDownload)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		cfg := s.cfg
		s.mu.RUnlock()
		cfg.Node.APIKey = ""
		cfg.Server.Token = ""
		writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "path": s.configPath})
	case http.MethodPost:
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "error": "unauthorized"})
			return
		}
		var req struct {
			Config config.Config `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		s.mu.RLock()
		current := s.cfg
		s.mu.RUnlock()
		if req.Config.Storage == (config.StorageConfig{}) {
			req.Config.Storage = current.Storage
		}
		if current.Node.APIKey != "" && req.Config.Node.APIKey == "" {
			req.Config.Node.APIKey = current.Node.APIKey
		}
		if current.Server.Token != "" && req.Config.Server.Token == "" {
			req.Config.Server.Token = current.Server.Token
		}
		if err := config.Save(s.configPath, req.Config); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": err.Error()})
			return
		}
		s.mu.Lock()
		s.cfg = req.Config
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "path": s.configPath, "restart_required": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleConfigPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/config" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.mu.RLock()
	version := buildinfo.Short()
	if t := buildinfo.Get().Time; t != "" {
		version += " · " + t
	}
	data := struct {
		Config         config.Config
		ConfigPath     string
		Version        string
		HasNodeAPIKey  bool
		HasServerToken bool
	}{Config: s.cfg, ConfigPath: s.configPath, Version: version, HasNodeAPIKey: s.cfg.Node.APIKey != "", HasServerToken: s.cfg.Server.Token != ""}
	data.Config.Node.APIKey = ""
	data.Config.Server.Token = ""
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = configPage.Execute(w, data)
}

func (s *Server) handleIntel(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 50
		}
		items, total := s.store.ListPaged(offset, limit)
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "offset": offset, "limit": limit})
	case http.MethodPost:
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "error": "unauthorized"})
			return
		}
		var it intel.ThreatIntel
		if err := json.NewDecoder(r.Body).Decode(&it); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		saved, err := s.store.Add(it)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "id": saved.ID})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleIntelID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/intel/")
	switch {
	case r.Method == http.MethodDelete:
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "error": "unauthorized"})
			return
		}
		if err := s.store.Delete(path); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	case r.Method == http.MethodPost && path == "reload":
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "error": "unauthorized"})
			return
		}
		if err := s.store.Reload(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	case r.Method == http.MethodPost && path == "sync":
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "error": "unauthorized"})
			return
		}
		var f intel.File
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		if err := s.store.Sync(f.Items); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	case r.Method == http.MethodPost && path == "sync-source":
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "error": "unauthorized"})
			return
		}
		var req struct {
			Source string              `json:"source"`
			Items  []intel.ThreatIntel `json:"items"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		if req.Source == "" {
			req.Source = r.URL.Query().Get("source")
		}
		if err := s.checkItemLimit(len(req.Items)); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		if err := s.store.SyncSource(req.Source, req.Items); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "count": len(req.Items)})
	case r.Method == http.MethodPost && path == "batch-upsert":
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "error": "unauthorized"})
			return
		}
		var f intel.File
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		if err := s.checkItemLimit(len(f.Items)); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		if err := s.store.UpsertMany(f.Items); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "count": len(f.Items)})
	case r.Method == http.MethodPost && path == "stix":
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "error": "unauthorized"})
			return
		}
		if !s.acceptSTIX() {
			writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "error": "stix disabled"})
			return
		}
		source := r.URL.Query().Get("source")
		if source == "" {
			source = s.defaultSource()
		}
		result, err := intel.ParseSTIXIndicators(r.Body, source)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		if err := s.checkItemLimit(len(result.Items)); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		if err := s.store.UpsertMany(result.Items); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "count": len(result.Items), "skipped": result.Skipped, "errors": result.Errors})
	case r.Method == http.MethodPost && path == "iocsync":
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "error": "unauthorized"})
			return
		}
		s.mu.RLock()
		fn := s.syncOnceFunc
		s.mu.RUnlock()
		if fn == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "error": "ioc sync not available"})
			return
		}
		count, err := fn()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "added": count})
	case r.Method == http.MethodGet && path == "stats":
		writeJSON(w, http.StatusOK, s.store.Stats())
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	deviceID := s.cfg.Node.DeviceID
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"version":     buildinfo.Short(),
		"built_at":    buildinfo.Get().Time,
		"device_id":   deviceID,
		"intel_count": s.store.Stats().Total,
		"server_time": time.Now().Unix(),
	})
}

func (s *Server) handlePushLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	path := s.cfg.Event.QueueDB
	s.mu.RUnlock()
	read := queue.RecentPushLogs
	if r.URL.Query().Get("summary") == "1" {
		read = queue.RecentPushSummaries
	}
	logs, err := read(path, 50)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []queue.PushLog{}, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": logs})
}

func (s *Server) handleStorageStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	s.mu.RLock()
	fn := s.storageStats
	s.mu.RUnlock()
	if fn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "storage metrics unavailable"})
		return
	}
	stats, err := fn()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, stats)
}
func (s *Server) handleEventDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	select {
	case s.detailSlots <- struct{}{}:
		defer func() { <-s.detailSlots }()
	default:
		writeJSON(w, 429, map[string]any{"error": "too many evidence reads"})
		return
	}
	key := r.URL.Query().Get("event_id")
	if key == "" || len(key) > 512 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	revision, err := strconv.ParseUint(r.URL.Query().Get("revision"), 10, 64)
	if err != nil && r.URL.Query().Get("revision") != "" {
		w.WriteHeader(400)
		return
	}
	if revision > 1 {
		key += "@revision:" + strconv.FormatUint(revision, 10)
	}
	s.mu.RLock()
	path := s.cfg.Event.QueueDB
	s.mu.RUnlock()
	if r.URL.Query().Get("offset") != "" {
		offset, e := strconv.Atoi(r.URL.Query().Get("offset"))
		length, e2 := strconv.Atoi(r.URL.Query().Get("length"))
		if e != nil || e2 != nil || offset < 0 || length < 1 || length > 65536 {
			w.WriteHeader(400)
			return
		}
		part, e := queue.ReadPacketRange(path, key, offset, length)
		if e != nil {
			code := 500
			if e == sql.ErrNoRows {
				code = 404
			}
			if strings.Contains(e.Error(), "offset exceeds") || strings.Contains(e.Error(), "invalid range") {
				code = 416
			}
			writeJSON(w, code, map[string]any{"error": e.Error()})
			return
		}
		writeJSON(w, 200, part)
		return
	}
	ev, err := queue.ReadEvent(path, key)
	if err != nil {
		code := 500
		if err == sql.ErrNoRows {
			code = 404
		}
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, ev)
}

func (s *Server) authorized(r *http.Request) bool {
	s.mu.RLock()
	token := s.cfg.Server.Token
	s.mu.RUnlock()
	if token == "" {
		return true
	}
	expected := "Bearer " + token
	got := r.Header.Get("Authorization")
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func (s *Server) checkItemLimit(incoming int) error {
	s.mu.RLock()
	maxItems := s.cfg.Intel.MaxItems
	s.mu.RUnlock()
	if maxItems <= 0 {
		return nil
	}
	total := s.store.Stats().Total
	if total+incoming > maxItems {
		return fmt.Errorf("intel item limit exceeded: max_items=%d current=%d incoming=%d", maxItems, total, incoming)
	}
	return nil
}

func (s *Server) handleEvidenceDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	baseDir := s.cfg.Evidence.PCAPDir
	s.mu.RUnlock()
	if baseDir == "" {
		baseDir = "./data/evidence"
	}
	baseDir = filepath.Clean(baseDir)
	rel := strings.TrimPrefix(r.URL.Path, "/api/v1/evidence/")
	if rel == "" || strings.Contains(rel, "..") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	abs := filepath.Join(baseDir, rel)
	if _, err := os.Stat(abs); os.IsNotExist(err) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(rel)))
	http.ServeFile(w, r, abs)
}

func (s *Server) acceptSTIX() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Intel.AcceptSTIX
}

func (s *Server) defaultSource() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Intel.DefaultSource
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

var configPage = template.Must(template.New("config").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ta_node 配置</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --line: #d9dee7;
      --text: #151922;
      --muted: #657083;
      --accent: #1f7a5a;
      --accent-dark: #155f45;
      --danger: #a33a32;
      --shadow: 0 1px 2px rgba(20, 24, 32, .08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      background: #ffffff;
      border-bottom: 1px solid var(--line);
      padding: 16px 24px;
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .topbar {
      max-width: 1180px;
      margin: 0 auto;
      display: flex;
      gap: 16px;
      align-items: center;
      justify-content: space-between;
    }
    h1 { font-size: 20px; margin: 0; font-weight: 650; }
    .path { color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }
    main {
      max-width: 1180px;
      margin: 0 auto;
      padding: 20px 24px 36px;
    }
    form {
      display: block;
      width: 100%;
      min-width: 0;
    }
    fieldset {
      border: 1px solid var(--line);
      background: var(--panel);
      box-shadow: var(--shadow);
      border-radius: 8px;
      padding: 16px;
      margin: 0;
      min-width: 0;
    }
    legend {
      padding: 0 6px;
      font-weight: 650;
      color: #202632;
    }
    .row {
      display: grid;
      grid-template-columns: 155px minmax(0, 1fr);
      gap: 12px;
      align-items: center;
      margin: 10px 0;
    }
    label { color: var(--muted); }
    input {
      width: 100%;
      min-height: 34px;
      border: 1px solid #cfd6e2;
      border-radius: 6px;
      padding: 7px 9px;
      color: var(--text);
      background: #fff;
      font: inherit;
    }
    input[type="checkbox"] {
      width: 18px;
      height: 18px;
      min-height: 18px;
      accent-color: var(--accent);
    }
    .full { grid-column: 1 / -1; }
    .actions {
      grid-column: 1 / -1;
      display: flex;
      gap: 10px;
      align-items: center;
      justify-content: flex-end;
      padding-top: 4px;
    }
    button {
      border: 1px solid transparent;
      border-radius: 7px;
      padding: 9px 14px;
      cursor: pointer;
      font: inherit;
      font-weight: 620;
    }
    .primary { background: var(--accent); color: white; }
    .primary:hover { background: var(--accent-dark); }
    .secondary { background: #fff; border-color: #cfd6e2; color: #222936; }
    .status {
      min-height: 20px;
      color: var(--muted);
      margin-right: auto;
    }
    .status.error { color: var(--danger); }
    .status.ok { color: var(--accent-dark); }
    .auth-token { width: 220px; flex: 0 0 auto; }
    .table-wrap {
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 7px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 720px;
      background: #fff;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 8px 10px;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th {
      background: #f1f4f7;
      color: #394252;
      font-weight: 650;
    }
    tr:last-child td { border-bottom: 0; }
    .toolbar {
      display: flex;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .muted { color: var(--muted); }
    .badge {
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 12px;
      font-weight: 650;
      background: #eef2f6;
      color: #394252;
    }
    .badge.pushed { background: #e4f4ec; color: #155f45; }
    .badge.failed { background: #f9e8e6; color: var(--danger); }
    .badge.pending { background: #eef2f6; color: #394252; }
    .packet-toggle {
      width: 28px;
      height: 28px;
      padding: 0;
      border: 0;
      background: transparent;
      color: #394252;
      font-size: 15px;
      line-height: 28px;
    }
    .packet-toggle:hover { background: #eef2f6; }
    .packet-toggle:disabled { cursor: default; color: #aab2bf; background: transparent; }
    .packet-detail-row > td { padding: 0; background: #f8fafc; }
    .packet-detail {
      padding: 14px 16px 16px 46px;
      border-bottom: 1px solid var(--line);
    }
    .packet-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 22px;
      margin-bottom: 12px;
      color: #4b5565;
      font-size: 13px;
    }
    .packet-block { margin-top: 12px; }
    .packet-block-title { margin-bottom: 5px; font-weight: 650; color: #202632; }
    .packet-tabs {
      display: flex;
      gap: 4px;
      margin-top: 14px;
      border-bottom: 1px solid #cfd8e5;
    }
    .packet-tab {
      flex: 0 0 auto;
      margin-bottom: -1px;
      padding: 8px 13px;
      border: 1px solid transparent;
      border-bottom-color: #cfd8e5;
      border-radius: 5px 5px 0 0;
      background: transparent;
      color: #586273;
      font-weight: 600;
    }
    .packet-tab:hover { background: #eef4fb; }
    .packet-tab.active {
      border-color: #8da6c4 #8da6c4 #f8fafc;
      background: #f8fafc;
      color: #0b67c2;
    }
    .packet-panel { padding-top: 2px; }
    .packet-panel[hidden] { display: none; }
    .packet-empty {
      margin-top: 12px;
      padding: 18px 12px;
      border: 1px dashed #cfd8e5;
      border-radius: 6px;
      text-align: center;
      color: var(--muted);
      background: #fff;
    }
    .packet-data {
      max-height: 260px;
      overflow: auto;
      margin: 0;
      padding: 10px 12px;
      border: 1px solid #d9e0e9;
      border-radius: 6px;
      background: #fff;
      color: #202632;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-all;
      font: 12px/1.55 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
    }
    .hex-details {
      overflow: hidden;
      border: 1px solid #d9e0e9;
      border-radius: 6px;
      background: #fff;
    }
    .hex-details > summary {
      cursor: pointer;
      padding: 10px 12px;
      color: #506176;
      font-size: 12px;
      font-weight: 650;
      user-select: none;
    }
    .hex-details[open] > summary { border-bottom: 1px solid #d9e0e9; }
    .hex-details .packet-data {
      max-height: 360px;
      border: 0;
      border-radius: 0;
    }
    .app-shell {
      display: grid;
      grid-template-columns: 232px minmax(0, 1fr);
      width: 100%;
      min-width: 0;
      min-height: calc(100vh - 65px);
    }
    .sidebar {
      position: sticky; top: 65px; align-self: start; height: calc(100vh - 65px);
      padding: 20px 14px; background: #13243a; color: #dce8f7; overflow-y: auto;
    }
    .nav-label { margin: 0 10px 8px; color: #7890ae; font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
    .nav-button {
      width: 100%; display: flex; align-items: center; gap: 10px; margin: 3px 0; padding: 10px 12px;
      border: 0; border-radius: 8px; background: transparent; color: #c8d6e8; text-align: left; font-weight: 560;
    }
    .nav-button:hover { background: #1d3551; color: #fff; }
    .nav-button.active { background: #245f91; color: #fff; box-shadow: inset 3px 0 #55c5f3; }
    .nav-icon { width: 20px; text-align: center; font-size: 16px; }
    .workspace { width: 100%; max-width: none; margin: 0; padding: 24px 30px 42px; min-width: 0; }
    .workspace-title { margin-bottom: 18px; }
    .workspace-title h2 { margin: 0 0 4px; font-size: 22px; }
    .workspace-title p { margin: 0; color: var(--muted); }
    .view { display: none; width: 100%; min-width: 0; }
    .view.active { display: block; }
    .config-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
    .metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 18px; }
    .metric-card { padding: 16px; border: 1px solid var(--line); border-radius: 10px; background: #fff; box-shadow: var(--shadow); }
    .metric-card .metric-label { color: var(--muted); font-size: 12px; }
    .metric-card .metric-value { margin-top: 7px; font-size: 21px; font-weight: 700; color: #1a2738; overflow-wrap: anywhere; }
    .metric-card .metric-note { margin-top: 5px; color: var(--muted); font-size: 12px; }
    .section-card { padding: 18px; border: 1px solid var(--line); border-radius: 10px; background: #fff; box-shadow: var(--shadow); }
    .section-card h3 { margin: 0 0 5px; font-size: 16px; }
    .quick-actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }
    .top-status { display: flex; gap: 8px; align-items: center; color: #27543f; font-size: 13px; font-weight: 650; }
    .status-dot { width: 9px; height: 9px; border-radius: 50%; background: #27a56a; box-shadow: 0 0 0 4px #dff4e9; }
    .context-state { display: inline-block; margin-left: 5px; border-radius: 999px; padding: 2px 7px; font-size: 11px; background: #e9f1f8; color: #315b7b; }
    .context-state.complete { background: #e1f4ea; color: #176244; }
    .context-state.pending { background: #fff2d9; color: #855b0b; }
    .session-strip { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin: 10px 0 4px; }
    .session-stat { padding: 9px 10px; border-radius: 7px; background: #edf3f8; color: #405166; font-size: 12px; }
    .session-stat strong { display: block; margin-top: 2px; color: #17263a; font-size: 14px; }
    .packet-fragments { margin-top: 12px; border: 1px solid #d9e0e9; border-radius: 7px; background: #fff; }
    .packet-fragments > summary { cursor: pointer; padding: 10px 12px; font-weight: 650; color: #33445a; }
    .fragment-item { border-top: 1px solid #e4e9ef; }
    .fragment-item > summary { cursor: pointer; padding: 8px 12px; color: #506176; font-size: 12px; }
    .fragment-item .packet-data { margin: 0 10px 10px; max-height: 160px; }
    .actions { position: sticky; bottom: 0; z-index: 3; margin-top: 18px; padding: 12px 14px; border: 1px solid var(--line); border-radius: 9px; background: rgba(255,255,255,.96); box-shadow: 0 -3px 14px rgba(30,45,62,.08); }
    @media (max-width: 860px) {
      .app-shell { grid-template-columns: 1fr; }
      .sidebar { position: static; height: auto; display: flex; gap: 5px; padding: 8px; overflow-x: auto; }
      .nav-label { display: none; }
      .nav-button { flex: 0 0 auto; width: auto; white-space: nowrap; }
      .config-grid { grid-template-columns: 1fr; }
      .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .topbar { align-items: flex-start; flex-direction: column; gap: 4px; }
    }
    @media (max-width: 560px) {
      header, .workspace { padding-left: 14px; padding-right: 14px; }
      .config-grid, .metric-grid, .session-strip { grid-template-columns: 1fr; }
      .row { grid-template-columns: 1fr; gap: 5px; }
      .actions { flex-wrap: wrap; justify-content: stretch; }
      .status { width: 100%; }
      .auth-token { width: 100%; flex: 1 1 100%; }
      .actions button { flex: 1; }
    }
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div>
        <h1>融合采集节点</h1>
        <div class="path">{{.Config.Node.DeviceID}} · ta_node {{.Version}}</div>
      </div>
      <div class="top-status"><span class="status-dot"></span>节点服务运行中</div>
    </div>
  </header>
  <div class="app-shell">
    <aside class="sidebar" aria-label="功能导航">
      <div style="width:100%">
        <div class="nav-label">运行与分析</div>
        <button type="button" class="nav-button active" data-view="overview"><span class="nav-icon">◫</span>运行概览</button>
        <button type="button" class="nav-button" data-view="alerts"><span class="nav-icon">⚠</span>告警中心</button>
        <div class="nav-label" style="margin-top:18px">采集与检测</div>
        <button type="button" class="nav-button" data-view="capture"><span class="nav-icon">⌁</span>采集与会话</button>
        <button type="button" class="nav-button" data-view="detection"><span class="nav-icon">◎</span>检测策略</button>
        <div class="nav-label" style="margin-top:18px">节点管理</div>
        <button type="button" class="nav-button" data-view="delivery"><span class="nav-icon">↗</span>事件与上报</button>
        <button type="button" class="nav-button" data-view="system"><span class="nav-icon">⚙</span>节点与系统</button>
      </div>
    </aside>
  <main class="workspace">
    <div class="workspace-title">
      <h2 id="viewTitle">运行概览</h2>
      <p id="viewDescription">查看节点采集、检测、告警和上报链路的整体状态。</p>
    </div>
    <form id="configForm">
      <section class="view active" data-view-panel="overview">
        <div class="metric-grid">
          <div class="metric-card"><div class="metric-label">节点标识</div><div class="metric-value">{{.Config.Node.DeviceID}}</div><div class="metric-note">服务在线</div></div>
          <div class="metric-card"><div class="metric-label">当前采集源</div><div class="metric-value">{{if .Config.Capture.PCAPFile}}PCAP{{else}}{{.Config.Capture.Interface}}{{end}}</div><div class="metric-note">{{if .Config.Capture.PCAPFile}}{{.Config.Capture.PCAPFile}}{{else}}实时网口采集{{end}}</div></div>
          <div class="metric-card"><div class="metric-label">会话聚合</div><div class="metric-value">{{if .Config.Aggregation.EnableTransactionLink}}已启用{{else}}逐包模式{{end}}</div><div class="metric-note">{{.Config.Aggregation.Mode}} · Schema 1.5</div></div>
          <div class="metric-card"><div class="metric-label">情报规则</div><div class="metric-value" id="overviewIntelCount">读取中</div><div class="metric-note">IOC 当前加载量</div></div>
        </div>
        <div class="section-card">
          <h3>检测链路状态</h3>
          <p class="muted">采集 → 协议解析 → 指纹/IOC检测 → 双向会话关联 → 事件队列 → 管理端上报</p>
          <div class="session-strip">
            <div class="session-stat">最近告警<strong id="overviewAlertCount">读取中</strong></div>
            <div class="session-stat">待处理事件<strong id="overviewPendingCount">读取中</strong></div>
            <div class="session-stat">响应等待窗口<strong>{{.Config.Aggregation.ResponseWaitSec}} 秒</strong></div>
            <div class="session-stat">配置文件<strong style="font-size:12px">{{.ConfigPath}}</strong></div>
          </div>
          <div class="quick-actions">
            <button class="primary view-shortcut" type="button" data-view="alerts">查看告警</button>
            <button class="secondary view-shortcut" type="button" data-view="capture">配置采集</button>
            <button class="secondary view-shortcut" type="button" data-view="detection">管理检测策略</button>
          </div>
        </div>
      </section>

      <section class="view" data-view-panel="alerts">
      <fieldset class="full">
        <legend>告警事件与会话证据</legend>
        <div class="toolbar">
          <div id="pushLogStatus" class="muted">最近 50 条告警及上下文状态</div>
          <button class="secondary" type="button" id="refreshPushLogsBtn">刷新告警</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th aria-label="展开报文"></th>
                <th>发生时间</th>
                <th>状态</th>
                <th>命中规则</th>
                <th>命中流量</th>
                <th>级别</th>
                <th>重试</th>
                <th>最近推送</th>
                <th>错误</th>
              </tr>
            </thead>
            <tbody id="pushLogRows">
              <tr><td colspan="9" class="muted">暂无数据</td></tr>
            </tbody>
          </table>
        </div>
      </fieldset>
      </section>

      <section class="view" data-view-panel="capture">
        <div class="config-grid">
          <fieldset>
            <legend>流量采集</legend>
            <div class="row"><label for="capture.interface">网卡</label><input id="capture.interface" value="{{.Config.Capture.Interface}}"></div>
            <div class="row"><label for="capture.pcap_file">PCAP 文件</label><input id="capture.pcap_file" value="{{.Config.Capture.PCAPFile}}"></div>
            <div class="row"><label for="capture.bpf_filter">BPF 过滤</label><input id="capture.bpf_filter" value="{{.Config.Capture.BPFFilter}}"></div>
            <div class="row"><label for="capture.snaplen">Snaplen</label><input id="capture.snaplen" type="number" min="64" value="{{.Config.Capture.Snaplen}}"></div>
            <div class="row"><label for="capture.promiscuous">混杂模式</label><input id="capture.promiscuous" type="checkbox" {{if .Config.Capture.Promiscuous}}checked{{end}}></div>
          </fieldset>
          <fieldset>
            <legend>双向会话聚合</legend>
            <div class="row"><label for="aggregation.mode">聚合模式</label><input id="aggregation.mode" value="{{.Config.Aggregation.Mode}}" placeholder="packet 或 session"></div>
            <div class="row"><label for="aggregation.enable_transaction_link">关联请求响应</label><input id="aggregation.enable_transaction_link" type="checkbox" {{if .Config.Aggregation.EnableTransactionLink}}checked{{end}}></div>
            <div class="row"><label for="aggregation.response_wait_sec">响应等待(秒)</label><input id="aggregation.response_wait_sec" type="number" min="1" value="{{.Config.Aggregation.ResponseWaitSec}}"></div>
            <div class="row"><label for="aggregation.max_sessions">最大会话数</label><input id="aggregation.max_sessions" type="number" min="1" value="{{.Config.Aggregation.MaxSessions}}"></div>
            <div class="row"><label for="aggregation.max_transactions_per_session">每会话事务数</label><input id="aggregation.max_transactions_per_session" type="number" min="1" value="{{.Config.Aggregation.MaxTransactionsPerSession}}"></div>
            <div class="row"><label for="aggregation.max_packets_per_transaction">每事务包数</label><input id="aggregation.max_packets_per_transaction" type="number" min="1" value="{{.Config.Aggregation.MaxPacketsPerTransaction}}"></div>
            <div class="row"><label for="aggregation.max_reassembly_bytes_per_side">单向重组字节</label><input id="aggregation.max_reassembly_bytes_per_side" type="number" min="1024" value="{{.Config.Aggregation.MaxReassemblyBytesPerSide}}"></div>
            <div class="row"><label for="aggregation.max_out_of_order_bytes">乱序窗口字节</label><input id="aggregation.max_out_of_order_bytes" type="number" min="0" value="{{.Config.Aggregation.MaxOutOfOrderBytes}}"></div>
            <div class="row"><label for="aggregation.store_packet_index">保存分片索引</label><input id="aggregation.store_packet_index" type="checkbox" {{if .Config.Aggregation.StorePacketIndex}}checked{{end}}></div>
          </fieldset>
          <fieldset>
            <legend>流表资源</legend>
            <div class="row"><label for="flow.max_flows">最大流数</label><input id="flow.max_flows" type="number" min="1" value="{{.Config.Flow.MaxFlows}}"></div>
            <div class="row"><label for="flow.idle_timeout_sec">空闲超时(秒)</label><input id="flow.idle_timeout_sec" type="number" min="1" value="{{.Config.Flow.IdleTimeoutSec}}"></div>
            <div class="row"><label for="flow.cleanup_interval_sec">清理间隔(秒)</label><input id="flow.cleanup_interval_sec" type="number" min="1" value="{{.Config.Flow.CleanupIntervalSec}}"></div>
          </fieldset>
          <fieldset>
            <legend>证据留存</legend>
            <div class="row"><label for="evidence.enable_pcap_save">保存命中 PCAP</label><input id="evidence.enable_pcap_save" type="checkbox" {{if .Config.Evidence.EnablePCAPSave}}checked{{end}}></div>
            <div class="row"><label for="evidence.pcap_dir">证据目录</label><input id="evidence.pcap_dir" value="{{.Config.Evidence.PCAPDir}}"></div>
            <div class="row"><label for="aggregation.save_full_session_pcap">完整会话 PCAP</label><input id="aggregation.save_full_session_pcap" type="checkbox" {{if .Config.Aggregation.SaveFullSessionPCAP}}checked{{end}}></div>
          </fieldset>
        </div>
      </section>

      <section class="view" data-view-panel="detection">
        <div class="config-grid" style="margin-bottom:16px">
          <fieldset>
            <legend>指纹检测</legend>
            <div class="row"><label for="patterns.enable">启用指纹规则</label><input id="patterns.enable" type="checkbox" {{if .Config.Patterns.Enable}}checked{{end}}></div>
            <div class="row"><label for="patterns.pattern_dir">规则目录</label><input id="patterns.pattern_dir" value="{{.Config.Patterns.PatternDir}}"></div>
          </fieldset>
          <fieldset>
            <legend>威胁情报同步</legend>
            <div class="row"><label for="intel.intel_file">情报文件</label><input id="intel.intel_file" value="{{.Config.Intel.IntelFile}}"></div>
            <div class="row"><label for="intel.enable_hot_reload">启用热加载</label><input id="intel.enable_hot_reload" type="checkbox" {{if .Config.Intel.EnableHotReload}}checked{{end}}></div>
            <div class="row"><label for="intel.reload_interval_sec">热加载间隔</label><input id="intel.reload_interval_sec" type="number" min="1" value="{{.Config.Intel.ReloadIntervalSec}}"></div>
            <div class="row"><label for="intel.prune_expired_interval_sec">过期清理间隔</label><input id="intel.prune_expired_interval_sec" type="number" min="0" value="{{.Config.Intel.PruneExpiredIntervalSec}}"></div>
            <div class="row"><label for="intel.accept_stix">接收 STIX</label><input id="intel.accept_stix" type="checkbox" {{if .Config.Intel.AcceptSTIX}}checked{{end}}></div>
            <div class="row"><label for="intel.default_source">默认来源</label><input id="intel.default_source" value="{{.Config.Intel.DefaultSource}}"></div>
            <div class="row"><label for="intel.max_items">最大 IOC 数</label><input id="intel.max_items" type="number" min="0" value="{{.Config.Intel.MaxItems}}"></div>
            <div class="row"><label for="intel.enable_ioc_sync">启用目录同步</label><input id="intel.enable_ioc_sync" type="checkbox" {{if .Config.Intel.EnableIocSync}}checked{{end}}></div>
            <div class="row"><label for="intel.ioc_sync_dir">同步目录1</label><input id="intel.ioc_sync_dir" value="{{.Config.Intel.IocSyncDir}}"></div>
            <div class="row"><label for="intel.ioc_sync_dir2">同步目录2</label><input id="intel.ioc_sync_dir2" value="{{.Config.Intel.IocSyncDir2}}"></div>
            <div class="row"><label for="intel.ioc_sync_interval_min">同步间隔(分)</label><input id="intel.ioc_sync_interval_min" type="number" min="1" value="{{.Config.Intel.IocSyncIntervalMin}}"></div>
            <div class="row"><label for="intel.ioc_sync_retain_days">保留天数</label><input id="intel.ioc_sync_retain_days" type="number" min="0" value="{{.Config.Intel.IocSyncRetainDays}}"></div>
            <div class="row"><label>手动同步</label><span><button class="secondary" type="button" id="triggerIocSyncBtn">立即同步</button> <span id="iocSyncStatus" class="muted"></span></span></div>
          </fieldset>
        </div>
      <fieldset class="full">
        <legend>威胁情报规则</legend>
        <div class="toolbar">
          <div id="intelTableStatus" class="muted">当前已加载 0 条 IOC 规则</div>
          <button class="secondary" type="button" id="refreshIntelBtn">刷新规则</button>
        </div>
        <div class="toolbar" style="justify-content:center;gap:12px;">
          <button class="secondary" type="button" id="intelPrevBtn" disabled>上一页</button>
          <span id="intelPageInfo" class="muted">第 1 页</span>
          <button class="secondary" type="button" id="intelNextBtn">下一页</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>类型</th>
                <th>值</th>
                <th>分类</th>
                <th>级别</th>
                <th>来源</th>
                <th>启用</th>
                <th>描述</th>
              </tr>
            </thead>
            <tbody id="intelRows">
              <tr><td colspan="8" class="muted">暂无数据</td></tr>
            </tbody>
          </table>
        </div>
      </fieldset>
      </section>

      <section class="view" data-view-panel="delivery">
        <div class="config-grid">
          <fieldset>
            <legend>事件队列</legend>
            <div class="row"><label for="storage.backend">存储格式</label><select id="storage.backend"><option value="v2" {{if ne .Config.Storage.Backend "legacy"}}selected{{end}}>无损去重</option><option value="legacy" {{if eq .Config.Storage.Backend "legacy"}}selected{{end}}>旧版兼容</option></select></div>
            <div class="row"><label for="storage.archive_dir">历史归档目录</label><input id="storage.archive_dir" value="{{.Config.Storage.ArchiveDir}}" placeholder="留空不启用归档"></div>
            <div class="row"><label for="storage.archive_after_hours">成功事件本机保留（小时）</label><input id="storage.archive_after_hours" type="number" min="0" value="{{.Config.Storage.ArchiveAfterHours}}"></div>
            <div class="row"><label for="storage.maintenance_interval_sec">归档检查间隔（秒）</label><input id="storage.maintenance_interval_sec" type="number" min="1" value="{{.Config.Storage.MaintenanceIntervalSec}}"></div>
            <div class="row"><label for="storage.archive_batch_size">每次归档条数</label><input id="storage.archive_batch_size" type="number" min="1" max="1000" value="{{.Config.Storage.ArchiveBatchSize}}"></div>
            <div class="row"><label for="storage.high_water_bytes">活动数据高水位（字节）</label><input id="storage.high_water_bytes" type="number" min="0" value="{{.Config.Storage.HighWaterBytes}}"></div>
            <div class="row"><label for="storage.low_water_bytes">活动数据低水位（字节）</label><input id="storage.low_water_bytes" type="number" min="0" value="{{.Config.Storage.LowWaterBytes}}"></div>
            <div class="row"><label for="storage.min_free_bytes">剩余空间警戒值（字节）</label><input id="storage.min_free_bytes" type="number" min="0" value="{{.Config.Storage.MinFreeBytes}}"></div>
            <p class="muted">归档保留完整历史。请选择有充足容量的磁盘；归档不等于删除证据，待发和失败事件不会被清除。</p>

            <div class="row"><label for="event.queue_db">SQLite DB</label><input id="event.queue_db" value="{{.Config.Event.QueueDB}}"></div>
            <div class="row"><label for="event.local_hit_window_sec">本地命中窗口</label><input id="event.local_hit_window_sec" type="number" min="0" value="{{.Config.Event.LocalHitWindowSec}}"></div>
          </fieldset>
          <fieldset>
            <legend>管理端上报</legend>
            <div class="row"><label for="event.enable_push">启用推送</label><input id="event.enable_push" type="checkbox" {{if .Config.Event.EnablePush}}checked{{end}}></div>
            <div class="row"><label for="node.management_url">管理端 URL</label><input id="node.management_url" value="{{.Config.Node.ManagementURL}}"></div>
            <div class="row"><label for="node.api_key">内部 API Key</label><input id="node.api_key" type="password" placeholder="{{if .HasNodeAPIKey}}留空保持不变{{else}}X-API-Key，留空则不发送{{end}}"></div>
            <div class="row"><label for="event.push_batch_size">推送批量</label><input id="event.push_batch_size" type="number" min="1" value="{{.Config.Event.PushBatchSize}}"></div>
            <div class="row"><label for="event.retry_interval_sec">重试间隔</label><input id="event.retry_interval_sec" type="number" min="1" value="{{.Config.Event.RetryIntervalSec}}"></div>
            <div class="row"><label for="event.push_timeout_sec">推送超时</label><input id="event.push_timeout_sec" type="number" min="1" value="{{.Config.Event.PushTimeoutSec}}"></div>
            <div class="row"><label for="event.max_push_retry">最大推送重试</label><input id="event.max_push_retry" type="number" min="0" value="{{.Config.Event.MaxPushRetry}}"></div>
          </fieldset>
        </div>
      </section>

      <section class="view" data-view-panel="system">
        <div class="config-grid">
          <fieldset>
            <legend>节点身份</legend>
            <div class="row"><label for="node.device_id">设备 ID</label><input id="node.device_id" value="{{.Config.Node.DeviceID}}"></div>
          </fieldset>
          <fieldset>
            <legend>本地管理服务</legend>
            <div class="row"><label for="server.enable">启用 API</label><input id="server.enable" type="checkbox" {{if .Config.Server.Enable}}checked{{end}}></div>
            <div class="row"><label for="server.listen">监听地址</label><input id="server.listen" value="{{.Config.Server.Listen}}"></div>
            <div class="row"><label for="server.token">API Token</label><input id="server.token" type="password" placeholder="{{if .HasServerToken}}留空保持不变{{end}}"></div>
          </fieldset>
        </div>
      </section>

      <div class="actions">
        <div id="status" class="status"></div>
        <input id="authToken" class="auth-token" type="password" autocomplete="current-password" placeholder="鉴权 Token（输入一次后记住）">
        <button class="secondary" type="button" id="reloadBtn">重新加载</button>
        <button class="primary" type="submit">保存配置</button>
      </div>
    </form>
  </main>
  </div>
  <script>
    const ids = [
      "node.device_id", "node.management_url", "node.api_key",
      "capture.interface", "capture.pcap_file", "capture.bpf_filter", "capture.snaplen", "capture.promiscuous",
      "patterns.enable", "patterns.pattern_dir",
      "intel.intel_file", "intel.reload_interval_sec", "intel.enable_hot_reload", "intel.prune_expired_interval_sec", "intel.accept_stix", "intel.default_source", "intel.max_items",
      "intel.enable_ioc_sync", "intel.ioc_sync_dir", "intel.ioc_sync_dir2", "intel.ioc_sync_interval_min", "intel.ioc_sync_retain_days",
      "evidence.enable_pcap_save", "evidence.pcap_dir",
      "storage.backend", "storage.archive_dir", "storage.archive_after_hours", "storage.maintenance_interval_sec", "storage.archive_batch_size", "storage.high_water_bytes", "storage.low_water_bytes", "storage.min_free_bytes",
      "event.enable_push", "event.queue_db", "event.push_batch_size", "event.retry_interval_sec", "event.push_timeout_sec", "event.max_push_retry", "event.local_hit_window_sec",
      "flow.max_flows", "flow.idle_timeout_sec", "flow.cleanup_interval_sec",
      "aggregation.mode", "aggregation.enable_transaction_link", "aggregation.response_wait_sec", "aggregation.max_sessions",
      "aggregation.max_transactions_per_session", "aggregation.max_packets_per_transaction", "aggregation.max_reassembly_bytes_per_side",
      "aggregation.max_out_of_order_bytes", "aggregation.store_packet_index", "aggregation.save_full_session_pcap",
      "server.enable", "server.listen", "server.token"
    ];
    const statusEl = document.getElementById("status");
    const AUTH_TOKEN_KEY = "ta_node.authToken";
    const authTokenEl = document.getElementById("authToken");
    authTokenEl.value = localStorage.getItem(AUTH_TOKEN_KEY) || "";
    authTokenEl.addEventListener("change", () => rememberToken(authTokenEl.value));
    function rememberToken(token) {
      token = (token || "").trim();
      if (token) localStorage.setItem(AUTH_TOKEN_KEY, token);
      else localStorage.removeItem(AUTH_TOKEN_KEY);
    }
    function authHeaders(base) {
      const headers = Object.assign({}, base || {});
      const token = authTokenEl.value.trim();
      if (token) headers["Authorization"] = "Bearer " + token;
      return headers;
    }
    const viewMeta = {
      overview: ["运行概览", "查看节点采集、检测、告警和上报链路的整体状态。"],
      alerts: ["告警中心", "查看每次命中、双向会话、请求响应事务和原始数据包证据。"],
      capture: ["采集与会话", "配置流量来源、双向会话关联、资源上限和证据留存。"],
      detection: ["检测策略", "管理指纹规则、威胁情报和自动同步策略。"],
      delivery: ["事件与上报", "配置事件持久化、revision队列和管理端推送。"],
      system: ["节点与系统", "管理节点身份、本地API和访问鉴权。"]
    };
    function setActiveView(name) {
      if (!viewMeta[name]) name = "overview";
      document.querySelectorAll("[data-view-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.viewPanel === name));
      document.querySelectorAll(".nav-button").forEach((button) => button.classList.toggle("active", button.dataset.view === name));
      document.getElementById("viewTitle").textContent = viewMeta[name][0];
      document.getElementById("viewDescription").textContent = viewMeta[name][1];
      location.hash = name;
    }
    document.querySelectorAll(".nav-button,.view-shortcut").forEach((button) => button.addEventListener("click", () => setActiveView(button.dataset.view)));
    setActiveView(location.hash.slice(1) || "overview");
    function readValue(id) {
      const el = document.getElementById(id);
      if (el.type === "checkbox") return el.checked;
      if (el.type === "number") return Number(el.value);
      return el.value;
    }
    function writeValue(id, value) {
      const el = document.getElementById(id);
      if (!el) return;
      if (el.type === "checkbox") el.checked = Boolean(value);
      else el.value = value ?? "";
    }
    function setPath(obj, path, value) {
      const parts = path.split(".");
      let cur = obj;
      for (let i = 0; i < parts.length - 1; i++) cur = cur[parts[i]] ??= {};
      cur[parts.at(-1)] = value;
    }
    function getPath(obj, path) {
      return path.split(".").reduce((cur, key) => cur?.[key], obj);
    }
    function collectConfig() {
      const cfg = {};
      for (const id of ids) setPath(cfg, id, readValue(id));
      return cfg;
    }
    function setStatus(text, cls) {
      statusEl.className = "status " + (cls || "");
      statusEl.textContent = text;
    }
    function formatTime(ts) {
      if (!ts) return "";
      return new Date(ts * 1000).toLocaleString();
    }
    function escapeText(value) {
      return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      })[ch]);
    }
    const INLINE_HEX_LIMIT = 512;
    function hexDataHTML(value) {
      const hex = String(value || "");
      if (hex.length <= INLINE_HEX_LIMIT) {
        return '<pre class="packet-data">' + escapeText(hex || "（无数据）") + '</pre>';
      }
      const byteLength = Math.ceil(hex.replace(/\s+/g, "").length / 2);
      return '<details class="hex-details"><summary>HEX 内容较长，已隐藏（' +
        escapeText(byteLength) + ' 字节），点击展开</summary><pre class="packet-data">' +
        escapeText(hex) + '</pre></details>';
    }
    function pushStatusLabel(status) {
      return ({pending: "待上报", pushed: "已上报", failed: "上报失败"})[status] || status || "未知";
    }
    function responseStatusLabel(status) {
      return ({pending: "等待响应", complete: "已完成", not_captured: "未捕获"})[status] || status || "未知";
    }
    function messageForSide(item, side) {
      const exchange = item.exchange?.[side];
      if (exchange) {
        const firstPacket = (exchange.packets || [])[0] || {};
        return {
          aggregate: true,
          capture_time: exchange.capture_start_time_usec ? new Date(exchange.capture_start_time_usec / 1000).toLocaleString() : "",
          packet_sequence: firstPacket.packet_sequence,
          payload_hex: exchange.reassembled_hex,
          payload_text: exchange.reassembled_text,
          captured_length: exchange.captured_bytes,
          wire_length: exchange.wire_bytes,
          capture_truncated: exchange.truncated,
          reassembly_incomplete: exchange.reassembly_incomplete,
          retransmissions: exchange.retransmissions,
          packet_count: exchange.packet_count,
          packets: exchange.packets || []
        };
      }
      const raw = item.raw_packet;
      if (!raw) return null;
      if (raw[side]) return raw[side];
      if (raw.message_direction !== side) return null;
      return {
        capture_time: raw.capture_time,
        capture_time_usec: raw.capture_time_usec,
        packet_sequence: raw.packet_sequence,
        packet_hex: raw.packet_hex,
        payload_hex: raw.payload_hex,
        payload_text: raw.payload_text,
        captured_length: raw.captured_length,
        wire_length: raw.wire_length,
        capture_truncated: raw.capture_truncated
      };
    }
    function packetFragmentsHTML(message) {
      const packets = message?.packets || [];
      if (!packets.length) return "";
      return '<details class="packet-fragments"><summary>原始数据包（' + packets.length + ' 包）</summary>' +
        packets.map((packet, index) => '<details class="fragment-item"><summary>#' + escapeText(packet.packet_sequence || (index + 1)) +
          ' · Seq ' + escapeText(packet.tcp_seq || 0) + ' · ' + escapeText(packet.captured_length || 0) + ' 字节' +
          (packet.retransmission ? ' · 重传' : '') + '</summary>' + hexDataHTML(packet.packet_hex || "") + '</details>').join("") +
        '</details>';
    }
    function packetPanelHTML(message, side, emptyState) {
      if (!message) {
        return '<div class="packet-empty">' + escapeText(emptyState || "未捕获到对应报文") + '</div>';
      }
      const captured = message.captured_length || 0;
      const wire = message.wire_length || captured;
      const truncation = message.capture_truncated ? "（抓包已截断）" : "";
      const payloadHex = message.payload_hex || "（无应用层负载）";
      const text = message.payload_text || "（二进制或无负载，无可读文本）";
      const label = side === "request" ? "请求" : "响应";
      const flags = [message.capture_truncated ? "内容已截断" : "", message.reassembly_incomplete ? "重组不完整" : "", message.retransmissions ? ("重传 " + message.retransmissions + " 次") : ""].filter(Boolean).join(" · ");
      return '<div class="packet-meta packet-block">' +
          '<span><strong>抓包时间：</strong>' + escapeText(message.capture_time || "") + '</span>' +
          '<span><strong>' + (message.aggregate ? '包数量' : '包序号') + '：</strong>' + escapeText(message.aggregate ? (message.packet_count || 0) : (message.packet_sequence || "")) + '</span>' +
          '<span><strong>长度：</strong>' + escapeText(captured + " / " + wire + " 字节 " + truncation) + '</span>' +
          (flags ? '<span><strong>状态：</strong>' + escapeText(flags) + '</span>' : '') +
        '</div>' +
        (!message.aggregate ? '<div class="packet-block"><div class="packet-block-title">完整' + label + '抓包（HEX）</div>' + hexDataHTML(message.packet_hex || "") + '</div>' : '') +
        '<div class="packet-block"><div class="packet-block-title">' + (message.aggregate ? '重组' : '') + label + '报文（HEX）</div>' +
          hexDataHTML(payloadHex) + '</div>' +
        '<div class="packet-block"><div class="packet-block-title">' + (message.aggregate ? '重组' : '') + label + '报文（文本）</div>' +
          '<pre class="packet-data">' + escapeText(text) + '</pre></div>' + packetFragmentsHTML(message);
    }
    function packetDetailHTML(item, detailID) {
      const raw = item.raw_packet;
      if (!raw && !item.exchange) return '<div class="packet-detail muted">该告警由旧版本产生，没有原始报文。</div>';
      const request = messageForSide(item, "request");
      const response = messageForSide(item, "response");
      const initialSide = request ? "request" : "response";
      const direction = raw?.message_direction === "request" ? "请求" :
        (raw?.message_direction === "response" ? "响应" : "未知方向");
      const requestPanelID = detailID + "-request";
      const responsePanelID = detailID + "-response";
      const summary = item.session_summary || {};
      const responseState = item.exchange?.response_status || (response ? "complete" : "not_captured");
      const responseEmpty = responseState === "pending" ? "等待响应报文" : "未捕获到响应报文";
      return '<div class="packet-detail">' +
        '<div class="packet-meta">' +
          '<span><strong>告警触发方向：</strong>' + escapeText(direction) + '</span>' +
          '<span><strong>会话 ID：</strong>' + escapeText(item.session_id || "逐包事件") + '</span>' +
          '<span><strong>事务 ID：</strong>' + escapeText(item.transaction_id || "-") + '</span>' +
          '<span><strong>上下文版本：</strong>rev ' + escapeText(item.context_revision || 1) + (item.context_final ? ' · 已完成' : ' · 更新中') + '</span>' +
        '</div>' +
        (item.session_summary ? '<div class="session-strip"><div class="session-stat">客户端流量<strong>' + escapeText((summary.client_packets || 0) + ' 包 / ' + (summary.client_wire_bytes || 0) + ' B') + '</strong></div><div class="session-stat">服务端流量<strong>' + escapeText((summary.server_packets || 0) + ' 包 / ' + (summary.server_wire_bytes || 0) + ' B') + '</strong></div><div class="session-stat">会话命中<strong>' + escapeText(summary.hit_count || 0) + ' 次</strong></div><div class="session-stat">响应状态<strong>' + escapeText(responseStatusLabel(responseState)) + '</strong></div></div>' : '') +
        '<div class="packet-tabs" role="tablist" aria-label="请求和响应报文">' +
          '<button type="button" class="packet-tab' + (initialSide === "request" ? ' active' : '') + '" data-side="request" role="tab" aria-selected="' + (initialSide === "request") + '" aria-controls="' + requestPanelID + '">请求报文</button>' +
          '<button type="button" class="packet-tab' + (initialSide === "response" ? ' active' : '') + '" data-side="response" role="tab" aria-selected="' + (initialSide === "response") + '" aria-controls="' + responsePanelID + '">响应报文</button>' +
        '</div>' +
        '<div id="' + requestPanelID + '" class="packet-panel" data-side="request" role="tabpanel"' + (initialSide === "request" ? '' : ' hidden') + '>' + packetPanelHTML(request, "request", "未捕获到请求报文") + '</div>' +
        '<div id="' + responsePanelID + '" class="packet-panel" data-side="response" role="tabpanel"' + (initialSide === "response" ? '' : ' hidden') + '>' + packetPanelHTML(response, "response", responseEmpty) + '</div>' +
      '</div>';
    }
    function bindPacketToggles() {
      document.querySelectorAll(".packet-toggle").forEach((button) => {
        button.addEventListener("click", async () => {
          const detail = document.getElementById(button.dataset.target);
          if (!detail) return;
          const opening = detail.hidden;
          if (opening && detail.dataset.eventId && !detail.dataset.loaded) {
            button.disabled = true;
            try {
              const query = new URLSearchParams({event_id: detail.dataset.eventId, revision: detail.dataset.revision});
              const res = await fetch("/api/v1/push/event?" + query, {headers: authHeaders({})});
              const item = await res.json();
              if (!res.ok) throw new Error(item.error || res.statusText);
              detail.querySelector("td").innerHTML = packetDetailHTML(item, detail.id);
              detail.dataset.loaded = "1";
              bindPacketTabs();
            } catch (err) {
              detail.querySelector("td").textContent = "读取报文失败：" + err.message;
            } finally {button.disabled = false;}
          }

          detail.hidden = !opening;
          button.textContent = opening ? "▼" : "▶";
          button.setAttribute("aria-expanded", String(opening));
          button.setAttribute("title", opening ? "收起原始报文" : "展开原始报文");
        });
      });
    }
    function bindPacketTabs() {
      document.querySelectorAll(".packet-tabs").forEach((tabs) => {
        tabs.querySelectorAll(".packet-tab").forEach((tab) => {
          tab.addEventListener("click", () => {
            const detail = tabs.closest(".packet-detail");
            const side = tab.dataset.side;
            tabs.querySelectorAll(".packet-tab").forEach((candidate) => {
              const selected = candidate === tab;
              candidate.classList.toggle("active", selected);
              candidate.setAttribute("aria-selected", String(selected));
            });
            detail.querySelectorAll(".packet-panel").forEach((panel) => {
              panel.hidden = panel.dataset.side !== side;
            });
          });
        });
      });
    }
    async function loadPushLogs() {
      const rowsEl = document.getElementById("pushLogRows");
      const logStatus = document.getElementById("pushLogStatus");
      logStatus.textContent = "正在读取推送日志...";
      try {
        const res = await fetch("/api/v1/push/logs?summary=1");
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || res.statusText);
        const items = data.items || [];
        document.getElementById("overviewAlertCount").textContent = items.length + " 条";
        document.getElementById("overviewPendingCount").textContent = items.filter((item) => item.status === "pending" || item.status === "failed").length + " 条";
        if (items.length === 0) {
          rowsEl.innerHTML = '<tr><td colspan="9" class="muted">暂无数据</td></tr>';
        } else {
          rowsEl.innerHTML = items.map((item, index) => {
            const rule = [item.ioc_type, item.ioc_value].filter(Boolean).join(": ") || item.event_name || item.event_id || "";
            const src = item.src_ip ? item.src_ip + (item.src_port ? ":" + item.src_port : "") : "";
            const dst = item.dst_ip ? item.dst_ip + (item.dst_port ? ":" + item.dst_port : "") : "";
            const hit = src && dst ? src + " → " + dst : (src || dst);
            const detailID = "packet-detail-" + index;
            const hasPacket = Boolean(item.raw_packet || item.exchange);
            const contextLabel = item.context_final ? "上下文完成" : (item.exchange?.response_status === "pending" ? "等待响应" : "逐包事件");
            const contextClass = item.context_final ? "complete" : "pending";
            return '<tr>' +
              '<td><button type="button" class="packet-toggle" data-target="' + detailID + '"' +
                (hasPacket ? ' title="展开原始报文" aria-expanded="false">▶' : ' title="无原始报文" disabled>▷') + '</button></td>' +
              '<td>' + escapeText(formatTime(item.occurred_at)) + '</td>' +
              '<td><span class="badge ' + escapeText(item.status) + '">' + escapeText(pushStatusLabel(item.status)) + '</span><span class="context-state ' + contextClass + '">' + escapeText(contextLabel) + '</span></td>' +
              '<td>' + escapeText(rule) + '</td>' +
              '<td>' + escapeText(hit) + '</td>' +
              '<td>' + escapeText(item.severity || "") + '</td>' +
              '<td>' + escapeText(item.retry_count) + '</td>' +
              '<td>' + escapeText(formatTime(item.updated_at)) + '</td>' +
              '<td>' + escapeText(item.last_error || "") + '</td>' +
            '</tr>' +
            '<tr id="' + detailID + '" data-event-id="' + escapeText(item.event_id) + '" data-revision="' + escapeText(item.context_revision || 1) + '" class="packet-detail-row" hidden><td colspan="9">展开后读取完整报文</td></tr>';
          }).join("");
          bindPacketToggles();
          bindPacketTabs();
        }
        logStatus.textContent = data.error ? ("读取队列失败：" + data.error) : "最近 50 条告警及最新上下文 revision";
      } catch (err) {
        rowsEl.innerHTML = '<tr><td colspan="9" class="muted">读取失败</td></tr>';
        logStatus.textContent = "读取推送日志失败：" + err.message;
        document.getElementById("overviewAlertCount").textContent = "读取失败";
        document.getElementById("overviewPendingCount").textContent = "读取失败";
      }
    }
    document.getElementById("configForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      setStatus("正在保存...", "");
      try {
        const res = await fetch("/api/v1/config", {
          method: "POST",
          headers: authHeaders({"Content-Type": "application/json"}),
          body: JSON.stringify({config: collectConfig()})
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.error || res.statusText);
        const rotated = String(readValue("server.token") || "").trim();
        if (rotated) rememberToken(rotated);
        setStatus("已保存，重启 ta_node 后采集和推送参数生效。", "ok");
      } catch (err) {
        setStatus("保存失败：" + err.message, "error");
      }
    });
    document.getElementById("reloadBtn").addEventListener("click", async () => {
      setStatus("正在读取...", "");
      try {
        const res = await fetch("/api/v1/config");
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || res.statusText);
        for (const id of ids) writeValue(id, getPath(data.config, id));
        setStatus("已重新加载当前内存配置。", "ok");
      } catch (err) {
        setStatus("读取失败：" + err.message, "error");
      }
    });
    document.getElementById("refreshPushLogsBtn").addEventListener("click", loadPushLogs);
    loadPushLogs();
    let intelPage = 0;
    const intelPageSize = 50;
    async function loadIntelRules() {
      const rowsEl = document.getElementById("intelRows");
      const status = document.getElementById("intelTableStatus");
      const prevBtn = document.getElementById("intelPrevBtn");
      const nextBtn = document.getElementById("intelNextBtn");
      const pageInfo = document.getElementById("intelPageInfo");
      const offset = intelPage * intelPageSize;
      try {
        const res = await fetch("/api/v1/intel?offset=" + offset + "&limit=" + intelPageSize);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || res.statusText);
        const items = data.items || [];
        const total = data.total || 0;
        document.getElementById("overviewIntelCount").textContent = total + " 条";
        status.textContent = "共 " + total + " 条 IOC 规则（第 " + (offset + 1) + "-" + Math.min(offset + items.length, total) + " 条）";
        status.className = "muted";
        pageInfo.textContent = "第 " + (intelPage + 1) + " / " + Math.max(1, Math.ceil(total / intelPageSize)) + " 页";
        prevBtn.disabled = intelPage === 0;
        nextBtn.disabled = offset + items.length >= total;
        if (items.length === 0) {
          rowsEl.innerHTML = '<tr><td colspan="8" class="muted">暂无数据</td></tr>';
        } else {
          rowsEl.innerHTML = items.map((item) =>
            '<tr>' +
              '<td>' + escapeText(item.id || "") + '</td>' +
              '<td>' + escapeText(item.type || "") + '</td>' +
              '<td>' + escapeText(item.value || "") + '</td>' +
              '<td>' + escapeText(item.category || "") + '</td>' +
              '<td>' + escapeText(item.severity || "") + '</td>' +
              '<td>' + escapeText(item.source || "") + '</td>' +
              '<td>' + (item.enabled ? '是' : '否') + '</td>' +
              '<td>' + escapeText(item.description || "") + '</td>' +
            '</tr>'
          ).join("");
        }
      } catch (err) {
        rowsEl.innerHTML = '<tr><td colspan="8" class="muted">读取失败</td></tr>';
        status.textContent = "读取规则失败：" + err.message;
        status.className = "error";
        document.getElementById("overviewIntelCount").textContent = "读取失败";
      }
    }
    document.getElementById("refreshIntelBtn").addEventListener("click", () => { intelPage = 0; loadIntelRules(); });
    document.getElementById("intelPrevBtn").addEventListener("click", () => { if (intelPage > 0) { intelPage--; loadIntelRules(); } });
    document.getElementById("intelNextBtn").addEventListener("click", () => { intelPage++; loadIntelRules(); });
    loadIntelRules();
    document.getElementById("triggerIocSyncBtn").addEventListener("click", async () => {
      const btn = document.getElementById("triggerIocSyncBtn");
      const status = document.getElementById("iocSyncStatus");
      btn.disabled = true;
      status.textContent = "正在同步...";
      status.className = "muted";
      try {
        const res = await fetch("/api/v1/intel/iocsync", {
          method: "POST",
          headers: authHeaders({"Content-Type": "application/json"})
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.error || res.statusText);
        status.textContent = "同步完成，新增 " + (data.added || 0) + " 条 IOC。";
        status.className = "ok";
      } catch (err) {
        status.textContent = "同步失败：" + err.message;
        status.className = "error";
      } finally {
        btn.disabled = false;
      }
    });
  </script>
</body>
</html>`))
