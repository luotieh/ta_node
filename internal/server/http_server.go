package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"ta_node/internal/config"
	"ta_node/internal/intel"
	"ta_node/internal/queue"
)

type Server struct {
	store      *intel.Store
	cfg        config.Config
	configPath string
	mu         sync.RWMutex
	mux        *http.ServeMux
}

func New(store *intel.Store, cfg config.Config, configPath string) *Server {
	s := &Server{store: store, cfg: cfg, configPath: configPath, mux: http.NewServeMux()}
	s.routes()
	return s
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
	s.mux.HandleFunc("/api/v1/intel", s.handleIntel)
	s.mux.HandleFunc("/api/v1/intel/", s.handleIntelID)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		cfg := s.cfg
		s.mu.RUnlock()
		cfg.Node.Token = ""
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
		if current.Node.Token != "" && req.Config.Node.Token == "" {
			req.Config.Node.Token = current.Node.Token
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
	data := struct {
		Config         config.Config
		ConfigPath     string
		HasNodeToken   bool
		HasNodeAPIKey  bool
		HasServerToken bool
	}{Config: s.cfg, ConfigPath: s.configPath, HasNodeToken: s.cfg.Node.Token != "", HasNodeAPIKey: s.cfg.Node.APIKey != "", HasServerToken: s.cfg.Server.Token != ""}
	data.Config.Node.Token = ""
	data.Config.Node.APIKey = ""
	data.Config.Server.Token = ""
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = configPage.Execute(w, data)
}

func (s *Server) handleIntel(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"items": s.store.List()})
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
	logs, err := queue.RecentPushLogs(path, 50)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []queue.PushLog{}, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": logs})
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
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
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
    @media (max-width: 860px) {
      form { grid-template-columns: 1fr; }
      .topbar { align-items: flex-start; flex-direction: column; gap: 4px; }
    }
    @media (max-width: 560px) {
      header, main { padding-left: 14px; padding-right: 14px; }
      .row { grid-template-columns: 1fr; gap: 5px; }
      .actions { flex-wrap: wrap; justify-content: stretch; }
      .status { width: 100%; }
      .auth-token { width: 100%; flex: 1 1 100%; }
      button { flex: 1; }
    }
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div>
        <h1>ta_node 配置</h1>
        <div class="path">配置文件：{{.ConfigPath}}</div>
      </div>
    </div>
  </header>
  <main>
    <form id="configForm">
      <fieldset>
        <legend>节点</legend>
        <div class="row"><label for="node.device_id">设备 ID</label><input id="node.device_id" value="{{.Config.Node.DeviceID}}"></div>
      </fieldset>
      <fieldset>
        <legend>采集</legend>
        <div class="row"><label for="capture.interface">网卡</label><input id="capture.interface" value="{{.Config.Capture.Interface}}"></div>
        <div class="row"><label for="capture.pcap_file">PCAP 文件</label><input id="capture.pcap_file" value="{{.Config.Capture.PCAPFile}}"></div>
        <div class="row"><label for="capture.bpf_filter">BPF 过滤</label><input id="capture.bpf_filter" value="{{.Config.Capture.BPFFilter}}"></div>
        <div class="row"><label></label><span class="muted" style="font-size:12px">BPF 过滤需用 -tags pcap 构建；默认 AF_PACKET 后端填写非空值会导致启动失败。</span></div>
        <div class="row"><label for="capture.snaplen">Snaplen</label><input id="capture.snaplen" type="number" min="64" value="{{.Config.Capture.Snaplen}}"></div>
        <div class="row"><label for="capture.promiscuous">混杂模式</label><input id="capture.promiscuous" type="checkbox" {{if .Config.Capture.Promiscuous}}checked{{end}}></div>
      </fieldset>
      <fieldset>
        <legend>规则与情报</legend>
        <div class="row"><label for="patterns.pattern_dir">规则目录</label><input id="patterns.pattern_dir" value="{{.Config.Patterns.PatternDir}}"></div>
        <div class="row"><label for="intel.intel_file">情报文件</label><input id="intel.intel_file" value="{{.Config.Intel.IntelFile}}"></div>
        <div class="row"><label for="intel.reload_interval_sec">热加载间隔</label><input id="intel.reload_interval_sec" type="number" min="1" value="{{.Config.Intel.ReloadIntervalSec}}"></div>
        <div class="row"><label for="intel.enable_hot_reload">启用热加载</label><input id="intel.enable_hot_reload" type="checkbox" {{if .Config.Intel.EnableHotReload}}checked{{end}}></div>
        <div class="row"><label for="intel.prune_expired_interval_sec">过期清理间隔</label><input id="intel.prune_expired_interval_sec" type="number" min="0" value="{{.Config.Intel.PruneExpiredIntervalSec}}"></div>
        <div class="row"><label for="intel.accept_stix">接收 STIX</label><input id="intel.accept_stix" type="checkbox" {{if .Config.Intel.AcceptSTIX}}checked{{end}}></div>
        <div class="row"><label for="intel.default_source">默认来源</label><input id="intel.default_source" value="{{.Config.Intel.DefaultSource}}"></div>
        <div class="row"><label for="intel.max_items">最大 IOC 数</label><input id="intel.max_items" type="number" min="0" value="{{.Config.Intel.MaxItems}}"></div>
      </fieldset>
      <fieldset>
        <legend>证据</legend>
        <div class="row"><label for="evidence.enable_pcap_save">保存 PCAP</label><input id="evidence.enable_pcap_save" type="checkbox" {{if .Config.Evidence.EnablePCAPSave}}checked{{end}}></div>
        <div class="row"><label for="evidence.pcap_dir">证据目录</label><input id="evidence.pcap_dir" value="{{.Config.Evidence.PCAPDir}}"></div>
      </fieldset>
      <fieldset>
        <legend>事件队列</legend>
        <div class="row"><label for="event.queue_db">SQLite DB</label><input id="event.queue_db" value="{{.Config.Event.QueueDB}}"></div>
      </fieldset>
      <fieldset>
        <legend>事件推送</legend>
        <div class="row"><label for="event.enable_push">启用推送</label><input id="event.enable_push" type="checkbox" {{if .Config.Event.EnablePush}}checked{{end}}></div>
        <div class="row"><label for="node.management_url">管理端 URL</label><input id="node.management_url" value="{{.Config.Node.ManagementURL}}"></div>
        <div class="row"><label for="node.token">推送 Token</label><input id="node.token" type="password" placeholder="{{if .HasNodeToken}}留空保持不变{{end}}"></div>
        <div class="row"><label for="node.api_key">内部 API Key</label><input id="node.api_key" type="password" placeholder="{{if .HasNodeAPIKey}}留空保持不变{{else}}X-API-Key，留空则不发送{{end}}"></div>
        <div class="row"><label for="event.push_batch_size">推送批量</label><input id="event.push_batch_size" type="number" min="1" value="{{.Config.Event.PushBatchSize}}"></div>
        <div class="row"><label for="event.retry_interval_sec">重试间隔</label><input id="event.retry_interval_sec" type="number" min="1" value="{{.Config.Event.RetryIntervalSec}}"></div>
        <div class="row"><label for="event.push_timeout_sec">推送超时</label><input id="event.push_timeout_sec" type="number" min="1" value="{{.Config.Event.PushTimeoutSec}}"></div>
      </fieldset>
      <fieldset>
        <legend>本地服务</legend>
        <div class="row"><label for="server.enable">启用 API</label><input id="server.enable" type="checkbox" {{if .Config.Server.Enable}}checked{{end}}></div>
        <div class="row"><label for="server.listen">监听地址</label><input id="server.listen" value="{{.Config.Server.Listen}}"></div>
        <div class="row"><label for="server.token">API Token</label><input id="server.token" type="password" placeholder="{{if .HasServerToken}}留空保持不变{{end}}"></div>
      </fieldset>
      <fieldset class="full">
        <legend>推送日志</legend>
        <div class="toolbar">
          <div id="pushLogStatus" class="muted">最近 50 条队列推送状态</div>
          <button class="secondary" type="button" id="refreshPushLogsBtn">刷新日志</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>时间</th>
                <th>状态</th>
                <th>事件</th>
                <th>IOC</th>
                <th>重试</th>
                <th>错误</th>
              </tr>
            </thead>
            <tbody id="pushLogRows">
              <tr><td colspan="6" class="muted">暂无数据</td></tr>
            </tbody>
          </table>
        </div>
      </fieldset>
      <div class="actions">
        <div id="status" class="status"></div>
        <input id="authToken" class="auth-token" type="password" autocomplete="current-password" placeholder="鉴权 Token（输入一次后记住）">
        <button class="secondary" type="button" id="reloadBtn">重新加载</button>
        <button class="primary" type="submit">保存配置</button>
      </div>
    </form>
  </main>
  <script>
    const ids = [
      "node.device_id", "node.management_url", "node.token", "node.api_key",
      "capture.interface", "capture.pcap_file", "capture.bpf_filter", "capture.snaplen", "capture.promiscuous",
      "patterns.pattern_dir",
      "intel.intel_file", "intel.reload_interval_sec", "intel.enable_hot_reload", "intel.prune_expired_interval_sec", "intel.accept_stix", "intel.default_source", "intel.max_items",
      "evidence.enable_pcap_save", "evidence.pcap_dir",
      "event.enable_push", "event.queue_db", "event.push_batch_size", "event.retry_interval_sec", "event.push_timeout_sec",
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
    async function loadPushLogs() {
      const rowsEl = document.getElementById("pushLogRows");
      const logStatus = document.getElementById("pushLogStatus");
      logStatus.textContent = "正在读取推送日志...";
      try {
        const res = await fetch("/api/v1/push/logs");
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || res.statusText);
        const items = data.items || [];
        if (items.length === 0) {
          rowsEl.innerHTML = '<tr><td colspan="6" class="muted">暂无数据</td></tr>';
        } else {
          rowsEl.innerHTML = items.map((item) =>
            '<tr>' +
              '<td>' + escapeText(formatTime(item.updated_at)) + '</td>' +
              '<td><span class="badge ' + escapeText(item.status) + '">' + escapeText(item.status) + '</span></td>' +
              '<td>' + escapeText(item.event_name || item.event_id || "") + '</td>' +
              '<td>' + escapeText([item.ioc_type, item.ioc_value].filter(Boolean).join(": ")) + '</td>' +
              '<td>' + escapeText(item.retry_count) + '</td>' +
              '<td>' + escapeText(item.last_error || "") + '</td>' +
            '</tr>'
          ).join("");
        }
        logStatus.textContent = data.error ? ("读取队列失败：" + data.error) : "最近 50 条队列推送状态";
      } catch (err) {
        rowsEl.innerHTML = '<tr><td colspan="6" class="muted">读取失败</td></tr>';
        logStatus.textContent = "读取推送日志失败：" + err.message;
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
  </script>
</body>
</html>`))
