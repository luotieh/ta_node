# 网闸 IOC zip 落地监听与规则实时导入 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 监听 `/data/yt/ioc` 目录里网闸投递的 `.zip` 规则包，实时解析、去重并入本节点 IOC 规则集，且把规则富字段（`evidence`/`recommended_action`）带到安全事件。

**Architecture:** 新增 `internal/iocwatch` 组件，短间隔轮询目录 → `archive/zip` 内存解包 → 解析现有 `items:` yaml → 三层去重 → `intel.Store.UpsertDedup` 原子落库并立即生效（matcher 监听 version）；富字段扩展进 `ThreatIntel`/`ThreatEvent`，detector 拷贝、push 整体 JSON 自动推送。

**Tech Stack:** Go 标准库 `archive/zip`、`gopkg.in/yaml.v3`（已 vendor）；无新增第三方依赖（不引入 fsnotify）。

## Global Constraints

- 不引入任何新的第三方依赖（离线 vendor 构建）；仅用标准库 + 已 vendor 的 `gopkg.in/yaml.v3`、`github.com/google/uuid`。
- 遵循现有轮询定时器风格（`hotReload`/`pruneExpired`/`flowCleanup`），所有长驻 goroutine 受 `ctx` 控制退出。
- 解析失败/坏文件绝不缩减现有规则集（增量语义）。
- zip 内容只在内存读取，不落盘解压（规避 zip-slip）。
- 去重按 canonical key `type|规范化value`，复用 `internal/intel/matcher.go` 的 `canonicalIP`/`canonicalDomain`。
- 每个 task 结束后 `go build ./...` 与相关 `go test` 必须通过。

---

## File Structure

- `internal/intel/types.go` — Modify：`ThreatIntel` 加 `Evidence`/`RecommendedAction`；新增 `Evidence` 结构体。
- `internal/intel/store.go` — Modify：新增 `UpsertDedup` + `canonicalKey`/`canonicalValue` 助手。
- `internal/intel/store_test.go` — Modify：`UpsertDedup` 单测。
- `internal/intel/types_test.go` — Create：yaml 解析富字段单测。
- `internal/event/event.go` — Modify：`ThreatEvent` 加 `RecommendedAction`/`IOCEvidence`。
- `internal/detector/engine.go` — Modify：intel→event 拷贝处补两行。
- `internal/detector/engine_test.go` — Modify：断言富字段被填充。
- `internal/config/config.go` — Modify：`IntelConfig` 加三字段 + 默认值 + `WatchInterval()`。
- `internal/config/config_test.go` — Create/Modify：默认值单测。
- `internal/iocwatch/extract.go` — Create：zip → `[]intel.ThreatIntel`。
- `internal/iocwatch/watcher.go` — Create：轮询 + 处理 + 移动。
- `internal/iocwatch/watcher_test.go` — Create：端到端组件测试。
- `cmd/ta_node/main.go` — Modify：挂载 watcher goroutine。
- `configs/ta_node.yaml`、`configs/ta_node.offline.yaml` — Modify：加配置示例注释。

---

## Task 1: 扩展 ThreatIntel 富字段

**Files:**
- Modify: `internal/intel/types.go`
- Create: `internal/intel/types_test.go`

**Interfaces:**
- Produces: `intel.Evidence` 结构体；`ThreatIntel.Evidence *Evidence`、`ThreatIntel.RecommendedAction string`。后续 Task 3/5 依赖这两个字段名。

- [ ] **Step 1: 写失败测试**

Create `internal/intel/types_test.go`:

```go
package intel

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadFileParsesRichFields(t *testing.T) {
	body := `items:
- id: otx-1
  type: domain
  value: evil.example.com
  category: c2
  severity: high
  source: Threat Intel Hub
  recommended_action: block_and_report
  evidence:
    activity: Some Campaign
    threat_labels: [ransomware, phishing]
    source: otx
    cross_check: null
    confidence: high (1 source)
    tlp: white
    misp_event_id: 6a46d120d41fcc87a8a52932
    narrative: null
  enabled: true
`
	var f File
	if err := yaml.Unmarshal([]byte(body), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Items) != 1 {
		t.Fatalf("want 1 item, got %d", len(f.Items))
	}
	it := f.Items[0]
	if it.RecommendedAction != "block_and_report" {
		t.Errorf("recommended_action: got %q", it.RecommendedAction)
	}
	if it.Evidence == nil {
		t.Fatal("evidence is nil")
	}
	if it.Evidence.Activity != "Some Campaign" || it.Evidence.TLP != "white" {
		t.Errorf("evidence base fields: %+v", it.Evidence)
	}
	if len(it.Evidence.ThreatLabels) != 2 || it.Evidence.MISPEventID != "6a46d120d41fcc87a8a52932" {
		t.Errorf("evidence labels/misp: %+v", it.Evidence)
	}
	if it.Evidence.CrossCheck != "" || it.Evidence.Narrative != "" {
		t.Errorf("null yaml should map to empty string: %+v", it.Evidence)
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test ./internal/intel/ -run TestLoadFileParsesRichFields -v`
Expected: FAIL（编译错误：`it.RecommendedAction`/`it.Evidence` 未定义）

- [ ] **Step 3: 实现**

Edit `internal/intel/types.go`，在 `ThreatIntel` 结构体末尾（`ExpireAt` 行之后、闭括号之前）加：

```go
	RecommendedAction string    `json:"recommended_action,omitempty" yaml:"recommended_action,omitempty"`
	Evidence          *Evidence `json:"evidence,omitempty" yaml:"evidence,omitempty"`
```

并在 `ThreatIntel` 结构体之后新增：

```go
// Evidence carries the rich threat context delivered alongside an IOC (via the
// gateway zip feed). It is preserved through matching into pushed events for AI
// analysis. Absent for locally-authored IOCs.
type Evidence struct {
	Activity     string   `json:"activity,omitempty" yaml:"activity,omitempty"`
	ThreatLabels []string `json:"threat_labels,omitempty" yaml:"threat_labels,omitempty"`
	Source       string   `json:"source,omitempty" yaml:"source,omitempty"`
	CrossCheck   string   `json:"cross_check,omitempty" yaml:"cross_check,omitempty"`
	Confidence   string   `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	TLP          string   `json:"tlp,omitempty" yaml:"tlp,omitempty"`
	MISPEventID  string   `json:"misp_event_id,omitempty" yaml:"misp_event_id,omitempty"`
	Narrative    string   `json:"narrative,omitempty" yaml:"narrative,omitempty"`
}
```

- [ ] **Step 4: 运行确认通过**

Run: `go test ./internal/intel/ -run TestLoadFileParsesRichFields -v`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add internal/intel/types.go internal/intel/types_test.go
git commit -m "Add Evidence and RecommendedAction fields to ThreatIntel"
```

---

## Task 2: Store.UpsertDedup（canonical 去重 + id 复用）

**Files:**
- Modify: `internal/intel/store.go`
- Modify: `internal/intel/store_test.go`

**Interfaces:**
- Consumes: `canonicalIP`/`canonicalDomain`（`internal/intel/matcher.go`，同包私有）。
- Produces: `func (s *Store) UpsertDedup(items []ThreatIntel) error`。Task 5 依赖它。

- [ ] **Step 1: 写失败测试**

在 `internal/intel/store_test.go` 末尾追加：

```go
func TestUpsertDedupCollapsesSameValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intel.yaml")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// 同一 value、不同 id、大小写/末尾点差异 —— 应折叠为一条
	err = s.UpsertDedup([]ThreatIntel{
		{ID: "otx-a", Type: "domain", Value: "Evil.example.com", Enabled: true},
		{ID: "otx-b", Type: "domain", Value: "evil.example.com.", Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	list := s.List()
	if len(list) != 1 {
		t.Fatalf("want 1 deduped item, got %d: %+v", len(list), list)
	}
}

func TestUpsertDedupReusesExistingID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intel.yaml")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(ThreatIntel{ID: "local-1", Type: "ip", Value: "1.2.3.4", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// feed 用不同 id 送同一 value —— 应复用既有 id 就地更新，不新增
	if err := s.UpsertDedup([]ThreatIntel{
		{ID: "otx-x", Type: "ip", Value: "1.2.3.4", Category: "c2", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	list := s.List()
	if len(list) != 1 {
		t.Fatalf("want 1 item, got %d", len(list))
	}
	if list[0].ID != "local-1" || list[0].Category != "c2" {
		t.Errorf("want in-place update of local-1 with category c2, got %+v", list[0])
	}
}

func TestUpsertDedupEmptyNoop(t *testing.T) {
	s, err := NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	v := s.Version()
	if err := s.UpsertDedup(nil); err != nil {
		t.Fatal(err)
	}
	if s.Version() != v {
		t.Errorf("empty upsert should not bump version: %d -> %d", v, s.Version())
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test ./internal/intel/ -run TestUpsertDedup -v`
Expected: FAIL（`UpsertDedup` 未定义）

- [ ] **Step 3: 实现**

在 `internal/intel/store.go` 末尾（`normalize` 函数之后）追加：

```go
// canonicalValue normalizes an IOC value for identity comparison, mirroring the
// matcher's indexing so two entries that would match the same traffic collapse
// to one key.
func canonicalValue(t, v string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "ip":
		if c := canonicalIP(v); c != "" {
			return c
		}
	case "domain":
		return canonicalDomain(v)
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// canonicalKey identifies an IOC by (type, normalized value) rather than id, so
// the same indicator delivered under different feed ids is deduped.
func canonicalKey(it ThreatIntel) string {
	return strings.ToLower(strings.TrimSpace(it.Type)) + "|" + canonicalValue(it.Type, it.Value)
}

// UpsertDedup merges a feed batch into the primary set with (type,value) dedup:
//   - within the batch, entries with the same canonical key collapse, keeping
//     the one with the newest incoming updated_at;
//   - against the existing set, an incoming entry whose canonical key already
//     exists reuses that entry's id (in-place update) instead of adding a
//     duplicate row for the same indicator.
// It bumps the version (matcher picks it up on the next packet) and persists
// atomically. An empty effective batch is a no-op.
func (s *Store) UpsertDedup(items []ThreatIntel) error {
	batch := map[string]ThreatIntel{}
	for _, it := range items {
		k := canonicalKey(it)
		if ex, ok := batch[k]; ok && ex.UpdatedAt >= it.UpdatedAt {
			continue
		}
		batch[k] = it
	}
	if len(batch) == 0 {
		return nil
	}
	now := time.Now().Unix()
	s.mu.Lock()
	existing := make(map[string]string, len(s.items))
	for id, it := range s.items {
		existing[canonicalKey(it)] = id
	}
	for k, it := range batch {
		if id, ok := existing[k]; ok {
			it.ID = id
		}
		createdAt := it.CreatedAt
		normalize(&it, now)
		if prev, ok := s.items[it.ID]; ok && createdAt == 0 {
			it.CreatedAt = prev.CreatedAt
		}
		s.primary[it.ID] = it
	}
	s.rebuildItemsLocked()
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, saved)
	}
	return nil
}
```

- [ ] **Step 4: 运行确认通过**

Run: `go test ./internal/intel/ -run TestUpsertDedup -v`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add internal/intel/store.go internal/intel/store_test.go
git commit -m "Add Store.UpsertDedup with canonical type/value dedup and id reuse"
```

---

## Task 3: 事件携带富字段 + detector 拷贝

**Files:**
- Modify: `internal/event/event.go`
- Modify: `internal/detector/engine.go`
- Modify: `internal/detector/engine_test.go`

**Interfaces:**
- Consumes: `intel.Evidence`（Task 1）；`hit.Evidence`/`hit.RecommendedAction`。
- Produces: `event.ThreatEvent.IOCEvidence *intel.Evidence`、`event.ThreatEvent.RecommendedAction string`。

- [ ] **Step 1: 改测试（先失败）**

在 `internal/detector/engine_test.go` 里，把现有 intel 命中用例的 `IntelHits` 那条加上富字段。找到：

```go
		IntelHits: []intel.ThreatIntel{
			{ID: "ioc-1", Type: "domain", Value: "evil.example.com", Source: "hub", Category: "c2", Severity: "high", Description: "known C2", ExpireAt: 4_102_444_800},
		},
```

替换为：

```go
		IntelHits: []intel.ThreatIntel{
			{ID: "ioc-1", Type: "domain", Value: "evil.example.com", Source: "hub", Category: "c2", Severity: "high", Description: "known C2", ExpireAt: 4_102_444_800,
				RecommendedAction: "block_and_report",
				Evidence:          &intel.Evidence{Activity: "Camp", Confidence: "high (1 source)", TLP: "white"}},
		},
```

并在同测试函数内 `ev.IOCDescription` 断言之后追加：

```go
	if ev.RecommendedAction != "block_and_report" {
		t.Errorf("recommended_action not propagated: %q", ev.RecommendedAction)
	}
	if ev.IOCEvidence == nil || ev.IOCEvidence.TLP != "white" || ev.IOCEvidence.Confidence != "high (1 source)" {
		t.Errorf("ioc_evidence not propagated: %+v", ev.IOCEvidence)
	}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test ./internal/detector/ -run . -v`
Expected: FAIL（`ev.IOCEvidence`/`ev.RecommendedAction` 未定义）

- [ ] **Step 3: 实现 — event.go**

在 `internal/event/event.go` 顶部 `package event` 之后加 import：

```go
import "ta_node/internal/intel"
```

在 `ThreatEvent` 结构体里，`IOCExpireAt` 字段之后加：

```go
	RecommendedAction string          `json:"recommended_action,omitempty"`
	IOCEvidence       *intel.Evidence `json:"ioc_evidence,omitempty"`
```

将 `SchemaVersion` 常量从 `"1.2"` 改为 `"1.3"`（字段新增，遵循注释约定）。

- [ ] **Step 4: 实现 — detector engine.go**

在 `internal/detector/engine.go` 的 intel 命中拷贝处（`ev.IOCExpireAt = hit.ExpireAt` 一行之后）加：

```go
		ev.RecommendedAction = hit.RecommendedAction
		ev.IOCEvidence = hit.Evidence
```

- [ ] **Step 5: 运行确认通过（并回归全包）**

Run: `go test ./internal/detector/ ./internal/event/ -v`
Expected: PASS（注意：`engine_test.go` 若断言了 `SchemaVersion`，用的是 `event.SchemaVersion` 常量比较，改常量不影响该断言）

- [ ] **Step 6: 提交**

```bash
git add internal/event/event.go internal/detector/engine.go internal/detector/engine_test.go
git commit -m "Propagate IOC evidence and recommended_action into threat events"
```

---

## Task 4: 配置项与默认值

**Files:**
- Modify: `internal/config/config.go`
- Create: `internal/config/config_test.go`

**Interfaces:**
- Produces: `IntelConfig.IocWatchDir string`、`IocWatchIntervalSec int`、`EnableIocWatch bool`；`func (c Config) WatchInterval() time.Duration`。Task 6 依赖。

- [ ] **Step 1: 写失败测试**

Create `internal/config/config_test.go`:

```go
package config

import (
	"testing"
	"time"
)

func TestDefaultIocWatch(t *testing.T) {
	c := Default()
	if c.Intel.IocWatchDir != "/data/yt/ioc" {
		t.Errorf("ioc_watch_dir default: %q", c.Intel.IocWatchDir)
	}
	if c.Intel.IocWatchIntervalSec != 5 {
		t.Errorf("ioc_watch_interval_sec default: %d", c.Intel.IocWatchIntervalSec)
	}
	if !c.Intel.EnableIocWatch {
		t.Error("enable_ioc_watch default should be true")
	}
	if c.WatchInterval() != 5*time.Second {
		t.Errorf("WatchInterval: %v", c.WatchInterval())
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test ./internal/config/ -run TestDefaultIocWatch -v`
Expected: FAIL（字段/方法未定义）

- [ ] **Step 3: 实现**

在 `internal/config/config.go` 的 `IntelConfig` 结构体末尾（`MaxItems` 之后）加：

```go
	IocWatchDir         string `json:"ioc_watch_dir" yaml:"ioc_watch_dir"`
	IocWatchIntervalSec int    `json:"ioc_watch_interval_sec" yaml:"ioc_watch_interval_sec"`
	EnableIocWatch      bool   `json:"enable_ioc_watch" yaml:"enable_ioc_watch"`
```

在 `Default()` 的 `Intel:` 块里（`MaxItems: 100000,` 之后）加：

```go
			IocWatchDir:         "/data/yt/ioc",
			IocWatchIntervalSec: 5,
			EnableIocWatch:      true,
```

在文件末尾其它 `func (c Config) XxxInterval()` 附近加：

```go
func (c Config) WatchInterval() time.Duration {
	return time.Duration(c.Intel.IocWatchIntervalSec) * time.Second
}
```

- [ ] **Step 4: 运行确认通过**

Run: `go test ./internal/config/ -run TestDefaultIocWatch -v`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "Add ioc_watch config fields and WatchInterval helper"
```

---

## Task 5: iocwatch 组件（解包 + 轮询 + 移动）

**Files:**
- Create: `internal/iocwatch/extract.go`
- Create: `internal/iocwatch/watcher.go`
- Create: `internal/iocwatch/watcher_test.go`

**Interfaces:**
- Consumes: `intel.Store.UpsertDedup`（Task 2）、`intel.File`/`intel.ThreatIntel`（Task 1）。
- Produces: `func New(store *intel.Store, dir string, interval time.Duration, maxItems int) *Watcher`、`func (w *Watcher) Run(ctx context.Context)`、`func (w *Watcher) scanOnce()`（包内可测）。

- [ ] **Step 1: 写失败测试**

Create `internal/iocwatch/watcher_test.go`:

```go
package iocwatch

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ta_node/internal/intel"
)

func newStore(t *testing.T) *intel.Store {
	t.Helper()
	s, err := intel.NewStore(filepath.Join(t.TempDir(), "intel.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

const sampleYAML = `items:
- id: otx-1
  type: domain
  value: evil.example.com
  category: c2
  severity: high
  recommended_action: block_and_report
  evidence: {activity: Camp, tlp: white}
  enabled: true
`

func newWatcher(store *intel.Store, dir string) *Watcher {
	w := New(store, dir, time.Second, 100000)
	w.staleAfter = 0 // 测试里立即判定坏 zip 为 failed
	return w
}

func TestScanImportsAndMoves(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	writeZip(t, filepath.Join(dir, "feed-1.zip"), map[string]string{"a.yaml": sampleYAML})
	newWatcher(store, dir).scanOnce()

	if len(store.List()) != 1 {
		t.Fatalf("want 1 item imported, got %d", len(store.List()))
	}
	it := store.List()[0]
	if it.Evidence == nil || it.Evidence.TLP != "white" || it.RecommendedAction != "block_and_report" {
		t.Errorf("rich fields lost: %+v", it)
	}
	if _, err := os.Stat(filepath.Join(dir, "processed", "feed-1.zip")); err != nil {
		t.Errorf("zip not moved to processed/: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "feed-1.zip")); !os.IsNotExist(err) {
		t.Error("original zip should be gone")
	}
}

func TestDuplicateDeliveryNoDoubleCount(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	writeZip(t, filepath.Join(dir, "feed.zip"), map[string]string{"a.yaml": sampleYAML})
	w := newWatcher(store, dir)
	w.scanOnce()
	w.scanOnce() // 第二次已移走 -> 无新增
	if len(store.List()) != 1 {
		t.Fatalf("want 1 item, got %d", len(store.List()))
	}
}

func TestSameValueDifferentIDDeduped(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	body := `items:
- {id: otx-a, type: domain, value: dup.example.com, enabled: true}
- {id: otx-b, type: domain, value: dup.example.com, enabled: true}
`
	writeZip(t, filepath.Join(dir, "dup.zip"), map[string]string{"a.yaml": body})
	newWatcher(store, dir).scanOnce()
	if len(store.List()) != 1 {
		t.Fatalf("want 1 deduped item, got %d", len(store.List()))
	}
}

func TestBadZipGoesToFailed(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	bad := filepath.Join(dir, "broken.zip")
	if err := os.WriteFile(bad, []byte("this is not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	newWatcher(store, dir).scanOnce() // staleAfter=0 -> 立即判失败
	if len(store.List()) != 0 {
		t.Errorf("bad zip must not change rule set, got %d", len(store.List()))
	}
	if _, err := os.Stat(filepath.Join(dir, "failed", "broken.zip")); err != nil {
		t.Errorf("bad zip not moved to failed/: %v", err)
	}
}

func TestHalfWrittenSkippedThenImported(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	// 先造一个完整 zip，再截断成半写；用近期 mtime + 较大 staleAfter 使其被跳过
	full := filepath.Join(dir, "wip.zip")
	writeZip(t, full, map[string]string{"a.yaml": sampleYAML})
	data, _ := os.ReadFile(full)
	if err := os.WriteFile(full, data[:len(data)/2], 0o644); err != nil {
		t.Fatal(err)
	}
	w := New(store, dir, time.Second, 100000) // staleAfter 默认较大
	w.scanOnce()
	if len(store.List()) != 0 {
		t.Fatalf("half-written zip must be skipped, got %d", len(store.List()))
	}
	if _, err := os.Stat(full); err != nil {
		t.Fatalf("half-written zip should remain in place: %v", err)
	}
	// 补齐后再扫描
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatal(err)
	}
	w.scanOnce()
	if len(store.List()) != 1 {
		t.Fatalf("want 1 item after completion, got %d", len(store.List()))
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test ./internal/iocwatch/ -v`
Expected: FAIL（`New`/`Watcher`/`scanOnce`/`staleAfter` 未定义，无法编译）

- [ ] **Step 3: 实现 extract.go**

Create `internal/iocwatch/extract.go`:

```go
package iocwatch

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"ta_node/internal/intel"
)

// errIncomplete signals a zip that cannot be opened yet — treated as still
// being written by the gateway and retried on a later scan.
var errIncomplete = errors.New("zip incomplete")

// maxZipUncompressed caps total decompressed bytes read from a single zip to
// bound memory against a malformed or hostile archive.
const maxZipUncompressed = 256 << 20

// extractItems reads every *.yaml/*.yml entry in the zip and parses them as
// intel item files. A zip that fails to open returns errIncomplete; any other
// error (bad entry, oversized, malformed yaml) is returned as a hard failure.
func extractItems(path string, maxItems int) ([]intel.ThreatIntel, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, errIncomplete
	}
	defer zr.Close()

	var items []intel.ThreatIntel
	var total int64
	for _, f := range zr.File {
		name := strings.ToLower(f.Name)
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open entry %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxZipUncompressed-total+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read entry %s: %w", f.Name, err)
		}
		total += int64(len(data))
		if total > maxZipUncompressed {
			return nil, fmt.Errorf("zip %s exceeds %d bytes uncompressed", path, maxZipUncompressed)
		}
		var fy intel.File
		if err := yaml.Unmarshal(data, &fy); err != nil {
			return nil, fmt.Errorf("parse entry %s: %w", f.Name, err)
		}
		items = append(items, fy.Items...)
		if maxItems > 0 && len(items) > maxItems {
			items = items[:maxItems]
			break
		}
	}
	return items, nil
}
```

- [ ] **Step 4: 实现 watcher.go**

Create `internal/iocwatch/watcher.go`:

```go
package iocwatch

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"ta_node/internal/intel"
)

// Watcher polls dir for gateway-delivered *.zip IOC packs and merges their
// rules into the store. Processed packs move to dir/processed, unrecoverable
// ones to dir/failed; a pack that cannot be opened yet (still being written) is
// left in place and retried on the next scan until it grows stale.
type Watcher struct {
	store      *intel.Store
	dir        string
	interval   time.Duration
	maxItems   int
	staleAfter time.Duration
}

// New builds a Watcher. staleAfter (how long an unreadable zip may sit before
// it is treated as corrupt rather than half-written) defaults to max(2*interval,
// 30s).
func New(store *intel.Store, dir string, interval time.Duration, maxItems int) *Watcher {
	stale := 2 * interval
	if stale < 30*time.Second {
		stale = 30 * time.Second
	}
	return &Watcher{store: store, dir: dir, interval: interval, maxItems: maxItems, staleAfter: stale}
}

// Run scans immediately then every interval until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) {
	w.scanOnce()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.scanOnce()
		}
	}
}

func (w *Watcher) scanOnce() {
	paths, err := filepath.Glob(filepath.Join(w.dir, "*.zip"))
	if err != nil {
		log.Printf("iocwatch: glob %s failed: %v", w.dir, err)
		return
	}
	sort.Strings(paths)
	for _, p := range paths {
		if info, err := os.Stat(p); err != nil || info.IsDir() {
			continue
		}
		w.processZip(p)
	}
}

func (w *Watcher) processZip(path string) {
	items, err := extractItems(path, w.maxItems)
	if errors.Is(err, errIncomplete) {
		// Half-written: leave in place and retry — unless it has sat unreadable
		// long enough to be considered corrupt.
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > w.staleAfter {
			log.Printf("iocwatch: %s unreadable for >%s, moving to failed/", filepath.Base(path), w.staleAfter)
			w.moveTo(path, "failed")
		}
		return
	}
	if err != nil {
		log.Printf("iocwatch: %s parse failed: %v", filepath.Base(path), err)
		w.moveTo(path, "failed")
		return
	}
	if err := w.store.UpsertDedup(items); err != nil {
		log.Printf("iocwatch: %s upsert failed: %v", filepath.Base(path), err)
		w.moveTo(path, "failed")
		return
	}
	log.Printf("iocwatch: imported %d IOC items from %s", len(items), filepath.Base(path))
	w.moveTo(path, "processed")
}

// moveTo relocates path into dir/sub, creating it and suffixing on name clash so
// a re-delivered filename never overwrites an earlier pack.
func (w *Watcher) moveTo(path, sub string) {
	dst := filepath.Join(w.dir, sub)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		log.Printf("iocwatch: mkdir %s failed: %v", dst, err)
		return
	}
	target := filepath.Join(dst, filepath.Base(path))
	if _, err := os.Stat(target); err == nil {
		target = filepath.Join(dst, fmt.Sprintf("%d-%s", time.Now().UnixNano(), filepath.Base(path)))
	}
	if err := os.Rename(path, target); err != nil {
		log.Printf("iocwatch: move %s -> %s failed: %v", path, target, err)
	}
}
```

- [ ] **Step 5: 运行确认通过**

Run: `go test ./internal/iocwatch/ -v`
Expected: PASS（5 个用例全绿）

- [ ] **Step 6: 提交**

```bash
git add internal/iocwatch/
git commit -m "Add iocwatch component: poll gateway dir, extract and dedup IOC zips"
```

---

## Task 6: 接入 main.go 与配置示例

**Files:**
- Modify: `cmd/ta_node/main.go`
- Modify: `configs/ta_node.yaml`
- Modify: `configs/ta_node.offline.yaml`

**Interfaces:**
- Consumes: `iocwatch.New`/`Run`（Task 5）、`cfg.WatchInterval()`（Task 4）。

- [ ] **Step 1: 接入 main.go**

在 `cmd/ta_node/main.go` 的 import 块加 `"ta_node/internal/iocwatch"`（与其它 `ta_node/internal/...` 同组）。

在 `hotReload` goroutine 挂载处（`if cfg.Intel.EnableHotReload { go hotReload(...) }` 之后、`if cfg.Intel.PruneExpiredIntervalSec > 0` 之前）加：

```go
	if cfg.Intel.EnableIocWatch && cfg.Intel.IocWatchDir != "" {
		w := iocwatch.New(intelStore, cfg.Intel.IocWatchDir, cfg.WatchInterval(), cfg.Intel.MaxItems)
		go w.Run(ctx)
	}
```

- [ ] **Step 2: 编译确认**

Run: `go build ./cmd/ta_node`
Expected: 无输出（成功）

- [ ] **Step 3: 配置示例注释**

在 `configs/ta_node.yaml` 的 `intel:` 块末尾（`max_items` 行之后）加：

```yaml
  # 网闸投递的 IOC 规则 zip 落地目录。轮询发现新 *.zip -> 解析 items yaml ->
  # 去重后 upsert 进 intel_file，立即生效。处理完移入 <dir>/processed，坏包移入
  # <dir>/failed。设为 "" 关闭。
  ioc_watch_dir: "/data/yt/ioc"
  ioc_watch_interval_sec: 5
  enable_ioc_watch: true
```

在 `configs/ta_node.offline.yaml` 的 `intel:` 块做同样追加（离线部署同样启用）。

- [ ] **Step 4: 全量回归**

Run: `go build ./... && go test ./...`
Expected: 全部 PASS

- [ ] **Step 5: 端到端手工验证**

```bash
# 造一个测试目录与规则 zip
mkdir -p /tmp/ioc-e2e
printf 'items:\n- {id: e2e-1, type: domain, value: e2e.example.com, category: c2, severity: high, enabled: true}\n' > /tmp/rule.yaml
( cd /tmp && zip -j /tmp/ioc-e2e/feed.zip rule.yaml )
# 用最小配置只跑 config 服务 + watcher（指向该目录）
./ta_node --config ./configs/ta_node.yaml --config-only --intel-file /tmp/e2e-intel.yaml &
# 观察日志出现 "iocwatch: imported 1 IOC items from feed.zip"，
# 且 /tmp/ioc-e2e/processed/feed.zip 存在、/tmp/e2e-intel.yaml 含 e2e-1
```

Expected: 日志出现导入行；`processed/feed.zip` 存在；`intel-file` 含该条。
（注：`ioc_watch_dir` 在 config 里，`--config-only` 下 watcher 仍启动；如需改目录，编辑 config 的 `ioc_watch_dir` 为 `/tmp/ioc-e2e` 后再跑。）

- [ ] **Step 6: 提交**

```bash
git add cmd/ta_node/main.go configs/ta_node.yaml configs/ta_node.offline.yaml
git commit -m "Wire iocwatch into startup and document ioc_watch config"
```

---

## Self-Review 记录

- **Spec 覆盖**：§4 数据流→Task 5/6；§5 三层去重→Task 2(落库)+Task 5(批内/幂等)；§6.1→Task 1；§6.2→Task 3(event)；§6.3→Task 3(detector)；§6.4→Task 4；§7 组件→Task 5；§8 健壮性→Task 5(errIncomplete/failed/stale/move)；§9 测试→各 Task 测试步骤。无遗漏。
- **占位符**：无 TBD/TODO；所有代码步骤含完整代码。
- **类型一致性**：`UpsertDedup`、`Evidence`、`IOCEvidence`、`RecommendedAction`、`WatchInterval`、`New/Run/scanOnce/staleAfter/moveTo/extractItems/errIncomplete` 全程命名一致。
- **注意点**：`SchemaVersion` 从 1.2→1.3（Task 3 Step 3）；若 `engine_test.go` 用常量比较则不受影响。`ioc_watch_dir` 为绝对路径 `/data/yt/ioc`，E2E 验证需改指测试目录。
