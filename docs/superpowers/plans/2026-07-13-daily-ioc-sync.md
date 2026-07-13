# 每日定时增量同步 + 规则来源收敛 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 IOC 规则来源收敛为 intel 主文件一处，并用进程内定时器每天 01:00 从 `/data/yt/ioc` 增量取最多 10 条新规则加入主文件、清理 10 天前的 zip。

**Architecture:** 删除 `intel.Store` 的 overlay 双源（单源化）；把实时轮询组件 `internal/iocwatch` 改名 `internal/iocsync` 并用 `Syncer.SyncOnce`（扫 zip→按主文件去重→取前 10→`UpsertDedup`→清理旧 zip）替换 `Watcher`；主文件天然充当消费游标。

**Tech Stack:** Go 标准库（`archive/zip`/`time`/`path/filepath`）+ 已 vendor 的 `gopkg.in/yaml.v3`、`github.com/google/uuid`。无新增第三方依赖。

## Global Constraints

- 不新增任何第三方依赖（离线 vendor 构建）。
- 每个 task 结束 `go build ./...` 与相关 `go test` 必须通过；触碰的文件 `gofmt -l` 必须干净。
- 不改动富字段（`evidence`/`recommended_action`）与事件推送（schema 1.3 不变）。
- “新规则”判定用 canonical `type|规范化value`（复用 intel 的 canonical 逻辑）。
- zip 只读：除超期清理外不移动/不删除；无 `processed/`/`failed/` 目录。
- 不在进程启动时立即同步，只按 `ioc_sync_hour`(默认1) 的每日 01:00 触发。

---

## File Structure

- `internal/intel/store.go` — Modify：删除 overlay，单源化；导出 `CanonicalKey`。
- `internal/intel/file_loader.go` — Modify：删除已无用的 `LoadDir`/`loadConcurrency`。
- `internal/intel/overlay_test.go` — Delete。
- `internal/intel/store_test.go` — 不改（作为单源化回归门）。
- `internal/iocwatch/` → `internal/iocsync/` — Rename（Task 2）。
- `internal/iocsync/watcher.go` + `watcher_test.go` — Delete（Task 4）。
- `internal/iocsync/sync.go` — Create：`Syncer`/`SyncOnce`/`cleanupOldZips`/`NextDailyTime`。
- `internal/iocsync/sync_test.go` + `helpers_test.go` — Create。
- `internal/iocsync/extract.go` / `extract_test.go` — 随包改名，log 前缀改 `iocsync:`。
- `internal/config/config.go` — Modify：加 `ioc_sync_*`（Task 3）→ 删 `intel_dir`/`ioc_watch_*`/`WatchInterval`/`--intel-dir`（Task 5）。
- `internal/config/config_test.go` — Modify。
- `cmd/ta_node/main.go` — Modify：`NewStoreWithDir`→`NewStore`（Task 1）；换挂载为每日同步（Task 4）。
- `configs/ta_node.yaml` / `configs/ta_node.offline.yaml` / `configs/intel.d/` / `README.md` — Modify/Delete（Task 5）。

---

## Task 1: intel.Store 单源化（删除 overlay）

**Files:**
- Modify: `internal/intel/store.go`
- Modify: `internal/intel/file_loader.go`
- Delete: `internal/intel/overlay_test.go`
- Modify: `cmd/ta_node/main.go` (2 处 `NewStoreWithDir`→`NewStore`)

**Interfaces:**
- Produces: `intel.NewStore(path string) (*Store, error)`（唯一构造函数，`NewStoreWithDir` 删除）；导出 `intel.CanonicalKey(it ThreatIntel) string`（Task 3/4 的 iocsync 需要）。所有既有方法（`Add/Delete/Sync/UpsertMany/SyncSource/UpsertDedup/PruneExpired/Reload/List/Get/Stats/Version`）签名与语义不变，仅内部改为单 `items` map。

- [ ] **Step 1: 删除 overlay 测试并确认现有测试是回归门**

```bash
git rm internal/intel/overlay_test.go
go test ./internal/intel/ 2>&1 | tail -5   # 现在会因 store.go 仍引用 overlay 而编译通过（尚未改），overlay_test 删除后无 LoadDir 测试
```
Expected: 编译通过、其余测试 PASS（此步只删测试文件）。

- [ ] **Step 2: 重写 `internal/intel/store.go` 为单源**

用以下完整内容替换 `internal/intel/store.go`：

```go
package intel

import (
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Store holds the active IOC set, backed by a single writable file at path.
// Add/Delete/Sync/SyncSource/UpsertMany/UpsertDedup/PruneExpired all mutate the
// set and persist it atomically. items is the read view used for matching,
// List and Stats.
type Store struct {
	mu      sync.RWMutex
	items   map[string]ThreatIntel
	path    string
	version int64
}

// NewStore opens a store backed by a single writable file (path may be "").
func NewStore(path string) (*Store, error) {
	s := &Store{items: map[string]ThreatIntel{}, path: path}
	if path != "" {
		if err := s.Reload(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Reload() error {
	var loaded []ThreatIntel
	if s.path != "" {
		var err error
		loaded, err = LoadFile(s.path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			loaded = nil
		}
	}
	now := time.Now().Unix()
	items := make(map[string]ThreatIntel, len(loaded))
	for _, it := range loaded {
		normalize(&it, now)
		items[it.ID] = it
	}
	s.mu.Lock()
	s.items = items
	s.version++
	s.mu.Unlock()
	return nil
}

func (s *Store) List() []ThreatIntel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ThreatIntel, 0, len(s.items))
	for _, it := range s.items {
		out = append(out, it)
	}
	return out
}

func (s *Store) Get(id string) (ThreatIntel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	it, ok := s.items[id]
	return it, ok
}

func (s *Store) Version() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func (s *Store) Add(it ThreatIntel) (ThreatIntel, error) {
	now := time.Now().Unix()
	normalize(&it, now)
	s.mu.Lock()
	s.items[it.ID] = it
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return it, SaveFileAtomic(s.path, saved)
	}
	return it, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	if _, ok := s.items[id]; !ok {
		s.mu.Unlock()
		return errors.New("intel not found")
	}
	delete(s.items, id)
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, saved)
	}
	return nil
}

func (s *Store) Sync(items []ThreatIntel) error {
	now := time.Now().Unix()
	next := map[string]ThreatIntel{}
	for _, it := range items {
		normalize(&it, now)
		next[it.ID] = it
	}
	s.mu.Lock()
	s.items = next
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, saved)
	}
	return nil
}

func (s *Store) UpsertMany(items []ThreatIntel) error {
	now := time.Now().Unix()
	s.mu.Lock()
	for _, it := range items {
		createdAt := it.CreatedAt
		normalize(&it, now)
		if existing, ok := s.items[it.ID]; ok && createdAt == 0 {
			it.CreatedAt = existing.CreatedAt
		}
		s.items[it.ID] = it
	}
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, saved)
	}
	return nil
}

func (s *Store) SyncSource(source string, items []ThreatIntel) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return errors.New("source required")
	}
	now := time.Now().Unix()
	normalized := make([]ThreatIntel, 0, len(items))
	for _, it := range items {
		it.Source = source
		normalize(&it, now)
		normalized = append(normalized, it)
	}
	s.mu.Lock()
	for id, it := range s.items {
		if it.Source == source {
			delete(s.items, id)
		}
	}
	for _, it := range normalized {
		s.items[it.ID] = it
	}
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, saved)
	}
	return nil
}

func (s *Store) Stats() StoreStats {
	now := time.Now().Unix()
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := StoreStats{
		Total:    len(s.items),
		ByType:   map[string]int{},
		BySource: map[string]int{},
		Version:  s.version,
	}
	for _, it := range s.items {
		if it.Enabled {
			stats.Enabled++
		}
		if it.ExpireAt > 0 && it.ExpireAt < now {
			stats.Expired++
		}
		stats.ByType[strings.ToLower(it.Type)]++
		stats.BySource[it.Source]++
		if it.UpdatedAt > stats.LastUpdatedAt {
			stats.LastUpdatedAt = it.UpdatedAt
		}
	}
	return stats
}

func (s *Store) PruneExpired(now int64) int {
	s.mu.Lock()
	deleted := 0
	for id, it := range s.items {
		if it.ExpireAt > 0 && it.ExpireAt < now {
			delete(s.items, id)
			deleted++
		}
	}
	if deleted == 0 {
		s.mu.Unlock()
		return 0
	}
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		if err := SaveFileAtomic(s.path, saved); err != nil {
			return deleted
		}
	}
	return deleted
}

func (s *Store) snapshotLocked() []ThreatIntel {
	items := make([]ThreatIntel, 0, len(s.items))
	for _, item := range s.items {
		items = append(items, item)
	}
	return items
}

func normalize(it *ThreatIntel, now int64) {
	it.Type = strings.ToLower(strings.TrimSpace(it.Type))
	it.Value = strings.TrimSpace(it.Value)
	it.Source = strings.TrimSpace(it.Source)
	if it.ID == "" {
		it.ID = "ioc-" + uuid.NewString()
	}
	if it.Source == "" {
		it.Source = "local"
	}
	if it.Severity == "" {
		it.Severity = "medium"
	}
	if it.CreatedAt == 0 {
		it.CreatedAt = now
	}
	it.UpdatedAt = now
}

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

// CanonicalKey identifies an IOC by (type, normalized value) rather than id, so
// the same indicator delivered under different feed ids is deduped. Exported so
// the iocsync feed can dedup candidates against the store.
func CanonicalKey(it ThreatIntel) string {
	return strings.ToLower(strings.TrimSpace(it.Type)) + "|" + canonicalValue(it.Type, it.Value)
}

// UpsertDedup merges a feed batch into the set with (type,value) dedup:
//   - within the batch, entries with the same canonical key collapse, keeping
//     the one with the newest incoming updated_at;
//   - against the existing set, an incoming entry whose canonical key already
//     exists reuses that entry's id (in-place update) instead of adding a
//     duplicate row for the same indicator.
//
// It bumps the version (matcher picks it up on the next packet) and persists
// atomically. An empty effective batch is a no-op.
func (s *Store) UpsertDedup(items []ThreatIntel) error {
	batch := map[string]ThreatIntel{}
	for _, it := range items {
		k := CanonicalKey(it)
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
		existing[CanonicalKey(it)] = id
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
		s.items[it.ID] = it
	}
	s.version++
	saved := s.snapshotLocked()
	s.mu.Unlock()
	if s.path != "" {
		return SaveFileAtomic(s.path, saved)
	}
	return nil
}
```

- [ ] **Step 3: 删除 `file_loader.go` 里已无用的 `LoadDir`/`loadConcurrency`**

在 `internal/intel/file_loader.go` 中删除 `LoadDir` 函数（第 26-70 行区域）和 `loadConcurrency`（第 72-81 行区域），并把 import 收敛为仅剩用到的：

```go
import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)
```

（`LoadFile`、`SaveFile`、`SaveFileAtomic`、`SaveFileAtomicBytes` 保留。删除后 `fmt`/`runtime`/`sort`/`sync` 不再被引用。）

- [ ] **Step 4: 更新 main.go 两处构造**

`cmd/ta_node/main.go`：把两处 `intel.NewStoreWithDir(cfg.Intel.IntelFile, cfg.Intel.IntelDir)`（约 54 行与 222 行）改为：

```go
intel.NewStore(cfg.Intel.IntelFile)
```

- [ ] **Step 5: 编译 + 回归测试**

Run:
```bash
go build ./... && go test ./internal/intel/ ./internal/detector/ -v 2>&1 | tail -20
gofmt -l internal/intel/store.go internal/intel/file_loader.go cmd/ta_node/main.go
```
Expected: build 成功；`internal/intel` 现有用例（`TestStoreSyncSourceUpsertStatsAndPrune`、`TestUpsertDedup*`）全部 PASS；detector PASS；gofmt 无输出。

- [ ] **Step 6: 提交**

```bash
git add internal/intel/store.go internal/intel/file_loader.go cmd/ta_node/main.go
git rm internal/intel/overlay_test.go
git commit -m "Make intel.Store single-source; remove overlay and NewStoreWithDir"
```

---

## Task 2: 包改名 internal/iocwatch → internal/iocsync

**Files:**
- Rename: `internal/iocwatch/` → `internal/iocsync/`
- Modify: `internal/iocsync/*.go`（package 名 + log 前缀）
- Modify: `cmd/ta_node/main.go`（import + `iocwatch.`→`iocsync.`）

**Interfaces:**
- 纯改名，行为不变。改名后 `iocsync.New(...) *Watcher` 与 `(*Watcher).Run` 仍是实时轮询（临时保留，Task 4 删除）。

- [ ] **Step 1: 目录改名**

```bash
git mv internal/iocwatch internal/iocsync
```

- [ ] **Step 2: 改包名与日志前缀**

在 `internal/iocsync/extract.go`、`watcher.go`、`extract_test.go`、`watcher_test.go` 中：
- 把首行 `package iocwatch` 改为 `package iocsync`。
- 把所有日志前缀字符串 `"iocwatch:` 改为 `"iocsync:`（`extract.go` 1 处、`watcher.go` 多处）。

```bash
grep -rl 'package iocwatch' internal/iocsync | xargs sed -i 's/package iocwatch/package iocsync/'
grep -rl '"iocwatch:' internal/iocsync | xargs sed -i 's/"iocwatch:/"iocsync:/g'
```

- [ ] **Step 3: 更新 main.go 引用**

`cmd/ta_node/main.go`：
- import 组里 `"ta_node/internal/iocwatch"` → `"ta_node/internal/iocsync"`。
- 挂载处 `iocwatch.New(...)` → `iocsync.New(...)`（其余不变）。

- [ ] **Step 4: 编译 + 测试**

Run:
```bash
go build ./... && go test ./internal/iocsync/ 2>&1 | tail -10
gofmt -l internal/iocsync/*.go cmd/ta_node/main.go
```
Expected: build 成功；iocsync 现有 6 个测试 PASS；gofmt 无输出。

- [ ] **Step 5: 提交**

```bash
git add -A internal/iocsync cmd/ta_node/main.go
git commit -m "Rename internal/iocwatch package to internal/iocsync"
```

---

## Task 3: 新增 ioc_sync_* 配置（保留旧字段，纯增量）

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Interfaces:**
- Produces: `IntelConfig.IocSyncDir string`、`EnableIocSync bool`、`IocSyncHour int`、`IocSyncDailyLimit int`、`IocSyncRetainDays int`，及各自默认值。Task 4 使用。

- [ ] **Step 1: 写失败测试**

在 `internal/config/config_test.go` 追加：

```go
func TestDefaultIocSync(t *testing.T) {
	c := Default()
	if c.Intel.IocSyncDir != "/data/yt/ioc" {
		t.Errorf("ioc_sync_dir default: %q", c.Intel.IocSyncDir)
	}
	if !c.Intel.EnableIocSync {
		t.Error("enable_ioc_sync default should be true")
	}
	if c.Intel.IocSyncHour != 1 {
		t.Errorf("ioc_sync_hour default: %d", c.Intel.IocSyncHour)
	}
	if c.Intel.IocSyncDailyLimit != 10 {
		t.Errorf("ioc_sync_daily_limit default: %d", c.Intel.IocSyncDailyLimit)
	}
	if c.Intel.IocSyncRetainDays != 10 {
		t.Errorf("ioc_sync_retain_days default: %d", c.Intel.IocSyncRetainDays)
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test ./internal/config/ -run TestDefaultIocSync -v`
Expected: FAIL（字段未定义）

- [ ] **Step 3: 加字段与默认值**

`internal/config/config.go` 的 `IntelConfig` 结构体末尾（现有 `EnableIocWatch` 之后）追加：

```go
	IocSyncDir        string `json:"ioc_sync_dir" yaml:"ioc_sync_dir"`
	EnableIocSync     bool   `json:"enable_ioc_sync" yaml:"enable_ioc_sync"`
	IocSyncHour       int    `json:"ioc_sync_hour" yaml:"ioc_sync_hour"`
	IocSyncDailyLimit int    `json:"ioc_sync_daily_limit" yaml:"ioc_sync_daily_limit"`
	IocSyncRetainDays int    `json:"ioc_sync_retain_days" yaml:"ioc_sync_retain_days"`
```

`Default()` 的 `Intel: IntelConfig{...}` 块末尾（现有 `EnableIocWatch: true,` 之后）追加：

```go
			IocSyncDir:        "/data/yt/ioc",
			EnableIocSync:     true,
			IocSyncHour:       1,
			IocSyncDailyLimit: 10,
			IocSyncRetainDays: 10,
```

- [ ] **Step 4: 运行确认通过**

Run: `go test ./internal/config/ -v 2>&1 | tail -15 && gofmt -l internal/config/config.go internal/config/config_test.go`
Expected: PASS（含旧 `TestDefaultIocWatch` 仍在、也 PASS）；gofmt 无输出。

- [ ] **Step 5: 提交**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "Add ioc_sync_* config fields (daily sync) alongside legacy ioc_watch"
```

---

## Task 4: 功能切换 — Syncer + 每日调度，删除实时 Watcher

**Files:**
- Create: `internal/iocsync/sync.go`
- Create: `internal/iocsync/sync_test.go`
- Create: `internal/iocsync/helpers_test.go`
- Delete: `internal/iocsync/watcher.go`, `internal/iocsync/watcher_test.go`
- Modify: `cmd/ta_node/main.go`

**Interfaces:**
- Consumes: `intel.NewStore`、`intel.CanonicalKey`、`intel.Store.UpsertDedup`、`extractItems`（本包）。
- Produces: `iocsync.New(store *intel.Store, dir string, dailyLimit, retainDays, maxItems int) *Syncer`、`(*Syncer).SyncOnce() (int, error)`、`iocsync.NextDailyTime(now time.Time, hour int) time.Time`。

- [ ] **Step 1: 写测试文件（先失败）**

Create `internal/iocsync/helpers_test.go`（把 writeZip 从将被删除的 watcher_test.go 迁到此处）：

```go
package iocsync

import (
	"archive/zip"
	"os"
	"testing"
)

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
```

Create `internal/iocsync/sync_test.go`：

```go
package iocsync

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// zipWith builds a zip whose rules.yaml lists n domain IOCs starting at `from`.
func zipWith(t *testing.T, path string, from, n int) {
	t.Helper()
	var b strings.Builder
	b.WriteString("items:\n")
	for i := from; i < from+n; i++ {
		fmt.Fprintf(&b, "- {id: gw-%d, type: domain, value: d%d.example.com, category: c2, enabled: true}\n", i, i)
	}
	writeZip(t, path, map[string]string{"rules.yaml": b.String()})
}

func TestSyncOnceLimitsToDaily(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	zipWith(t, filepath.Join(dir, "a.zip"), 0, 25)
	s := New(store, dir, 10, 10, 100000)
	added, err := s.SyncOnce()
	if err != nil {
		t.Fatal(err)
	}
	if added != 10 || len(store.List()) != 10 {
		t.Fatalf("want 10 added/total, got added=%d total=%d", added, len(store.List()))
	}
}

func TestSyncOnceCursorContinuesNextDay(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	zipWith(t, filepath.Join(dir, "a.zip"), 0, 25)
	s := New(store, dir, 10, 10, 100000)
	// day 1: +10, day 2: +10 (next batch, since first 10 now in main file), day 3: +5
	if a, _ := s.SyncOnce(); a != 10 {
		t.Fatalf("day1 added=%d", a)
	}
	if a, _ := s.SyncOnce(); a != 10 {
		t.Fatalf("day2 added=%d", a)
	}
	if a, _ := s.SyncOnce(); a != 5 {
		t.Fatalf("day3 added=%d", a)
	}
	if a, _ := s.SyncOnce(); a != 0 {
		t.Fatalf("day4 added=%d (all consumed)", a)
	}
	if len(store.List()) != 25 {
		t.Fatalf("want 25 total, got %d", len(store.List()))
	}
}

func TestSyncOnceDedupsAcrossCandidates(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	// same value under two ids -> counts as one toward the limit
	body := "items:\n" +
		"- {id: a, type: domain, value: dup.example.com, enabled: true}\n" +
		"- {id: b, type: domain, value: DUP.example.com., enabled: true}\n"
	writeZip(t, filepath.Join(dir, "a.zip"), map[string]string{"r.yaml": body})
	s := New(store, dir, 10, 10, 100000)
	added, _ := s.SyncOnce()
	if added != 1 || len(store.List()) != 1 {
		t.Fatalf("want 1 deduped, got added=%d total=%d", added, len(store.List()))
	}
}

func TestSyncOnceInsufficient(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	zipWith(t, filepath.Join(dir, "a.zip"), 0, 4)
	s := New(store, dir, 10, 10, 100000)
	added, _ := s.SyncOnce()
	if added != 4 {
		t.Fatalf("want 4 added, got %d", added)
	}
}

func TestSyncOnceBadZipSkipped(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	if err := os.WriteFile(filepath.Join(dir, "bad.zip"), []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipWith(t, filepath.Join(dir, "good.zip"), 0, 3)
	s := New(store, dir, 10, 10, 100000)
	added, err := s.SyncOnce()
	if err != nil {
		t.Fatalf("SyncOnce should not fail on a bad zip: %v", err)
	}
	if added != 3 {
		t.Fatalf("want 3 added from good zip, got %d", added)
	}
	// bad zip stays (retain window not exceeded), good zip stays too
	if _, err := os.Stat(filepath.Join(dir, "bad.zip")); err != nil {
		t.Errorf("bad zip should remain in place: %v", err)
	}
}

func TestCleanupRemovesOldZips(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t)
	old := filepath.Join(dir, "old.zip")
	recent := filepath.Join(dir, "recent.zip")
	zipWith(t, old, 0, 1)
	zipWith(t, recent, 100, 1)
	past := time.Now().AddDate(0, 0, -15)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	recentT := time.Now().AddDate(0, 0, -5)
	if err := os.Chtimes(recent, recentT, recentT); err != nil {
		t.Fatal(err)
	}
	s := New(store, dir, 10, 10, 100000)
	if _, err := s.SyncOnce(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("15-day-old zip should have been removed")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Error("5-day-old zip should remain")
	}
}

func TestNextDailyTime(t *testing.T) {
	loc := time.UTC
	mk := func(h, m int) time.Time { return time.Date(2026, 7, 13, h, m, 0, 0, loc) }
	cases := []struct {
		now      time.Time
		wantDay  int
		wantHour int
	}{
		{mk(0, 30), 13, 1},  // before 1am -> today 1am
		{mk(1, 0), 14, 1},   // exactly 1am -> next day (strictly after)
		{mk(13, 0), 14, 1},  // after 1am -> next day
	}
	for _, c := range cases {
		got := NextDailyTime(c.now, 1)
		if got.Day() != c.wantDay || got.Hour() != c.wantHour || got.Minute() != 0 {
			t.Errorf("NextDailyTime(%v,1)=%v, want day=%d hour=%d", c.now, got, c.wantDay, c.wantHour)
		}
	}
}
```

Also delete the old watcher tests so writeZip isn't redeclared and Watcher references vanish:

```bash
git rm internal/iocsync/watcher.go internal/iocsync/watcher_test.go
```

- [ ] **Step 2: 运行确认失败**

Run: `go test ./internal/iocsync/ 2>&1 | tail -15`
Expected: FAIL/编译错误（`New`/`Syncer`/`SyncOnce`/`NextDailyTime` 未定义；watcher 已删）。

- [ ] **Step 3: 实现 `internal/iocsync/sync.go`**

Create `internal/iocsync/sync.go`：

```go
package iocsync

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"ta_node/internal/intel"
)

// Syncer performs the daily incremental IOC sync: it scans dir for gateway
// *.zip packs, adds up to dailyLimit rules not already in the store, then
// removes zips older than retainDays. The store's own dedup (by canonical
// type/value) makes the main file the consumption cursor.
type Syncer struct {
	store      *intel.Store
	dir        string
	dailyLimit int
	retainDays int
	maxItems   int
}

func New(store *intel.Store, dir string, dailyLimit, retainDays, maxItems int) *Syncer {
	return &Syncer{store: store, dir: dir, dailyLimit: dailyLimit, retainDays: retainDays, maxItems: maxItems}
}

// SyncOnce scans dir, imports up to dailyLimit "new" IOCs (canonical key not in
// the main file) into the store, then prunes zips older than retainDays. It
// returns the number of IOCs added. Bad/half-written zips are logged and
// skipped; a scan error never shrinks the rule set.
func (s *Syncer) SyncOnce() (int, error) {
	paths, err := filepath.Glob(filepath.Join(s.dir, "*.zip"))
	if err != nil {
		return 0, err
	}
	sort.Strings(paths)

	// The main file is the cursor: an IOC already present is not "new".
	seen := map[string]bool{}
	for _, it := range s.store.List() {
		seen[intel.CanonicalKey(it)] = true
	}

	var candidates []intel.ThreatIntel
	scanned := 0
	for _, p := range paths {
		if s.dailyLimit > 0 && len(candidates) >= s.dailyLimit {
			break
		}
		if info, statErr := os.Stat(p); statErr != nil || info.IsDir() {
			continue
		}
		items, exErr := extractItems(p, s.maxItems)
		if exErr != nil {
			log.Printf("iocsync: skip %s: %v", filepath.Base(p), exErr)
			continue
		}
		scanned++
		for _, it := range items {
			if s.dailyLimit > 0 && len(candidates) >= s.dailyLimit {
				break
			}
			k := intel.CanonicalKey(it)
			if seen[k] {
				continue
			}
			seen[k] = true
			candidates = append(candidates, it)
		}
	}

	if len(candidates) > 0 {
		if err := s.store.UpsertDedup(candidates); err != nil {
			return 0, err
		}
	}
	removed := s.cleanupOldZips(time.Now())
	log.Printf("iocsync: added %d new IOC(s) from %d zip(s); removed %d expired zip(s)", len(candidates), scanned, removed)
	return len(candidates), nil
}

// cleanupOldZips removes *.zip in dir whose mtime is older than retainDays.
func (s *Syncer) cleanupOldZips(now time.Time) int {
	if s.retainDays <= 0 {
		return 0
	}
	paths, err := filepath.Glob(filepath.Join(s.dir, "*.zip"))
	if err != nil {
		return 0
	}
	cutoff := now.AddDate(0, 0, -s.retainDays)
	removed := 0
	for _, p := range paths {
		info, statErr := os.Stat(p)
		if statErr != nil || info.IsDir() {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(p); err != nil {
				log.Printf("iocsync: remove old zip %s failed: %v", filepath.Base(p), err)
				continue
			}
			removed++
		}
	}
	return removed
}

// NextDailyTime returns the next local time strictly after now at hour:00,
// used by the scheduler to fire once per day.
func NextDailyTime(now time.Time, hour int) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}
```

- [ ] **Step 4: 运行 iocsync 测试通过**

Run: `go test ./internal/iocsync/ -v 2>&1 | tail -25 && gofmt -l internal/iocsync/*.go`
Expected: 全部 PASS（含 extract_test.go 复用 writeZip）；gofmt 无输出。

- [ ] **Step 5: main.go 换挂载 + 每日调度器**

`cmd/ta_node/main.go`：

(a) 把现有实时挂载块（约 83-84 行）：

```go
	if cfg.Intel.EnableIocWatch && cfg.Intel.IocWatchDir != "" {
		w := iocsync.New(intelStore, cfg.Intel.IocWatchDir, cfg.WatchInterval(), cfg.Intel.MaxItems)
		go w.Run(ctx)
	}
```

替换为：

```go
	if cfg.Intel.EnableIocSync && cfg.Intel.IocSyncDir != "" {
		syncer := iocsync.New(intelStore, cfg.Intel.IocSyncDir, cfg.Intel.IocSyncDailyLimit, cfg.Intel.IocSyncRetainDays, cfg.Intel.MaxItems)
		go runDailyIOCSync(ctx, syncer, cfg.Intel.IocSyncHour)
	}
```

(b) 在 `hotReload` 函数附近新增：

```go
// runDailyIOCSync fires Syncer.SyncOnce once per day at hour:00 (local time).
func runDailyIOCSync(ctx context.Context, s *iocsync.Syncer, hour int) {
	for {
		timer := time.NewTimer(time.Until(iocsync.NextDailyTime(time.Now(), hour)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			if added, err := s.SyncOnce(); err != nil {
				log.Printf("iocsync failed: %v", err)
			} else if added > 0 {
				log.Printf("iocsync: added %d new IOC(s)", added)
			}
		}
	}
}
```

- [ ] **Step 6: 编译 + 全量测试**

Run:
```bash
go build ./... && go test ./... 2>&1 | grep -E "FAIL|ok .*iocsync|ok .*intel|ok .*config" 
gofmt -l cmd/ta_node/main.go
```
Expected: build 成功；无 FAIL；gofmt 无输出。
（注：此时 `cfg.WatchInterval()`/`EnableIocWatch`/`IocWatchDir` 已不再被引用，但字段/方法仍在 config 中——Task 5 清理。）

- [ ] **Step 7: 提交**

```bash
git add -A internal/iocsync cmd/ta_node/main.go
git commit -m "Replace realtime watcher with daily Syncer (10 new IOCs/day + zip cleanup)"
```

---

## Task 5: 清理旧配置/旗标 + 配置文件 + 文档

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`
- Modify: `configs/ta_node.yaml`, `configs/ta_node.offline.yaml`
- Delete: `configs/intel.d/`
- Modify: `README.md`

**Interfaces:** 无新增；删除死字段/旗标。

- [ ] **Step 1: 删除旧配置字段/默认/旗标/方法**

`internal/config/config.go`：
- `IntelConfig` 删除四个字段：`IntelDir`、`IocWatchDir`、`IocWatchIntervalSec`、`EnableIocWatch`。
- `Default()` 删除对应四个默认值行：`IntelDir: "./configs/intel.d",`、`IocWatchDir: "/data/yt/ioc",`、`IocWatchIntervalSec: 5,`、`EnableIocWatch: true,`。
- 删除 `--intel-dir` 旗标：`LoadWithFlags` 中 `intelDir := fs.String("intel-dir", ...)` 一行，以及 `if *intelDir != "" { cfg.Intel.IntelDir = *intelDir }` 两行。
- 删除 `WatchInterval()` 方法（约 249-251 行）。

`internal/config/config_test.go`：删除 `TestDefaultIocWatch`（引用了已删字段）。

- [ ] **Step 2: 编译 + 测试**

Run:
```bash
go build ./... && go test ./internal/config/ -v 2>&1 | tail -10
gofmt -l internal/config/config.go internal/config/config_test.go
```
Expected: build 成功；`TestDefaultIocSync`（及其它）PASS；gofmt 无输出。

- [ ] **Step 3: 配置文件切换**

`configs/ta_node.yaml` 的 `intel:` 块：删除 `intel_dir:` 行及其注释、删除 `ioc_watch_dir`/`ioc_watch_interval_sec`/`enable_ioc_watch` 三行及注释；追加：

```yaml
  # 每日定时从下述目录增量同步 IOC 规则到 intel_file（主文件即唯一规则来源）。
  ioc_sync_dir: "/data/yt/ioc"    # 网闸投递的规则 zip 目录；设 "" 关闭
  enable_ioc_sync: true
  ioc_sync_hour: 1                # 每天触发时刻（本地时，0-23）
  ioc_sync_daily_limit: 10        # 每天最多新增条数
  ioc_sync_retain_days: 10        # 删除该目录内早于 N 天的 zip
```

对 `configs/ta_node.offline.yaml` 的 `intel:` 块做同样修改。

- [ ] **Step 4: 删除 overlay 目录**

```bash
git rm -r configs/intel.d
```

- [ ] **Step 5: 更新 README**

`README.md`：删除标题 “### Splitting and incrementally adding IOCs” 及其整段（讲 `intel.d` overlay 的内容）。在 intel 说明处加一段：

```markdown
### 每日定时增量同步（网闸投递）

节点每天 `ioc_sync_hour`（默认 01:00）从 `ioc_sync_dir`（默认 `/data/yt/ioc`）下的
`*.zip` 中，取最多 `ioc_sync_daily_limit`（默认 10）条“新”规则（按 type+value 判断，
已在主文件的跳过）增量写入 `intel_file`，主文件即唯一规则来源与消费游标。随后删除该
目录内 mtime 早于 `ioc_sync_retain_days`（默认 10）天的 zip。zip 从不被移动，仅按保留期清理。
```

- [ ] **Step 6: 全量验证**

Run:
```bash
go build ./... && go test ./... 2>&1 | tail -20
grep -rn "IntelDir\|IocWatch\|WatchInterval\|intel_dir\|intel\.d" internal/ cmd/ configs/ || echo "no stale references"
```
Expected: 全绿；无残留引用（README 里的历史说明已删）。

- [ ] **Step 7: 提交**

```bash
git add -A internal/config configs README.md
git commit -m "Remove intel_dir/ioc_watch config, drop intel.d overlay, document daily sync"
```

---

## Self-Review 记录

- **Spec 覆盖**：§4.3 单源 Store→Task 1；§4.1 iocsync/extract 复用+改名→Task 2/4；§4.1 Syncer/SyncOnce/cleanup→Task 4；§4.2 调度→Task 4；§4.4 配置→Task 3(加)+Task 5(删)；§4.5 server 无需改（已核对，未纳入任务）；§4.6 配置文件/intel.d/README→Task 5；§6 测试→各 Task；§3 语义（限额10/主文件游标/坏zip跳过/清理）→Task 4 测试。
- **占位符**：无 TBD/TODO；代码步骤均含完整代码。
- **类型/命名一致**：`NewStore`、`CanonicalKey`（导出）、`UpsertDedup`、`Syncer`、`SyncOnce`、`NextDailyTime`、`runDailyIOCSync`、`ioc_sync_*` 字段全程一致。
- **构建绿链**：Task1(改 main 用 NewStore)→Task2(改名，行为不变)→Task3(加新配置，旧留)→Task4(切换代码+删watcher，新配置就绪)→Task5(删死配置+文档)。每步可编译。
- **writeZip 迁移**：Task 4 新增 `helpers_test.go` 持有 writeZip，同任务 `git rm watcher_test.go`（原 writeZip 所在），避免重复定义；extract_test.go 继续复用。
