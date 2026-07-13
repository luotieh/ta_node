# 规则来源收敛 + 每日定时增量同步 — 设计文档

- 日期：2026-07-13
- 状态：待评审
- 取代/修改：`docs/superpowers/specs/2026-07-10-gateway-ioc-zip-watch-design.md`（实时监听改为每日定时；移除 overlay）
- 关联代码：`internal/intel`、`internal/iocwatch`（改名为 `internal/iocsync`）、`internal/config`、`internal/server`、`cmd/ta_node/main.go`、`configs/*`、`README.md`

## 1. 目标

1. **规则来源只保留 intel 主文件**（`intel.intel_file`）。移除 `intel_dir`（overlay）与实时 `iocwatch` 轮询。
2. **每天凌晨 01:00**，从 `/data/yt/ioc` 内的 `*.zip` 中**增量取最多 10 条“新规则”**加入主文件。
3. **每天清理** `/data/yt/ioc` 内 **mtime 早于 10 天** 的 zip。

## 2. 设计决策（已与用户确认）

| 决策点 | 选择 |
|---|---|
| 取数语义 | 限额 10，**主文件做游标**：“新” = canonical `type|value` 不在主文件；每次全量扫描去重后取前 10 条 |
| 调度 | **进程内定时器**（下一个 01:00 触发，触发后重算次日；不在启动时立即跑） |
| 来源收敛 | **彻底删除** overlay（`intel_dir`）与实时 `iocwatch` 轮询 |
| Store overlay | **彻底删除** overlay 代码（三 map 简化为单源；删 `overlay_test.go`；`NewStoreWithDir`→`NewStore`） |
| 旧 zip | **清理 10 天前** 的 zip（作为每日任务的一部分） |

## 3. 关键语义

- **“新”的判定**：canonical key `type|规范化value`（复用 `intel.canonicalKey`）不在当前主文件里。
- **取数顺序**（确定、可复现）：zip 按文件名排序 → zip 内按 entry 顺序 → yaml 内按 `items` 顺序；对候选逐条判断，跳过“已在主文件”或“本批已选过同 canonical key”者，累计到 `daily_limit`(10) 即止。
- **zip 只读、不移动/不删除（除超期清理外）**：`/data/yt/ioc` 视为网闸单向只读投递目录。已入主文件的规则次日被去重自然跳过，剩余的继续被取——主文件天然充当消费游标。**不再有 `processed/`、`failed/` 子目录。**
- **坏 / 半写 zip**：`extractItems` 打不开或解析失败 → 只 log 跳过、不移动，次日重试。
- **不足 10 / 为 0**：有几条加几条；为 0 则 log 跳过。
- **清理**：同步完成后，删除 `dir` 内 mtime 早于 `retain_days`(10) 天的 `*.zip`。
  - 注意（已知取舍）：若某 zip 内还有未消费的规则但已超期，会随该 zip 一并被删、不再进入候选池。`retain_days` 与 `daily_limit` 的配比由运维按投递量调整。

## 4. 组件设计

### 4.1 `internal/iocsync`（由 `internal/iocwatch` 改名）

- **保留 `extract.go`**（`extractItems`、`errIncomplete`、`maxZipUncompressed`）——zip→`[]intel.ThreatIntel` 解析逻辑复用。`maxItems` 参数继续作为单个 zip 的内存上限（传 `intel.max_items`）。
- **删除 `watcher.go`**（实时轮询 `Watcher`/`Run`/`scanOnce`/`moveTo`）及其 `watcher_test.go` 里针对 processed/failed/半写归档的用例。
- **新增 `sync.go`**：

```go
type Syncer struct {
    store      *intel.Store
    dir        string
    dailyLimit int
    retainDays int
    maxItems   int
}

func New(store *intel.Store, dir string, dailyLimit, retainDays, maxItems int) *Syncer

// SyncOnce 扫描 dir 内所有 zip，取最多 dailyLimit 条“新”规则增量写入主文件，
// 然后清理超过 retainDays 天的旧 zip。返回本次新增条数。
func (s *Syncer) SyncOnce() (added int, err error)
```

`SyncOnce` 逻辑：
1. `filepath.Glob(dir/*.zip)`，排序。
2. 逐个 `extractItems`（坏 zip 只 log 跳过）；按序汇总所有 items。
3. 构建主文件 canonical 集合：`store.List()` → `set[canonicalKey]`。
4. 顺序遍历汇总 items，跳过已在 `set` 或本批已选（`seen`）者，累计候选到 `dailyLimit` 即止。
5. `store.UpsertDedup(candidates)`（增量写主文件、bump version、matcher 立即生效）。
6. `cleanupOldZips(now)`：删除 mtime 早于 `retainDays` 天的 zip。
7. log：`iocsync: added N new IOC(s) from <M> zip(s); removed K expired zip(s)`。

### 4.2 定时调度（`cmd/ta_node/main.go`）

与 `hotReload`/`pruneExpired` 同风格的 goroutine：

```go
func runDailyIOCSync(ctx context.Context, s *iocsync.Syncer, hour int) {
    for {
        next := nextDailyTime(time.Now(), hour) // 下一个 hour:00
        timer := time.NewTimer(time.Until(next))
        select {
        case <-ctx.Done():
            timer.Stop()
            return
        case <-timer.C:
            if added, err := s.SyncOnce(); err != nil {
                log.Printf("iocsync failed: %v", err)
            } else {
                log.Printf("iocsync: added %d new IOC(s)", added)
            }
        }
    }
}

// nextDailyTime 返回严格晚于 now 的下一个当地时间 hour:00。
func nextDailyTime(now time.Time, hour int) time.Time
```

挂载（替换原 iocwatch 挂载处）：

```go
if cfg.Intel.EnableIocSync && cfg.Intel.IocSyncDir != "" {
    s := iocsync.New(intelStore, cfg.Intel.IocSyncDir,
        cfg.Intel.IocSyncDailyLimit, cfg.Intel.IocSyncRetainDays, cfg.Intel.MaxItems)
    go runDailyIOCSync(ctx, s, cfg.Intel.IocSyncHour)
}
```

### 4.3 `internal/intel/store.go` — 移除 overlay，单源化

- `Store` 字段简化为：`mu`、`items map[string]ThreatIntel`、`path`、`version`（删除 `primary`、`overlay`、`dir`）。
- 删除 `NewStoreWithDir`；`NewStore(path)` 直接加载 `path`→`items`。
- `Reload()`：只读 `path`。
- `Delete`：删除 overlay 只读分支，直接从 `items` 删。
- `Sync`/`UpsertMany`/`SyncSource`/`PruneExpired`/`UpsertDedup`：去掉 overlay 循环，直接操作 `items`。
- 删除 `rebuildItemsLocked`（无合并）；`snapshotLocked` 返回 `items` 值。
- 删除 `internal/intel/overlay_test.go`。
- `canonicalKey`/`canonicalValue`/`UpsertDedup` 保留不变（`UpsertDedup` 现从 `items` 建 canonical 索引）。

**调用点更新**：`cmd/ta_node/main.go`（2 处 `NewStoreWithDir`→`NewStore`）、CLI reload 路径、任何测试。

### 4.4 `internal/config/config.go`

- `IntelConfig` **删除**：`IntelDir`、`IocWatchDir`、`IocWatchIntervalSec`、`EnableIocWatch`；删除 `WatchInterval()`；删除 `--intel-dir` flag。
- **新增**：
  ```go
  IocSyncDir        string `json:"ioc_sync_dir" yaml:"ioc_sync_dir"`
  EnableIocSync     bool   `json:"enable_ioc_sync" yaml:"enable_ioc_sync"`
  IocSyncHour       int    `json:"ioc_sync_hour" yaml:"ioc_sync_hour"`
  IocSyncDailyLimit int    `json:"ioc_sync_daily_limit" yaml:"ioc_sync_daily_limit"`
  IocSyncRetainDays int    `json:"ioc_sync_retain_days" yaml:"ioc_sync_retain_days"`
  ```
- `Default()`：`IocSyncDir:"/data/yt/ioc"`、`EnableIocSync:true`、`IocSyncHour:1`、`IocSyncDailyLimit:10`、`IocSyncRetainDays:10`；删除 `IntelDir:"./configs/intel.d"` 及旧 ioc_watch 默认。

### 4.5 `internal/server/http_server.go` — 无需改动（仅核对）

已核对：配置页模板与保存白名单（`http_server.go:610`）**从未包含** `intel_dir` 或 `ioc_watch_*`（只有 `intel_file`/`reload_interval_sec`/`enable_hot_reload`/`prune_expired_interval_sec`/`accept_stix`/`default_source`/`max_items`）。因此删除这些结构体字段**不影响配置页**，本文件无需修改。旧的磁盘配置若仍含 `intel_dir:`/`ioc_watch_*:` 键，`yaml.v3`（未开 KnownFields）会忽略未知键，不报错——向后兼容。新字段 `ioc_sync_*` 不进配置页（非必须）。

### 4.6 配置文件与文档

- `configs/ta_node.yaml`、`configs/ta_node.offline.yaml`：删除 `intel_dir` 与 `ioc_watch_*`，加 `ioc_sync_*` 注释块。
- 删除 `configs/intel.d/`（overlay 目录不再加载）及其 README/sample。
- `README.md`：删除 “Splitting and incrementally adding IOCs / intel.d overlay” 段落，改写为“每日定时从 `/data/yt/ioc` 增量同步（限量 10、清理 10 天前 zip）”。

## 5. 不做（YAGNI）

- 不保留 overlay/intel_dir 任何回退开关（彻底删）。
- 不保留 `processed/`/`failed/` 归档目录。
- 不在进程启动时立即同步（只按 01:00 触发）。
- 不做错过当天的补跑（进程 01:00 不在线则跳过当天）。
- 不改动富字段（`evidence`/`recommended_action`）与事件推送（schema 1.3 不变）。

## 6. 测试计划

- `internal/iocsync/sync_test.go`（表驱动 + 临时目录 + `writeZip` 复用）：
  1. 主文件空、文件夹 3 个 zip 共 25 条 → `SyncOnce` 后主文件恰好 +10；返回 added=10。
  2. 主文件已含其中若干 → 只补齐到“新”前 10；已存在的不重复。
  3. 同值不同 id / 同值跨 zip → 候选去重，只算一条名额。
  4. 新规则不足 10（如 4 条）→ 全加，added=4。
  5. 坏 zip 混入 → 跳过、不影响其它、不移动、主文件不含坏数据。
  6. 清理：造 mtime 分别为 5 天/15 天前的 zip（`os.Chtimes`）→ `SyncOnce` 后 15 天前的被删、5 天前的保留。
- `internal/intel/`：`UpsertDedup` 及现有用例在单源 `Store` 下仍绿；补/改因删 `NewStoreWithDir` 受影响的用例。
- `nextDailyTime`：纯函数单测——now 在 00:30/01:00/13:00 时，下一个 01:00 的计算（含“正好等于时返回次日”）。

## 7. 端到端验证

编译 native 二进制，用一份把 `ioc_sync_hour` 设为“下一分钟对应的小时”不便；改为对 `Syncer.SyncOnce()` 直接驱动的 `go test -run` 演示（沙盒无法常驻定时进程）：造 zip → SyncOnce → 断言主文件 +N 且富字段保留、旧 zip 被清理。
