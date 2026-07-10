# 网闸 IOC zip 落地监听与规则实时导入 — 设计文档

- 日期：2026-07-10
- 状态：待评审
- 关联代码：`internal/intel`、`internal/detector`、`internal/event`、`internal/config`、`cmd/ta_node/main.go`

## 1. 背景与目标

内网 `ta_node` 无法直连外网的 Threat Intel Hub。情报以离线方式经**网闸**投递：
外网侧把规则打包成 `.zip`，落到内网 `/data/yt/ioc/` 目录。

目标：**监听该目录，实时把 zip 内的规则解析、去重后并入本节点的 IOC 规则集**，
并把规则携带的富字段（`evidence`、`recommended_action`）**一路带到安全事件**里，
供管理端 / AI 分析使用。

本通道在语义上等价于现有 HTTP `POST /api/v1/intel/sync-source` 的**离线投递版**，
只是走文件而非网络。

## 2. 关键事实（现状调研）

- zip 内规则文件与现有 `configs/intel.yaml` **同一 schema**：顶层 `items:`，每项是
  `intel.ThreatIntel`（`id/type/value/category/severity/source/description/tags/enabled/...`）。
  样例见 `docs/intel.yaml`。样例中**额外**带了两个当前 struct 未定义的字段：
  `evidence`（嵌套对象）与 `recommended_action`（如 `block_and_report`）。
- `intel.Store` 已有 `primary`（可写 `intel.yaml`）+ `overlay`（只读 `intel.d/`）双源，
  合并读视图按 `id` 去重、primary 优先。`UpsertMany` 按 `id` upsert 进 primary 并原子落盘。
- `intel.Matcher.ensureIndex()` 监听 `store.Version()`，版本一变即重建索引 →
  **`UpsertMany` 后下一个包立即生效**，无需等热加载定时器。
- 现有并发任务全部是**轮询定时器**风格（`hotReload`/`pruneExpired`/`flowCleanup`），
  且项目为**离线 vendor 构建**（ARM 离线部署）。`fsnotify` **未 vendor**。
- 事件推送 `push.PushEvent` = `json.Marshal(ThreatEvent)` 整体序列化，
  queue 也存整体 JSON → **给 `ThreatEvent` 新增带 json tag 的字段即自动端到端推送**，
  无需改序列化白名单。
- detector 在 `engine.go:104-116` 把命中 `ThreatIntel` 的字段拷进 `ThreatEvent`
  （`IOCType/IOCValue/IOCCategory/IOCID/IOCSource/IOCTags/IOCDescription/IOCExpireAt`）。

## 3. 设计决策（已与用户确认）

| 决策点 | 选择 | 理由 |
|---|---|---|
| 监听机制 | **短间隔轮询**（默认 5s），不引入 fsnotify | 离线 vendor 约束 + 全轮询代码风格；5s 满足"实时" |
| 合并语义 | **增量合并**（upsert，不删未出现的旧条目） | 用户确认；对应"每次只送新情报"的投递模式 |
| 落库方式 | **`UpsertMany` 进主 `intel.yaml`** | 去重/更新最干净、立即生效、富字段随之持久化 |
| 富字段 | **保留**，并推送到安全事件 | 用户确认：最终推送到安全事件 |
| 事件字段形状 | **嵌套对象 `ioc_evidence` + 顶层 `recommended_action`** | 结构完整，利于 AI 分析 |
| 去重 | **三层去重**（见 §5） | 用户强调"要做好去重" |

## 4. 架构与数据流

新增组件 `internal/iocwatch`，在 `main.go` 内作为一个 goroutine 启动
（与 `hotReload`/`pruneExpired` 同风格，受 `ctx` 控制优雅退出）。

```
网闸 → /data/yt/ioc/*.zip
  → [轮询 5s] 发现新 zip（不在 processed/、failed/ 子目录）
  → 完整性校验：能被 archive/zip 打开 = 中央目录已写完（半写文件打不开）
  → 读取 zip 内所有 *.yaml/*.yml（内存中读取，不落盘，规避 zip-slip）
  → intel.File{Items} 解析（yaml.v3，自动填充 evidence/recommended_action）
  → normalize + 三层去重
  → store.UpsertDedup(items)  ← bump version，matcher 下一个包即生效，原子落盘
  → 成功：zip move 到 /data/yt/ioc/processed/
     失败：zip move 到 /data/yt/ioc/failed/  并 log（不缩减现有规则集）
```

命中时（detector）→ `ThreatEvent` 带上 `ioc_evidence` + `recommended_action`
→ enqueue → push 整体 JSON 推送到管理端。

## 5. 去重（三层）

canonical key 定义：`type + "|" + 规范化 value`，复用 matcher 的规范化逻辑
（`canonicalIP` / `canonicalDomain`，url 用小写 trim）。

1. **批内去重**：同一批（含跨 zip 内多文件）按 canonical key 折叠，
   冲突保留 `updated_at` 最新者。避免一批里同值多条。
2. **落库去重（关键）**：因 Hub 的 id 形如 `otx-<eventid>-<indicatorid>`，
   **同一 value 可能带不同 id**。若仅按 id upsert 会让同值累积多条，
   进而使 matcher 对一个包产生多条命中。故落库前对**已有 store 中相同 canonical key**
   归并：若已存在相同 (type,value)，复用其既有 `id` 更新（in-place），而非新增。
   → 通过新增 `Store.UpsertDedup(items)` 在**锁内原子完成**：
   进入锁 → 用当前合并视图构建 `canonicalKey→id` 索引 → 对每个入参，
   若命中索引则改写其 `id` 为既有 id → 再走 upsert。避免读-改-写竞态。
3. **重复投递去重**：同一 zip 只处理一次。处理成功即 move 出监听目录到
   `processed/`，天然幂等；文件名冲突时加时间戳/序号后缀（时间戳由 caller 传入，
   见 §8 注意事项）。

## 6. 数据结构变更

### 6.1 `internal/intel/types.go`

```go
type ThreatIntel struct {
    // ... 现有字段不变 ...
    RecommendedAction string    `json:"recommended_action,omitempty" yaml:"recommended_action,omitempty"`
    Evidence          *Evidence `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

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

注意：样例中 `cross_check` / `narrative` 可能是 `null` 或字符串 → 用 `string`
（yaml `null` → 零值 `""`），`misp_event_id` 用 `string`（样例为十六进制串）。

### 6.2 `internal/event/event.go`

`ThreatEvent` 新增：

```go
RecommendedAction string          `json:"recommended_action,omitempty"`
IOCEvidence       *intel.Evidence `json:"ioc_evidence,omitempty"`
```

（event 包引用 intel 包；确认无 import 环——intel 不依赖 event，安全。）

### 6.3 `internal/detector/engine.go`（约 109-116 行处补两行）

```go
ev.RecommendedAction = hit.RecommendedAction
ev.IOCEvidence = hit.Evidence
```

### 6.4 `internal/config/config.go` — `IntelConfig` 新增

```go
IocWatchDir         string `json:"ioc_watch_dir" yaml:"ioc_watch_dir"`
IocWatchIntervalSec int    `json:"ioc_watch_interval_sec" yaml:"ioc_watch_interval_sec"`
EnableIocWatch      bool   `json:"enable_ioc_watch" yaml:"enable_ioc_watch"`
```

默认值（`Default()`）：`IocWatchDir: "/data/yt/ioc"`、`IocWatchIntervalSec: 5`、
`EnableIocWatch: true`。`configs/*.yaml` 补注释示例。
（config 页面表单为可选项，本期不强制，视时间加。）

## 7. 新增组件 `internal/iocwatch`

职责单一：目录轮询 + zip 解包解析 + 调 store。对外接口：

```go
// Watcher 轮询 dir，把新 zip 内的 IOC 规则解析并 upsert 进 store。
func New(store *intel.Store, dir string, interval time.Duration, maxItems int) *Watcher
func (w *Watcher) Run(ctx context.Context)   // 阻塞直到 ctx.Done()，供 go 调用
```

内部：
- `scanOnce()`：glob `dir/*.zip`（跳过子目录），逐个 `processZip`。
- `processZip(path)`：`zip.OpenReader` 失败 → 视为半写，直接返回不移动，下轮重试；
  打开成功 → 遍历 entry，取 `*.yaml/*.yml`，`io.ReadAll`（受单文件/总量上限约束）
  → `yaml.Unmarshal` 成 `intel.File` → 汇总 items → 批内去重 →
  `store.UpsertDedup` → 成功 move 到 `processed/`，任一步失败 move 到 `failed/`。
- 上限：总条数受 `maxItems`（沿用 `intel.max_items`）约束；单个 zip 解压总字节设一个
  合理硬上限（如 256MB）防 zip bomb；条目超限则截断并 log。

`main.go` 挂载：

```go
if cfg.Intel.EnableIocWatch && cfg.Intel.IocWatchDir != "" {
    w := iocwatch.New(intelStore, cfg.Intel.IocWatchDir,
        time.Duration(cfg.Intel.IocWatchIntervalSec)*time.Second, cfg.Intel.MaxItems)
    go w.Run(ctx)
}
```

## 8. 错误处理与健壮性

- **半写文件**：`zip.OpenReader` 失败即跳过、不移动、下轮重试。网闸写入过程中的 zip
  自然被拦住，写完（中央目录落盘）后才被处理。
- **坏 zip / 坏 yaml**：move 到 `failed/` 并 log，**绝不缩减现有规则集**
  （增量语义天然满足：解析失败就不 upsert）。
- **子目录隔离**：`processed/` 与 `failed/` 是 `dir` 下子目录，扫描时排除，避免重复处理。
- **幂等**：处理成功即移出，重复投递同名文件也只会各自处理一次。
- **优雅退出**：`Run` select `ctx.Done()`。
- **无 Date/随机限制**：move 目标文件名若冲突需后缀去重；生产代码可用 `time.Now()`。
  （该限制仅针对 workflow 脚本，不影响本 Go 组件。）

## 9. 测试计划（表驱动 + 临时目录）

`internal/iocwatch/watcher_test.go`：
1. 正常：造一个含 `items:` yaml 的 zip 落地 → `scanOnce` 后 store 条数增加、
   `processed/` 有该 zip、命中项带 evidence/recommended_action。
2. 重复投递：同一 zip 处理两次不重复累加（第二次因已移走而不再处理）。
3. 同值不同 id 去重：两条 `type=domain,value=x` 但 id 不同 → store 里只 1 条。
4. 坏 zip / 坏 yaml → 进 `failed/`，store 条数不变。
5. 半写 zip（截断字节）→ 不移动、store 不变；补齐后再扫描能正常导入。

`internal/intel/`：`UpsertDedup` 单测（canonical 去重、id 复用、原子落盘）。
`internal/detector/`：命中带 evidence 时 `ev.IOCEvidence`/`ev.RecommendedAction` 被填充。

## 10. 不做（YAGNI / 明确排除）

- 不引入 fsnotify / inotify。
- 不做 zip 内嵌套目录递归以外的复杂结构（仅平铺 `*.yaml/*.yml`）。
- 不做整源替换 / 删除语义（本期只增量合并）。
- config 网页表单本期可选，不阻塞主功能。
- 不解析 zip 内 STIX/CSV（本通道格式固定为 items yaml；如需另立通道）。
