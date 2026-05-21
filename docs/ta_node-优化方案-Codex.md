# ta_node 优化方案（供 Codex 执行）

> 目标：将 ta_node 优化为“威胁情报消费节点”，能够持续接收 Threat Intel Hub 推送的最新 active IOC，并使用最新内存情报匹配后续采集到的流量，命中后生成事件并推送管理端。

---

## 1. 项目定位

ta_node 不需要实现完整 TAXII Server。它应该专注于：

- 采集流量：在线网卡或离线 PCAP。
- 解析流量：提取 `PacketFeature`。
- 匹配规则：payload fingerprint。
- 匹配情报：ip / cidr / domain / url。
- 消费上游情报：从 Threat Intel Hub 接收最新 active IOC。
- 热更新内存情报：无需重启即可使用新 IOC。
- 告警事件：命中 IOC 后生成事件，进入 SQLite 队列，再推送管理端。

当前项目已经有本地情报文件、HTTP 情报 API、热加载、事件队列和配置页。优化重点是增强“外部情报消费能力”和“实时更新一致性”。

---

## 2. 当前能力梳理

### 2.1 已有配置

```yaml
intel:
  intel_file: "./configs/intel.yaml"
  reload_interval_sec: 30
  enable_hot_reload: true
```

### 2.2 已有情报结构

```go
type ThreatIntel struct {
    ID          string   `json:"id" yaml:"id"`
    Type        string   `json:"type" yaml:"type"`
    Value       string   `json:"value" yaml:"value"`
    Category    string   `json:"category" yaml:"category"`
    Severity    string   `json:"severity" yaml:"severity"`
    Source      string   `json:"source" yaml:"source"`
    Description string   `json:"description" yaml:"description"`
    Tags        []string `json:"tags" yaml:"tags"`
    Enabled     bool     `json:"enabled" yaml:"enabled"`
    CreatedAt   int64    `json:"created_at" yaml:"created_at"`
    UpdatedAt   int64    `json:"updated_at" yaml:"updated_at"`
    ExpireAt    int64    `json:"expire_at,omitempty" yaml:"expire_at,omitempty"`
}
```

### 2.3 已有 HTTP API

```http
GET    /api/v1/intel
POST   /api/v1/intel
DELETE /api/v1/intel/{id}
POST   /api/v1/intel/reload
POST   /api/v1/intel/sync
```

### 2.4 已有匹配逻辑

当前实时检测中实际参与匹配的类型：

| type | 匹配位置 |
|---|---|
| ip | 源 IP、目的 IP、DNS answers |
| cidr | 源 IP、目的 IP、DNS answers |
| domain | DNS Query、HTTP Host |
| url | HTTP URL |
| hash | 当前仅存储，不检测 |

---

## 3. 总体优化目标

```text
Threat Intel Hub
  -> active IOC
  -> ta_node HTTP API
  -> Store 内存更新
  -> MatchPacket 使用最新 Store
  -> 后续流量命中 IOC
  -> Detector 生成事件
  -> SQLite 队列
  -> 管理端推送
```

关键要求：

- 接收新情报后无需重启。
- 不因全量同步覆盖本地人工 IOC。
- 支持按 source 替换 Threat Intel Hub 来源的情报。
- 支持 STIX/TAXII Envelope 的轻量接收适配，但不实现完整 TAXII Server。
- 提供情报版本、统计、更新时间和健康状态。
- 保证并发安全。

---

## 4. 推荐新增能力

## 4.1 按 source 同步接口

当前 `/api/v1/intel/sync` 是全量替换，会覆盖所有内存情报和本地文件。生产环境不建议上游 Hub 直接使用它，因为会覆盖 `local`、`cli` 等本地情报。

新增接口：

```http
POST /api/v1/intel/sync-source
```

或兼容式：

```http
POST /api/v1/intel/sync?source=Threat%20Intel%20Hub
```

推荐新增独立路由，语义更清晰：

```http
POST /api/v1/intel/sync-source
Content-Type: application/json
```

Request：

```json
{
  "source": "Threat Intel Hub",
  "items": [
    {
      "id": "thih-ip-1.2.3.4",
      "type": "ip",
      "value": "1.2.3.4",
      "category": "c2",
      "severity": "high",
      "source": "Threat Intel Hub",
      "enabled": true,
      "expire_at": 1780000000
    }
  ]
}
```

语义：

```text
1. 删除旧的 source=Threat Intel Hub 的 IOC
2. 保留 source=local / cli / manual 的 IOC
3. 写入新的 source=Threat Intel Hub 的 IOC
4. 持久化到 intel_file
5. 更新内存 Store
```

---

## 4.2 增量 upsert 接口

新增：

```http
POST /api/v1/intel/batch-upsert
```

Request：

```json
{
  "items": []
}
```

语义：

```text
1. 对每条 IOC 执行 normalize
2. 如果 ID 存在则更新
3. 如果 ID 不存在则插入
4. 不影响其他 source 的 IOC
5. 持久化到 intel_file
```

适合 Threat Intel Hub 只推增量 IOC 的场景。

---

## 4.3 STIX/TAXII 轻量接收接口

不做完整 TAXII Server，仅新增轻量解析接口：

```http
POST /api/v1/intel/stix
```

支持两种输入：

### STIX Bundle

```json
{
  "type": "bundle",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--...",
      "pattern": "[ipv4-addr:value = '1.2.3.4']",
      "labels": ["c2"],
      "confidence": 85,
      "valid_until": "2026-06-04T00:00:00Z"
    }
  ]
}
```

### TAXII Envelope

```json
{
  "objects": [
    {
      "type": "indicator",
      "pattern": "[domain-name:value = 'evil.example.com']",
      "labels": ["malware"],
      "confidence": 90
    }
  ]
}
```

转换为内部 `ThreatIntel`。

---

## 5. STIX -> ThreatIntel 映射

| STIX Pattern | ta_node Type | Value |
|---|---|---|
| `[ipv4-addr:value = '1.2.3.4']` | ip | `1.2.3.4` |
| `[ipv6-addr:value = '2001:db8::1']` | ip | `2001:db8::1` |
| `[domain-name:value = 'evil.example.com']` | domain | `evil.example.com` |
| `[url:value = 'http://evil.example.com/a']` | url | `http://evil.example.com/a` |
| `[ipv4-addr:value ISSUBSET '45.67.89.0/24']` | cidr | `45.67.89.0/24` |
| `[file:hashes.'SHA-256' = '...']` | hash | hash value |

### 5.1 confidence -> severity

```text
confidence >= 90 -> critical
confidence >= 70 -> high
confidence >= 40 -> medium
else             -> low
```

### 5.2 labels -> category

优先规则：

```text
c2          -> c2
phishing    -> phishing
malware     -> malware
scanner     -> scanner
botnet      -> botnet
exploit     -> exploit
webshell    -> webshell
unknown     -> unknown
```

### 5.3 valid_until -> expire_at

```text
STIX valid_until -> Unix timestamp seconds
如果没有 valid_until，则按类型默认 TTL 计算
```

默认 TTL：

| type | category | ttl |
|---|---|---:|
| url | phishing | 3 天 |
| url | malware | 7 天 |
| ip | c2 | 14 天 |
| ip | scanner | 3 天 |
| ip | botnet | 30 天 |
| domain | malware | 30 天 |
| cidr | scanner | 3 天 |
| hash | malware | 180 天 |

---

## 6. Store 优化

### 6.1 新增方法

在 `internal/intel/store.go` 增加：

```go
func (s *Store) UpsertMany(items []ThreatIntel) error
func (s *Store) SyncSource(source string, items []ThreatIntel) error
func (s *Store) Stats() StoreStats
func (s *Store) Get(id string) (ThreatIntel, bool)
func (s *Store) PruneExpired(now int64) int
```

### 6.2 `SyncSource` 语义

```go
func (s *Store) SyncSource(source string, items []ThreatIntel) error {
    // 1. normalize 所有新 items
    // 2. 加锁
    // 3. 删除 map 中 Source == source 的旧 IOC
    // 4. 插入新 IOC
    // 5. 释放锁
    // 6. 保存文件
}
```

### 6.3 持久化优化

当前 Add / Delete / Sync 会直接 SaveFile。建议：

- Store 层保持立即持久化，保证简单可靠。
- 后续如 IOC 数量较大，再引入 debounced persistence。
- 保存文件时使用临时文件 + rename，避免写坏 YAML。

新增：

```go
func SaveFileAtomic(path string, items []ThreatIntel) error
```

流程：

```text
1. 写入 path.tmp
2. fsync
3. rename path.tmp -> path
```

---

## 7. HTTP API 优化

### 7.1 API 列表

保留：

```http
GET    /api/v1/intel
POST   /api/v1/intel
DELETE /api/v1/intel/{id}
POST   /api/v1/intel/reload
POST   /api/v1/intel/sync
```

新增：

```http
POST   /api/v1/intel/sync-source
POST   /api/v1/intel/batch-upsert
POST   /api/v1/intel/stix
GET    /api/v1/intel/stats
GET    /api/v1/health
```

### 7.2 `/api/v1/intel/stats`

Response：

```json
{
  "total": 1000,
  "enabled": 950,
  "expired": 50,
  "by_type": {
    "ip": 500,
    "domain": 300,
    "url": 150,
    "cidr": 50
  },
  "by_source": {
    "Threat Intel Hub": 800,
    "local": 200
  },
  "last_updated_at": 1780000000
}
```

### 7.3 `/api/v1/health`

Response：

```json
{
  "status": "ok",
  "device_id": "node-001",
  "intel_count": 1000,
  "server_time": 1780000000
}
```

---

## 8. STIX Parser 设计

新增包：

```text
internal/intel/stix.go
```

### 8.1 数据结构

```go
type STIXEnvelope struct {
    Type    string       `json:"type"`
    Objects []STIXObject `json:"objects"`
}

type STIXObject struct {
    Type        string   `json:"type"`
    ID          string   `json:"id"`
    Pattern     string   `json:"pattern"`
    Labels      []string `json:"labels"`
    Confidence  int      `json:"confidence"`
    Description string   `json:"description"`
    ValidFrom   string   `json:"valid_from"`
    ValidUntil  string   `json:"valid_until"`
}
```

### 8.2 解析函数

```go
func ParseSTIXIndicators(r io.Reader, defaultSource string) ([]ThreatIntel, error)
func STIXIndicatorToThreatIntel(obj STIXObject, defaultSource string) (ThreatIntel, bool)
func ParseSTIXPattern(pattern string) (typ string, value string, ok bool)
```

### 8.3 Pattern 支持范围

先只支持单一 observable pattern：

```text
[ipv4-addr:value = 'x']
[ipv6-addr:value = 'x']
[domain-name:value = 'x']
[url:value = 'x']
[file:hashes.MD5 = 'x']
[file:hashes.'SHA-1' = 'x']
[file:hashes.'SHA-256' = 'x']
[ipv4-addr:value ISSUBSET 'x.x.x.x/yy']
```

不支持复杂 AND/OR 的 pattern 时：

- 跳过该对象
- 计入 `skipped`
- 返回响应中给出原因

---

## 9. 匹配引擎优化

当前 `MatchPacket()` 每包遍历所有 IOC。IOC 数量上千时尚可，数量上万时性能会下降。建议增加索引。

### 9.1 新增 Matcher 索引

```go
type Matcher struct {
    store *Store
    mu sync.RWMutex
    ipSet map[string][]ThreatIntel
    cidrs []CIDRIntel
    domainMap map[string][]ThreatIntel
    urlList []ThreatIntel
    version int64
}
```

### 9.2 Store 版本号

在 Store 中增加：

```go
version int64
```

每次 Add / Sync / SyncSource / Delete 后递增。

Matcher 每次匹配前检查版本：

```go
if matcher.version != store.Version() {
    matcher.RebuildIndex()
}
```

### 9.3 匹配优化

- IP：O(1) map 查找。
- CIDR：仍需遍历，但数量通常较少。
- Domain：支持精确和后缀匹配。
- URL：先按 host 或完整 URL 简单索引，后续再优化。

---

## 10. 安全优化

### 10.1 本地 API 鉴权

当前本地 API 无鉴权风险较高。建议增加可选 token：

配置新增：

```yaml
server:
  enable: true
  listen: "0.0.0.0:19090"
  token: ""
```

兼容策略：

```text
server.token 为空 -> 不启用鉴权
server.token 非空 -> 要求 Authorization: Bearer <token>
```

需要保护接口：

```http
POST /api/v1/intel
DELETE /api/v1/intel/{id}
POST /api/v1/intel/reload
POST /api/v1/intel/sync
POST /api/v1/intel/sync-source
POST /api/v1/intel/batch-upsert
POST /api/v1/intel/stix
POST /api/v1/config
```

GET 接口可选是否保护，生产建议全部保护。

### 10.2 配置页安全

当前配置页能写回配置文件，生产环境必须：

- 绑定 `127.0.0.1` 或开启 token。
- 禁止公网裸露。
- 不在页面回显 token 明文。
- 保存 token 时不要打印日志。

---

## 11. 配置优化

### 11.1 新增配置项

```yaml
server:
  enable: true
  listen: "0.0.0.0:19090"
  token: ""

intel:
  intel_file: "./configs/intel.yaml"
  reload_interval_sec: 30
  enable_hot_reload: true
  prune_expired_interval_sec: 300
  accept_stix: true
  default_source: "Threat Intel Hub"
  max_items: 100000
```

### 11.2 配置页同步

Web 配置页新增字段：

- `server.token`
- `intel.accept_stix`
- `intel.prune_expired_interval_sec`
- `intel.max_items`

---

## 12. 与 Threat Intel Hub 的推荐对接

### 12.1 首选接口

```http
POST http://<ta_node>:19090/api/v1/intel/sync-source
Authorization: Bearer <token>
Content-Type: application/json
```

Body：

```json
{
  "source": "Threat Intel Hub",
  "items": [
    {
      "id": "thih-ip-virustotal-1.2.3.4",
      "type": "ip",
      "value": "1.2.3.4",
      "category": "c2",
      "severity": "high",
      "source": "Threat Intel Hub",
      "description": "source=VirusTotal reputation_score=-80",
      "tags": ["threat-intel-hub", "virustotal", "c2"],
      "enabled": true,
      "expire_at": 1780000000
    }
  ]
}
```

### 12.2 兼容 STIX 接口

```http
POST http://<ta_node>:19090/api/v1/intel/stix?source=Threat%20Intel%20Hub
Authorization: Bearer <token>
Content-Type: application/json
```

Body 可以是 STIX Bundle 或 TAXII Envelope。

---

## 13. 事件增强

当流量命中 IOC 后，事件中应尽量保留 IOC 信息。

建议事件结构增加：

```json
{
  "intel_id": "thih-ip-...",
  "intel_type": "ip",
  "intel_value": "1.2.3.4",
  "intel_category": "c2",
  "intel_severity": "high",
  "intel_source": "Threat Intel Hub",
  "intel_tags": ["c2", "threat-intel-hub"]
}
```

如果当前事件模型已包含 `IntelHits`，确保推送管理端时不丢失这些字段。

---

## 14. 过期清理

即使 Matcher 已跳过过期 IOC，也建议定期清理内存和文件中的过期项。

新增后台任务：

```go
func pruneExpired(ctx context.Context, store *intel.Store, interval time.Duration)
```

规则：

```text
1. 每 5 分钟执行
2. 删除 ExpireAt > 0 && ExpireAt < now 的 IOC
3. 可选仅删除 source=Threat Intel Hub 的过期 IOC
4. 持久化文件
```

注意：如果需要历史留存，不要在 ta_node 保留历史 IOC，历史应留在 Threat Intel Hub。

---

## 15. 测试计划

### 15.1 Store 测试

- [ ] `Add` 不破坏已有 IOC。
- [ ] `Sync` 全量替换。
- [ ] `SyncSource` 只替换指定 source。
- [ ] `UpsertMany` 插入和更新正确。
- [ ] `PruneExpired` 删除过期项。
- [ ] 并发读写无 data race。

### 15.2 STIX Parser 测试

- [ ] 解析 STIX Bundle。
- [ ] 解析 TAXII Envelope。
- [ ] 支持 ipv4。
- [ ] 支持 ipv6。
- [ ] 支持 domain。
- [ ] 支持 url。
- [ ] 支持 cidr。
- [ ] 支持 file hash。
- [ ] 跳过复杂 pattern。

### 15.3 HTTP API 测试

- [ ] `/api/v1/intel/sync-source`
- [ ] `/api/v1/intel/batch-upsert`
- [ ] `/api/v1/intel/stix`
- [ ] `/api/v1/intel/stats`
- [ ] 鉴权开启时未授权返回 401。
- [ ] 鉴权关闭时保持兼容。

### 15.4 匹配测试

- [ ] IP IOC 命中 SrcIP。
- [ ] IP IOC 命中 DstIP。
- [ ] CIDR IOC 命中网段。
- [ ] Domain IOC 命中 DNSQuery。
- [ ] Domain IOC 命中 HTTPHost。
- [ ] URL IOC 命中 HTTPURL。
- [ ] ExpireAt 过期的 IOC 不命中。

---

## 16. Codex 执行任务清单

### 阶段 1：Store 能力增强

- [ ] 修改 `internal/intel/store.go`
- [ ] 新增 `UpsertMany`
- [ ] 新增 `SyncSource`
- [ ] 新增 `Stats`
- [ ] 新增 `PruneExpired`
- [ ] 新增 `Version`
- [ ] 保存文件改为 atomic save

### 阶段 2：HTTP API 增强

- [ ] 修改 `internal/server/http_server.go`
- [ ] 新增 `/api/v1/intel/sync-source`
- [ ] 新增 `/api/v1/intel/batch-upsert`
- [ ] 新增 `/api/v1/intel/stats`
- [ ] 新增 `/api/v1/health`
- [ ] 返回 JSON 中包含 `success/count/skipped/error`

### 阶段 3：STIX 轻量解析

- [ ] 新增 `internal/intel/stix.go`
- [ ] 实现 Bundle / Envelope 解析
- [ ] 实现 STIX Pattern 解析
- [ ] 实现 confidence/severity 映射
- [ ] 实现 valid_until/expire_at 映射
- [ ] 新增 `/api/v1/intel/stix`

### 阶段 4：Matcher 性能优化

- [ ] 为 `internal/intel/matcher.go` 增加索引
- [ ] Store 版本变化后自动重建索引
- [ ] 保持现有匹配行为兼容
- [ ] 增加单元测试

### 阶段 5：鉴权与配置

- [ ] 修改 `internal/config/config.go`
- [ ] ServerConfig 增加 `Token`
- [ ] IntelConfig 增加 `AcceptSTIX`、`PruneExpiredIntervalSec`、`MaxItems`
- [ ] 修改配置页隐藏 token 明文
- [ ] HTTP 写接口增加 Bearer 校验

### 阶段 6：后台任务

- [ ] 在 `cmd/ta_node/main.go` 增加 pruneExpired goroutine
- [ ] 支持 `intel.prune_expired_interval_sec`
- [ ] 写日志但不要刷屏

### 阶段 7：文档

- [ ] 更新 README.md
- [ ] 更新 docs/ta_node.md
- [ ] 增加 Threat Intel Hub 对接示例
- [ ] 增加 STIX 接收示例
- [ ] 增加安全部署建议

---

## 17. 验收标准

### 17.1 功能验收

- [ ] Threat Intel Hub 可推送 active IOC 到 ta_node。
- [ ] ta_node 接收后无需重启即可用于后续流量检测。
- [ ] 本地 `local` / `cli` IOC 不会被 Hub 同步覆盖。
- [ ] 过期 IOC 不参与匹配。
- [ ] STIX Bundle 可被轻量解析。
- [ ] TAXII Envelope 可被轻量解析。
- [ ] 配置页可设置 token 和情报参数。
- [ ] 管理端事件包含命中 IOC 信息。

### 17.2 性能验收

- [ ] 1 万条 IOC 下匹配性能可接受。
- [ ] 批量同步 1 万条 IOC 不导致服务长时间阻塞。
- [ ] 无明显 data race。
- [ ] YAML 写入不会产生损坏文件。

### 17.3 安全验收

- [ ] 开启 token 后，未授权请求无法修改情报。
- [ ] token 不在配置页面明文展示。
- [ ] token 不进入日志。
- [ ] 默认文档建议监听 `127.0.0.1` 或通过反向代理加 TLS。

---

## 18. 给 Codex 的直接 Prompt

```text
你正在优化 Go 项目 ta_node。
请将其增强为 Threat Intel Hub 的威胁情报消费节点。

目标：
1. 保留现有抓包、解析、规则匹配、事件队列和推送逻辑。
2. 增强 internal/intel.Store，支持 UpsertMany、SyncSource、Stats、PruneExpired、Version。
3. 新增 HTTP API：
   - POST /api/v1/intel/sync-source
   - POST /api/v1/intel/batch-upsert
   - POST /api/v1/intel/stix
   - GET  /api/v1/intel/stats
   - GET  /api/v1/health
4. 新增轻量 STIX 2.1/TAXII Envelope 解析能力，只解析 Indicator。
5. 将 STIX Indicator 转为内部 ThreatIntel。
6. 支持 ip/cidr/domain/url/hash，其中 hash 先只存储不检测。
7. 新增 server.token 可选鉴权，保护写接口。
8. 优化 Matcher，使其在 IOC 数量较大时使用索引匹配。
9. 接收到最新情报后无需重启，即可用于后续采集流量分析。
10. 增加单元测试和文档。

约束：
- 不实现完整 TAXII Server，不做 Discovery/API Root/Collection 管理。
- 保持现有 /api/v1/intel 和 /api/v1/intel/sync 行为兼容。
- /api/v1/intel/sync-source 只替换指定 source 的情报，不覆盖 local/cli。
- 过期 IOC 不参与匹配。
- 写 YAML 使用 atomic save，避免文件损坏。
- 通过 go test ./...。
```

---

## 19. 推荐文件变更摘要

```text
cmd/ta_node/main.go
internal/config/config.go
internal/intel/types.go
internal/intel/store.go
internal/intel/stix.go
internal/intel/matcher.go
internal/intel/file.go 或现有文件保存逻辑
internal/server/http_server.go
internal/server/http_server_test.go
internal/intel/store_test.go
internal/intel/stix_test.go
internal/intel/matcher_test.go
README.md
docs/ta_node.md
configs/ta_node.yaml
configs/intel.yaml
```

---

## 20. 最终目标状态

完成后，ta_node 应达到：

```text
启动后加载本地 IOC
持续采集流量
接收 Threat Intel Hub 推送
按 source 更新内存 Store
自动跳过过期 IOC
用最新 ip/cidr/domain/url IOC 匹配后续流量
命中后生成事件
事件进入 SQLite 队列
管理端不可用时重试
```

这样 ta_node 就成为一个清晰、轻量、实时的威胁情报消费与流量检测节点。
