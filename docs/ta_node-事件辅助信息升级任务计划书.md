# ta_node 事件辅助信息升级任务计划书

## 1. 背景

ta_node 当前的检测链路为：

```text
capture -> parser.Parse -> fingerprint.Match / intel.MatchPacket -> flow.Update -> detector.Detect -> queue.Enqueue -> push (HTTP POST JSON)
```

推送给管理端 / AI 分析侧的事件结构 `event.ThreatEvent`（`internal/event/event.go`）目前只包含**5 元组 + 命中标签 + 流计数**。问题在于：`parser.Parse` 已经解析出大量应用层上下文（HTTP 方法/UA/请求头/请求体、DNS 应答、payload 样本、ICMP 序列号等），但这些信息在 `flow.FlowFeature`（`internal/flow/flow.go`）和 `aggregator.Update`（`internal/flow/aggregator.go:84-87`）这一聚合边界被丢弃，只透传了 `HTTPHost / HTTPURL / DNSQuery` 三项。

结果是：AI 拿到的事件只知道"谁命中了什么规则"，缺少研判真假、定性、关联所需的上下文证据。

## 2. 目标

在**不破坏现有字段兼容性**、**不引入外部数据源依赖**的前提下，把已经解析但被丢弃的辅助信息补进推送 payload，并补充少量可零成本计算的派生字段，提升 AI 研判的信息密度。

分层目标：

- **第一档（核心，零采集成本）**：透传已解析的应用层字段到事件。
- **第二档（低成本派生）**：流持续时长、流量方向判定。
- **第三档（情报元数据）**：IOC 命中事件补充描述、过期时间等已有但未透传的字段。
- **第四档（事件元数据）**：schema 版本、传感器版本，便于上游处理格式演进与可追溯。

非目标（本次不做，列入后续，详见第 7 节专项）：

- GeoIP / ASN / rDNS 富化（需引入外部数据库依赖）。
- 资产上下文（hostname / 区域 / 资产标签，需外部资产源）。
- 命中频次计数（节点/管理分层，零外部依赖；见 7.1）。
- 目标 ↔ IOC 每次通联的数据大小 / 双向上下行字节统计（客户需求；见 7.2）。
- TCP 流重组。

## 3. 设计要点

### 3.1 内存安全（关键约束）

`aggregator` 已有的内存策略是：**命中信息（hits）只挂在返回给调用方的 feature 上，不写回 stored flow**，以避免长生命周期流无界增长（见 `aggregator.go:18-22` 注释）。

本次新增的"重"应用层字段（请求头 map、请求体样本、payload 样本、DNS 应答）**遵循同样策略**：只从当前触发包 `pf` 挂到返回值 `out`，不写入 `st.feature`。这样既不增加每流常驻内存，又能保证事件携带的是**触发命中的那个包**的上下文（比保留流首包上下文更准确）。

### 3.2 隐私 / 安全

HTTP 请求头按**白名单**采集，避免把 `Cookie / Authorization / Proxy-Authorization` 等敏感凭据推送出去。白名单：`host, referer, content-type, content-length, x-forwarded-for, accept, accept-language, origin, x-requested-with`。请求体只取**截断样本**（≤512B，非可打印转 hex）。

### 3.3 向后兼容

所有新增字段均为 `omitempty`；既有字段（`event_id / src_ip / ...`）保持不变，类型、JSON tag 不动。新增的应用层上下文集中在嵌套对象 `app` 下，避免顶层字段膨胀。

## 4. 字段清单

### 4.1 事件顶层新增（`event.ThreatEvent`）

| 字段 | JSON | 来源 |
|---|---|---|
| FirstTime | `first_time` | flow.FirstTime |
| DurationMs | `duration_ms` | (LastTime-FirstTime)/1000 |
| Direction | `direction` | 由 home_net 判定 inbound/outbound/lateral/external |
| App | `app` | 嵌套应用层上下文（见下） |
| IOCDescription | `ioc_description` | intel.Description |
| IOCExpireAt | `ioc_expire_at` | intel.ExpireAt |
| SchemaVersion | `schema_version` | 常量 |
| SensorVersion | `sensor_version` | 构建常量 |

### 4.2 应用层上下文（新结构 `event.AppContext`，JSON `app`）

`http_method, http_host, http_url, user_agent, http_headers(map), http_body_sample, dns_query, dns_qtype, dns_answers, payload_sample, icmp_seq`

## 5. 实施步骤

1. **parser**：`PacketFeature` 增加 `HTTPHeaders map[string]string`、`HTTPBodySample string`；`parseHTTP` 按白名单填充请求头、采样请求体。
2. **flow.FlowFeature**：增加透传字段（HTTPMethod/UserAgent/HTTPHeaders/HTTPBodySample/DNSQType/DNSAnswers/PayloadSample/ICMPSeq）。
3. **flow.aggregator**：`Update` 与 `transientFeature` 把当前包 `pf` 的应用层上下文挂到返回值（不写回 stored flow）。
4. **event**：新增 `AppContext`、`SchemaVersion` 常量及顶层新增字段。
5. **detector.engine**：填充 `App`、`FirstTime`、`DurationMs`、`Direction`、IOC 描述/过期、版本；新增 `WithHomeNet / WithSensorVersion` 构建方法（保持 `New(deviceID)` 兼容现有测试）。
6. **config**：`NodeConfig` 增加 `home_net []string`。
7. **main**：解析 home_net CIDR，注入 detector，定义 sensor 版本常量。
8. **测试**：扩展 detector / aggregator 测试覆盖新字段；`go build ./...` 与 `go test ./...` 全绿。

## 6. 验收标准

- `go build ./...`、`go vet ./...`、`go test ./...` 全部通过。
- 构造含 HTTP / DNS 命中的流，`detector.Detect` 输出的事件 JSON 包含 `app` 上下文、`direction`、`duration_ms`、`schema_version`。
- 请求头不含敏感凭据（cookie/authorization 被过滤）。
- 既有事件字段与 JSON tag 不变，旧消费方解析不受影响。
- 每流常驻内存不因新增字段增长（重字段不写回 stored flow）。

## 7. 后续专项（不在本次升级范围）

### 7.1 命中频次计数（节点/管理分层，零外部依赖）

> 更正：早先把"命中频次计数"列为"依赖外部数据源"不准确。命中频次**不需要任何外部数据源**，
> 它是内部有状态聚合。全局最优是把"频次"拆成两种本质不同的量，各放在只有它能廉价且
> 正确计算的那一层——节点侧算"局部突发"，管理侧算"全局权威"。

**为什么不能单选一侧：**

| 维度 | 只放节点侧 | 只放管理侧 |
|---|---|---|
| 视野 | 仅本节点镜像到的流量，看不到同一 IOC 跨多节点/多主机的全局画面 | 天然全局 |
| 时效 | 事件自带频次，AI 立即可用 | 单条事件到达时无频次，需查库/后聚合 |
| 边缘成本 | 节点性能敏感，长周期/大基数计数吃内存 | 成本集中、可水平扩展 |
| 正确性 | 流表淘汰、事件去重、满载丢弃会扭曲长周期计数 | 落库后可精确去重统计 |
| 重启 | 内存计数器丢失（除非落 SQLite，再增成本） | 有 DB |

核心矛盾：长周期 + 跨节点 + 精确，节点侧做不好；即时 + 自带上下文，管理侧给不了。故必须分层。

**职责切分：**

- **节点侧 —— 局部突发（cheap hint，非真相）** ✅ 已实施
  - 按 `ioc_id`/`rule_id` 键，统计最近 N 秒（默认 60s）滑动窗口命中次数。
  - 实现：新增 `internal/counter` 滑动窗口计数器，有界（maxKeys/maxStamps）+ 满载惰性淘汰，照搬 `flow.Aggregator` 的有界淘汰范式；以流时间驱动，PCAP 回放确定可测。
  - 入 payload：`local_hit_count` + `local_window_sec` + `local_first_seen` + `local_scope:"node"`。
  - 配置：`event.local_hit_window_sec`（0 关闭）。

- **管理侧 —— 全局权威（source of truth）**
  - 跨所有节点、长周期（小时/天/全时）按节点送来的稳定键 group by：
    `global_hit_count`（去重后的 distinct `event_id` 数 = 命中过的不同流数）、
    `global_first_seen`/`global_last_seen`、`distinct_src_count`/`distinct_dst_count`/`distinct_node_count`（扩散面）、campaign 关联。
  - 节点无需发送任何全局计数，只需把键发干净。

**节点侧必须保证的 3 件事（本次升级后基本已具备）：**

1. 稳定一致的身份键 —— `detector.stableEventID`（`internal/detector/engine.go`）已提供。✅
2. 可去重的 `event_id` —— 推送有重试会重复 POST；**管理侧 ingest 必须按 `event_id` 幂等去重**，否则频次灌虚高。节点 SQLite 队列已用 `event_id UNIQUE` 防重复入队，跨重试网络重投需管理端兜底。⚠️ 落地前确认。
3. 准确时间戳 —— 本次升级已带 `first_time` + `duration_ms`。✅

**落地优先级：** ① 先做管理侧全局计数（节点已送齐键，风险最低，前提是确认 `event_id` 幂等去重）→ ② 再做节点侧局部突发计数（本仓库内可独立提交）。payload 务必标 `scope` 区分 `local_*`（节点近似）与 `global_*`（管理真相），避免 AI 混淆或重复计数。

### 7.2 目标 ↔ IOC 每次通联的数据大小（客户需求）

**需求：** 记录每一次"内网目标 ↔ IOC"通联所传输的数据量，供 AI 判定数据外传 / 载荷下载 / beacon 节律。

**现状与差距：**

- 现有 `event.bytes` = 单向 5 元组的 **payload 字节累加**（`aggregator.go:83` 仅 `len(pf.Payload)`，不含 L3/L4 头），且 `flow.Aggregator` 按精确 5 元组 `src:sport-dst:dport-proto` 建键（`aggregator.go:54`），**A→B 与 B→A 是两条独立流**。
- 因此当前无法在单条事件里给出"一次通联"的双向总量与上下行拆分，也缺少在线字节（wire bytes）口径。

**对 AI 的价值：** `bytes_to_ioc` 大、`bytes_from_ioc` 小 → 数据外传；`bytes_from_ioc` 大 → 载荷下载；小而周期性对称 → beacon。

**分阶段方案（同样遵循节点/管理分层）：**

- **阶段 A（节点侧，最小改动，低风险）** ✅ 已实施
  - 新增 `wire_bytes`（按 `packet.Metadata().Length` 累加，回退抓包长）与现有 payload `bytes` 并存，给出两种口径。
  - 对 IOC 命中事件，依据匹配到的 IOC 是 `dst` 还是 `src`（ip/cidr 精确判定，domain/url 视为去向 IOC），给当前单向流的体量打方向标：`volume_role: "to_ioc" | "from_ioc"`。
  - 不改流表键，不动现有语义，随事件直接输出每方向体量。

- **阶段 B（节点侧，双向流账，较大改动）**
  - 流表键规范化（端点排序，使 A↔B 两方向归并到同一会话），新增方向计数：
    `bytes_to_ioc` / `bytes_from_ioc` / `packets_to_ioc` / `packets_from_ioc`（payload 与 wire 各一套）。
  - 影响面：改 `aggregator.go` 建键与 `transientFeature`，需同步更新 `aggregator_test.go`；内存不增（一条会话替代两条单向流）。
  - 注意仍遵循内存安全约束：重计数字段只挂返回值或受 TTL 淘汰约束。

- **管理侧（全局累计，权威）**
  - 按规范化 5 元组 + 会话窗口 join 两个方向，产出"每次通联"的双向总量；并按 `ioc_id` 累计每个 IOC 的历史通联总字节 / 总次数（配合 7.1 频次）。

**落地优先级：** 阶段 A 可与 7.1 节点侧计数同批实现并提交（都不改流表键）；阶段 B 与管理侧 join 单列，作为更精确的会话级账目。

### 7.3 其他后续（依赖外部数据源 / 更大改动）

- GeoIP / ASN / rDNS 富化（需外部地理/信誉库）。
- 资产上下文（hostname / 区域 / 资产标签，需外部资产源）。
- TCP 流重组。
