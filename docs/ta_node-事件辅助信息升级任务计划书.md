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

非目标（本次不做，列入后续）：

- GeoIP / ASN / rDNS 富化（需引入外部数据库依赖）。
- 资产上下文（hostname / 区域 / 资产标签，需外部资产源）。
- TCP 流重组、双向上下行精确分流统计。

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

## 7. 后续（不在本次范围）

GeoIP/ASN/rDNS 富化、资产上下文、双向上下行统计、命中频次计数 —— 依赖外部数据源或更大改动，单列专项。
