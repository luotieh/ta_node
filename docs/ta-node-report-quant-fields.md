# ta_node（融合采集节点）新增字段说明 — 安全事件量化报告

> 版本标识：`schema_version: "1.6"`（1.5 基础上新增，向下兼容）
> 配套报告模版：`docs/security_incident_report_template.md`
> 管理端接入文档：`docs/event-fields-enhancement.md`（1.5 字段基线）
> **实现状态：evidence_files, severity_basis, data_exfil, ioc_stats, rule_stats, action_hints, impact_hints 已落地；payload_features 和 app_stats 待后续实现**

## 1. 背景与职责划分

新报告模版要求输出**可验证的量化数据**（如"5 分钟内 12,847 次请求、32% 带 SQL 注入特征、
1.2GB 数据外传、IOC 24 小时内命中 3 次"）。管理端已具备全局聚合能力
（`occurrence_count`、首末次时间、总字节/包数、规则/IOC 分布、5 分钟峰值窗口），
但以下细粒度数据**必须由采集节点在本地窗口内统计后下发**：

| 数据 | 责任方 |
| --- | --- |
| 单次命中事件字段（src/dst/rule/ioc/app/raw_packet/session_summary 等） | 节点（已有，1.5） |
| 节点本地窗口内的**应用层聚合**（端点/方法/UA/请求数/响应码/延迟） | 节点（新增） |
| 载荷特征分类计数（SQL注入/C2指令/敏感数据等）与置信度 | 节点（新增） |
| 数据外传统计（方向、总量、敏感关键词命中） | 节点（新增） |
| IOC/规则在节点窗口内的重复命中统计 | 节点（新增） |
| 业务影响观测（4xx/5xx、延迟）与攻击意图线索 | 节点（新增，观测型） |
| 处置建议与证据附件清单 | 节点（新增） |
| 全局聚合频次、速率、峰值窗口、月度总结 | 管理端（已有） |
| 定性结论、影响叙事、IOC 有效性解释 | LLM（管理端） |

**原则**：节点只上报"看到的事实"，不做定性结论；数字由节点计数，叙事由管理端 LLM 生成。

## 2. 新增顶级字段总览

以下字段全部为顶层 `omitempty`，未实现时管理端报告相应章节自动隐藏，不影响旧流程。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `app_stats` | `object` | 节点本地窗口内应用层流量聚合（HTTP/DNS） |
| `payload_features` | `array<object>` | 载荷特征分类计数（SQLi/C2/敏感数据等） |
| `data_exfil` | `object` | 数据外传/下载观测统计 |
| `ioc_stats` | `array<object>` | 节点窗口内 IOC 重复命中统计 |
| `rule_stats` | `array<object>` | 节点窗口内规则命中统计 |
| `impact_hints` | `object` | 业务影响与攻击意图的观测线索 |
| `action_hints` | `array<object>` | 处置建议（供管理端采纳） |
| `evidence_files` | `array<object>` | 证据附件清单（PCAP/截图/解码样本） |
| `severity_basis` | `object` | 级别判定依据（分数与理由） |

## 3. 字段明细

### 3.1 `app_stats` — 应用层聚合（对应报告"关键流量证据"）

节点在本地统计窗口（建议与 `local_window_sec` 对齐，默认 60 秒）内按目标端点聚合：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `window_start_usec` | `uint64` | 是 | 统计窗口起始（微秒） |
| `window_end_usec` | `uint64` | 是 | 统计窗口结束（微秒） |
| `request_count` | `uint64` | 是 | 窗口内请求总数（HTTP 首行或 DNS 查询计数） |
| `response_count` | `uint64` | 否 | 已观测到响应的请求数 |
| `endpoints` | `array<object>` | 否 | 端点聚合明细，上限 50 条 |
| `http_4xx_count` | `uint64` | 否 | 4xx 响应数（业务影响线索） |
| `http_5xx_count` | `uint64` | 否 | 5xx 响应数 |
| `p95_latency_ms` | `uint64` | 否 | 观测到的响应延迟 P95（毫秒） |
| `max_latency_ms` | `uint64` | 否 | 观测到的最大延迟 |

`endpoints[]` 元素：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `method` | `string` | `GET`/`POST`/… |
| `path` | `string` | 请求路径（不含 query，或含归一化 query） |
| `host` | `string` | Host 头 |
| `count` | `uint64` | 命中该端点的请求数 |
| `user_agents` | `array<string>` | 去重 UA 列表，上限 10 条 |
| `sample_request_body` | `string` | 请求体样本，上限 300 字符，可含脱敏标记 |

### 3.2 `payload_features` — 载荷特征分类（对应"恶意载荷特征/百分比"）

节点对请求/响应载荷做规则化分类，只报"命中特征 + 次数"，不下定性结论：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `name` | `string` | 特征名，如 `sqli` / `xss` / `c2_command` / `path_traversal` / `sensitive_data` / `credential_brute` |
| `count` | `uint64` | 窗口内命中次数 |
| `total_requests` | `uint64` | 参与统计的请求总数（管理端据此算占比：count/total_requests） |
| `sample` | `string` | 样本摘要，上限 300 字符，敏感内容脱敏 |
| `confidence` | `int` | 0–100，特征判定的确定性（如 95） |
| `evidence_ref` | `string` | 证据引用（如 `rule_id`、`evidence_files[].id`） |

示例：`{"name":"sqli","count":4096,"total_requests":12800,"sample":"card_number=' OR 1=1--","confidence":100}`

### 3.3 `data_exfil` — 数据外传观测（对应"数据外传痕迹/数据风险"）

> **> 方向由事件顶层 `volume_role` 提供，`data_exfil` 不重复携带 `role` 字段。**

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `total_wire_bytes` | `uint64` | 窗口内该方向总字节（含 L2-L4 头） |
| `total_packets` | `uint64` | 总包数 |
| `dest` | `string` | 目标 IP/域名 |
| `dest_port` | `uint32` | 目标端口 |
| `encrypted` | `bool` | 载荷是否加密/TLS |
| `sensitive_keywords` | `array<object>` | 敏感字段命中：`{keyword, count, sample}`，上限 20 条 |
| `observed_entries` | `uint64` | 疑似外传记录条数 |

### 3.4 `ioc_stats` — IOC 重复命中（对应"IOC关联验证 / IOC有效性"）

> **> 职责分工：顶层 `ioc_*` 字段携带单条 IOC 静态属性（ID、值、类型、描述等）；`ioc_stats` 仅补窗口级时序聚合（命中次数、首末时间），不重复 `ioc_value`/`ioc_type` 以外的字段。**

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `ioc_value` | `string` | IOC 值（与顶层一致，便于窗口维度聚合查询） |
| `ioc_type` | `string` | `ip` / `domain` / `url` |
| `hit_count` | `uint64` | 节点本地窗口内命中次数（取自 `local_hit_count`） |
| `first_seen_usec` | `uint64` | 窗口内首次命中（取自 `local_first_seen`） |
| `last_seen_usec` | `uint64` | 窗口内末次命中 |
| `threat_source` | `string` | 情报源（如 `otx`） |
| `confidence` | `string` | 情报置信度原文（取自 IOC evidence） |
| `expire_at_usec` | `int64` | IOC 过期时间 |

### 3.5 `rule_stats` — 规则命中统计（对应"证据来源/规则触发"）

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `rule_id` | `string` | 规则 ID，如 `SEC-CC-001` |
| `rule_name` | `string` | 规则名称 |
| `hit_count` | `uint64` | 窗口内命中次数 |
| `first_seen_usec` | `uint64` | 首次命中 |
| `last_seen_usec` | `uint64` | 末次命中 |
| `severity` | `string` | 规则级别 |
| `evidence_ref` | `string` | 证据引用 |

### 3.6 `impact_hints` — 影响观测线索（对应"影响评估"）

节点只填**可观测事实**，不写结论性文字；缺少数据时整个块省略：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `error_rate_percent` | `float64` | 窗口内 4xx/5xx 占比 |
| `latency_degraded` | `bool` | P95 延迟是否显著高于基线（如 >2×） |
| `latency_baseline_ms` | `uint64` | 基线 P95（如有） |
| `latency_observed_ms` | `uint64` | 当前 P95 |
| `affected_entries` | `uint64` | 疑似受影响请求/记录数 |
| `observed_intent` | `string` | 观测线索枚举：`brute_force` / `exfiltration` / `recon` / `payload_delivery` / `unknown` |
| `intent_basis` | `string` | 判定依据（如 `大量 401 后成功、字段名含 card_number`） |

### 3.7 `action_hints` — 处置建议（对应"立即行动项/后续处置项"）

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `action` | `string` | 动作：`block_ip` / `block_domain` / `enable_waf_rule` / `save_evidence` / `notify_owner` |
| `priority` | `string` | `immediate` / `followup` |
| `reason` | `string` | 触发理由（引用数字，如 `request_rate=256/min`） |
| `evidence_ref` | `string` | 证据引用 |

### 3.8 `evidence_files` — 证据附件（对应"附件清单"）

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | `string` | 附件 ID（供 `evidence_ref` 引用） |
| `name` | `string` | 文件名，如 `SEC-ALERT-xxx_evidence.zip` |
| `type` | `string` | `pcap` / `screenshot` / `decoded_sample` / `netflow_log` / `ioc_report` |
| `path_ref` | `string` | 对象存储 key 或路径 |
| `sha256` | `string` | 哈希（若已生成） |
| `size` | `uint64` | 字节数 |
| `description` | `string` | 说明 |

### 3.9 `severity_basis` — 级别依据（对应"事件级别（判定依据）"）

**计分规则**（节点本地评分，管理端会结合全局风险分做最终判定）：

| 维度 | 分值 | 条件 |
| --- | --- | --- |
| IOC/规则严重级别 | +40 | severity = `critical` |
| IOC/规则严重级别 | +25 | severity = `high` |
| IOC/规则严重级别 | +15 | severity = `medium` |
| IOC/规则严重级别 | +5 | severity = `low` 或未知 |
| 情报源置信度 | +15 | IOC 含 evidence 信息 |
| 窗口高频命中 | +20 | `local_hit_count > 10` |
| 窗口低频命中 | +10 | `local_hit_count > 1` |
| 威胁类型加成 | +10 | category ≠ `network_activity` |
| C2 通信 | +10 | event_type = `c2` |
| 双向流量观测 | +10 | `data_exfil.total_wire_bytes > 0` |

总分封顶 100。每项命中后对应的理由字符串写入 `reasons` 数组。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `score` | `int` | 节点侧评分 0–100 |
| `reasons` | `array<string>` | 理由列表 |

## 4. 聚合语义与限制

1. **窗口**：`app_stats` / `payload_features` / `ioc_stats` / `rule_stats` 均以节点本地窗口统计，窗口起点由 `window_start_usec` 标明；管理端负责跨窗口/跨事件求和，不会把节点局部计数当成全局权威频次（全局以管理端 `occurrence_count` 为准）。
2. **占比**：管理端用 `payload_features[].count / total_requests` 计算百分比，节点不需要预计算百分比，避免口径分歧。
3. **上限与截断**：`endpoints ≤ 50`、`payload_features ≤ 20`、`ioc_stats ≤ 50`、`rule_stats ≤ 50`、`sensitive_keywords ≤ 20`、`action_hints ≤ 10`、`evidence_files ≤ 10`；样本字符串 ≤ 300 字符，超出截断并追加 `…(truncated)`。
4. **置信度**：`payload_features[].confidence` 为 0–100 整数；`ioc_stats[].confidence` 保留情报原文。
5. **脱敏**：样本与敏感字段命中必须脱敏（卡号/密码/Token 打码），证据文件按管理端策略脱敏后上传。
6. **兼容**：全部 `omitempty`；`schema_version` 升为 `"1.6"`，旧管理端忽略新字段，新管理端对缺失字段隐藏对应报告章节。

## 5. 与报告模版字段的映射

| 报告章节/字段 | 主要数据来源 |
| --- | --- |
| 三.1 关键流量证据（异常流量模式） | `app_stats` + `rule_stats` + 管理端 `quant_stats` |
| 三.1 恶意载荷特征（32% SQLi / 15% C2） | `payload_features`（count/total_requests/confidence） |
| 三.1 数据外传痕迹（1.2GB / 加密字段） | `data_exfil` + `session_summary` + `volume_role` |
| 三.2 IOC 关联验证 | `ioc_stats` + `ioc` + `ioc_evidence` |
| 三.3 IOC 有效性说明（24h 3 次/新注册域名） | `ioc_stats.first/last_seen` + 管理端聚合 + 情报 WHOIS |
| 四 影响评估（延迟/失败率/外传条数） | `impact_hints`（观测） + `data_exfil` + 管理端/站点监测 |
| 五 处置建议 | `action_hints` + `recommended_action` + 管理端阈值规则 |
| 六 附件清单 | `evidence_files` + 管理端证据包 |
| 一 事件级别判定依据 | `severity_basis` + 管理端风险评分 |

## 6. 完整 JSON 示例（仅新增块）

```json
{
  "event_id": "evt-report-quant-001",
  "device_id": "node-001",
  "event_type": "cc_attack",
  "occurrence_time": "2026-08-05T02:00:00Z",
  "src_ip": "185.143.223.102",
  "dst_ip": "10.20.30.8",
  "direction": "inbound",
  "rule_id": "SEC-CC-001",
  "ioc_value": "185.143.223.102",
  "ioc_type": "ip",
  "schema_version": "1.6",
  "app_stats": {
    "window_start_usec": 1785409200000000,
    "window_end_usec": 1785409500000000,
    "request_count": 12847,
    "response_count": 12700,
    "http_4xx_count": 3411,
    "http_5xx_count": 987,
    "p95_latency_ms": 3200,
    "max_latency_ms": 8900,
    "endpoints": [
      {
        "method": "POST",
        "path": "/api/payment/validate",
        "host": "pay.example.com",
        "count": 12847,
        "user_agents": ["Mozilla/5.0 (X11; Linux x86_64; rv:102.0)"]
      }
    ]
  },
  "payload_features": [
    {
      "name": "sqli",
      "count": 4111,
      "total_requests": 12847,
      "sample": "card_number=***' OR 1=1--",
      "confidence": 100,
      "evidence_ref": "WAF-PCAP-20260805-001"
    },
    {
      "name": "c2_command",
      "count": 1927,
      "total_requests": 12847,
      "sample": "X-Command: EXEC /bin/sh (base64)",
      "confidence": 95,
      "evidence_ref": "WAF-PCAP-20260805-001"
    }
  ],
  "data_exfil": {
    "role": "to_ioc",
    "total_wire_bytes": 1288490188,
    "total_packets": 20480,
    "dest": "185.143.223.102",
    "dest_port": 443,
    "encrypted": true,
    "observed_entries": 3142,
    "sensitive_keywords": [
      { "keyword": "card_number", "count": 3142, "sample": "card_number=****" }
    ]
  },
  "ioc_stats": [
    {
      "ioc_value": "185.143.223.102",
      "ioc_type": "ip",
      "hit_count": 3,
      "first_seen_usec": 1785405000000000,
      "last_seen_usec": 1785409200000000,
      "threat_source": "otx",
      "confidence": "high (1 source)",
      "matched_rules": ["SEC-CC-001"]
    }
  ],
  "rule_stats": [
    {
      "rule_id": "SEC-CC-001",
      "rule_name": "CC 攻击高频请求",
      "hit_count": 12847,
      "first_seen_usec": 1785405000000000,
      "last_seen_usec": 1785409200000000,
      "severity": "high"
    }
  ],
  "impact_hints": {
    "error_rate_percent": 34.2,
    "latency_degraded": true,
    "latency_baseline_ms": 480,
    "latency_observed_ms": 3200,
    "affected_entries": 3142,
    "observed_intent": "brute_force",
    "intent_basis": "POST /api/payment/validate 高频 4xx，字段含 card_number"
  },
  "action_hints": [
    { "action": "block_ip", "priority": "immediate", "reason": "request_rate=256/min, sqli=32%", "evidence_ref": "SEC-CC-001" },
    { "action": "enable_waf_rule", "priority": "immediate", "reason": "payload_features.sqli=4111", "evidence_ref": "WAF-PCAP-20260805-001" }
  ],
  "evidence_files": [
    {
      "id": "WAF-PCAP-20260805-001",
      "name": "SEC-ALERT-20260805-001_evidence.zip",
      "type": "pcap",
      "path_ref": "evidence/node-001/evt-report-quant-001/pcap",
      "sha256": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
      "size": 10485760,
      "description": "触发窗口 PCAP 片段（脱敏）"
    }
  ],
  "severity_basis": {
    "score": 92,
    "reasons": ["命中 C2/CC 规则 SEC-CC-001", "窗口 5 分钟 12847 次请求", "34% 请求带 SQL 注入特征"]
  }
}
```

## 7. 管理端接入计划（供两端对齐）

管理端 `event_mapping.go` 将在现有 `putIfPresent` 链路上新增透传：

```go
putIfPresent(context, "app_stats", ly["app_stats"])
putIfPresent(context, "payload_features", ly["payload_features"])
putIfPresent(context, "data_exfil", ly["data_exfil"])
putIfPresent(context, "ioc_stats", ly["ioc_stats"])
putIfPresent(context, "rule_stats", ly["rule_stats"])
putIfPresent(context, "impact_hints", ly["impact_hints"])
putIfPresent(context, "action_hints", ly["action_hints"])
putIfPresent(context, "evidence_files", ly["evidence_files"])
putIfPresent(context, "severity_basis", ly["severity_basis"])
```

字段名以此文档为准；节点侧有实现难度或缺失的块直接不发送，报告相应章节自动隐藏。

## 8. 节点端实现细节

### 8.1 `payload_features` 实现方案

扩展 `fingerprint/` 规则格式，增加分类元数据字段：

```yaml
# patterns/sqli.yaml
items:
  - id: PF-SQLI-001
    class: sqli                # 载荷分类标签
    type: threat
    name: SQL Injection
    pattern: "(?i)(union\\s+select|or\\s+1=1|select.*from.*information_schema)"
    confidence: 95             # 置信度 0–100
```

**改动清单**：

| 文件 | 改动 | 说明 |
|------|------|------|
| `fingerprint/types.go` | +3 字段 | `Class string`、`Confidence int`、`TotalMatched int` |
| `fingerprint/pattern.go` | +15 行 | `PatternRule.Match()` 返回 class+confidence；新增 `Classify()` 公共方法 |
| `detector/engine.go` | +40 行 | 按 `class` 聚合窗口计数，生成 `payload_features[]` |

**聚合规则**：
- 窗口内按 `rule.Class` 分组，每组统计 `count`（命中次数）
- `total_requests` 取窗口内总 HTTP 请求数（来自 `app_stats.request_count`）
- `confidence` 取该类所有命中规则的加权平均
- `sample` 取首个命中包的文本摘要（≤300 字符，脱敏）
- 上限 20 组，按 `count` 降序截断

### 8.2 `app_stats` 实现方案

**缺失能力及解决**：

| 能力 | 当前状态 | 实现方式 |
|------|---------|---------|
| HTTP 状态码 | `parseHTTP` 响应分支仅设置方向，未提取状态码 | 解析 `HTTP/1.1 200 OK` 首行，提取整数状态码 |
| 端点聚合 | 无窗口级聚合 | `Engine` 上挂 `map[string]*endpointAgg`，按 `host+method+path` 去重 |
| 延迟估算 | 无请求-响应关联 | 同 5 元组中，响应时间 − 请求时间。P95 用排序 ring buffer |
| 内存上限 | 流表 100 万上限 | 端点 ≤ 50 条，按 `count` 降序保留 top 50 |

**HTTP 状态码解析**（`parser/parser.go`）：

```go
// 追加到 parseHTTP 响应分支（现有代码位置之后）
if bytes.HasPrefix(pf.Payload, []byte("HTTP/")) {
    pf.MessageDirection = "response"
    // 提取状态码: "HTTP/1.1 200 OK\r\n..." -> 200
    if len(pf.Payload) > 12 && pf.Payload[9] == ' ' {
        code := pf.Payload[9:12]
        if n, err := strconv.Atoi(string(code)); err == nil && n >= 100 {
            pf.HTTPStatusCode = uint16(n)
        }
    }
    return
}
```

**端点聚合**（`detector/engine.go`，新增 `WindowAgg` 内部字段）：

```go
type endpointAgg struct {
    host       string
    method     string
    path       string
    count      uint64
    userAgents map[string]bool
    sampleBody string
}

// Engine 新增窗口聚合器（内部，不导出）
e.endpointMap map[string]*endpointAgg  // key: host+method+path[:50]
e.totalReqs   uint64
e.totalResps  uint64
e.code4xx     uint64
e.code5xx     uint64
e.latencies   *latencyRing  // 固定容量 1000 条，P95 取顶
```

**改动清单**：

| 文件 | 改动 | 说明 |
|------|------|------|
| `parser/parser.go` | +5 行 | HTTP 状态码提取 |
| `flow/flow.go` | +1 字段 | `FlowFeature.HTTPStatusCode uint16` |
| `flow/aggregator.go` | +1 行 | `attachAppContext` 透传 `HTTPStatusCode` |
| `detector/engine.go` | +60 行 | `WindowAgg` 字段 + `aggregate()` 方法 + `buildAppStats()` 方法 |

### 8.3 总体改动量

| 组件 | 文件数 | 代码行数 | 新依赖 |
|------|--------|---------|--------|
| `payload_features` | 3 文件 | ~55 行 | 无 |
| `app_stats` | 4 文件 | ~66 行 | 无 |
| **合计** | **5 文件** | **~120 行** | **无** |

无新增包，无外部依赖，在当前架构内完成。
