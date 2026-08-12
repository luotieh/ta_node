# ta_node 安全事件推送 API 文档

> Schema Version: `1.6` | 更新日期: 2026-08-05

---

## 1. 接口概述

| 项目 | 值 |
|------|-----|
| **方法** | `POST` |
| **Content-Type** | `application/json` |
| **认证** | `X-API-Key: <token>`（Header，可选，管理端 `internal_api_key` 不为空时必填） |
| **推送模式** | 批量推送，每批 `push_batch_size` 条（默认 100），间隔 `retry_interval_sec` 秒（默认 30） |
| **失败重试** | 最多 `max_push_retry` 次（默认 20），超限后保留在队列但不再重推 |
| **幂等性** | 事件 ID `event_id` 为 SHA-256，同包同规则重复推送 ID 不变 |

**管理端接入路径**（示例）：

```
POST http://<host>:<port>/traffic/internal/event/push
```

> 注意：节点推送到管理端的**内部推送接口**（`/traffic/internal/event/push`），非前端 `POST /api/v1/intel/*` 或 `/api/v1/event`。

---

## 2. 请求格式

请求体为单条 `ThreatEvent` JSON 对象。批量推送时依次发送。

### 2.1 顶层字段清单

#### 身份与时间

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `event_id` | `string` | ✅ | 事件唯一 ID，格式 `evt-` + 32 位十六进制（SHA-256 前 16 字节） |
| `device_id` | `string` | ✅ | 采集节点标识 |
| `event_time` | `uint64` | ✅ | 事件发生时间，微秒时间戳 |
| `occurrence_time` | `string` | ❌ | RFC3339 UTC 时间（如 `2026-08-05T02:00:00Z`） |
| `schema_version` | `string` | ❌ | 事件格式版本，当前 `"1.6"` |
| `sensor_version` | `string` | ❌ | 节点二进制版本（如 `ccb28036e527-dirty`） |

#### 网络 5 元组

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `src_ip` | `string` | ✅ | 源 IP |
| `src_port` | `uint16` | ✅ | 源端口 |
| `dst_ip` | `string` | ✅ | 目的 IP |
| `dst_port` | `uint16` | ✅ | 目的端口 |
| `proto` | `string` | ✅ | 协议：`tcp` / `udp` / `icmp` |
| `protocol` | `string` | ❌ | 同 `proto`，管理端兼容字段 |
| `direction` | `string` | ✅ | 方向：`inbound` / `outbound` / `lateral` / `external` / `unknown` |

#### 威胁分类

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `event_type` | `string` | ✅ | 事件类型（如 `c2`、`phishing`、`threat`） |
| `event_name` | `string` | ✅ | 命中 IOC 值或规则名称 |
| `severity` | `string` | ✅ | 严重级别：`critical` / `high` / `medium` / `low` |
| `model` | `string` | ✅ | `threat_fingerprint`（规则命中）或 `threat_intel`（IOC 命中） |
| `threat_source` | `string` | ✅ | 威胁来源：`intel_ip` / `intel_domain` / `payload_rule` 等 |

#### 流统计

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `first_time` | `uint64` | ❌ | 流首包时间，微秒 |
| `duration_ms` | `uint64` | ❌ | 流持续时长，毫秒 |
| `flows` | `uint64` | ✅ | 流计数（当前始终为 1） |
| `packets` | `uint64` | ✅ | 该流向已观测包数 |
| `bytes` | `uint64` | ✅ | 载荷总字节 |
| `wire_bytes` | `uint64` | ❌ | 线缆总字节（含 L2-L4 头） |
| `volume_role` | `string` | ❌ | 流量角色（见 [§2.5](#25-volume_role-枚举)） |

#### IOC 字段（仅 `model = threat_intel` 时有效）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `ioc_type` | `string` | ❌ | `ip` / `domain` / `url` / `cidr` |
| `ioc_value` | `string` | ❌ | IOC 值 |
| `ioc_category` | `string` | ❌ | IOC 分类 |
| `ioc_id` | `string` | ❌ | IOC 唯一 ID |
| `ioc_source` | `string` | ❌ | 情报来源 |
| `ioc_tags` | `string[]` | ❌ | 标签 |
| `ioc_description` | `string` | ❌ | 描述 |
| `ioc_expire_at` | `int64` | ❌ | 过期时间，Unix 秒 |
| `recommended_action` | `string` | ❌ | 推荐操作（如 `block_and_report`） |
| `ioc_evidence` | `object` | ❌ | IOC 证据详情（见 [§2.4](#24-ioc_evidence)） |

#### 指纹规则字段（仅 `model = threat_fingerprint` 时有效）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `rule_id` | `string` | ❌ | 规则 ID |
| `threat_index` | `string` | ❌ | 载荷匹配位置，格式 `match_from,match_to` |

#### 应用协议标识

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `service` | `string` | ❌ | 应用层协议标识。优先级：载荷解析 > 端口映射 |

**取值逻辑**：

| 优先 | 来源 | 示例值 |
|------|------|--------|
| 1 | HTTP 载荷解析到方法 | `"HTTP"` |
| 1 | DNS 载荷解析到查询 | `"DNS"` |
| 1 | TLS ClientHello SNI | `"HTTPS"` |
| 2 | 端口 80, 8080, 8000, 8888 | `"HTTP"` |
| 2 | 端口 443, 8443 | `"HTTPS"` |
| 2 | 端口 53 | `"DNS"` |
| 2 | 端口 22 | `"SSH"` |
| 2 | 端口 21 | `"FTP"` |
| 2 | 端口 25, 587 | `"SMTP"` |
| 2 | 端口 3306 | `"MySQL"` |
| 2 | 端口 5432 | `"PostgreSQL"` |
| 2 | 端口 6379 | `"Redis"` |
| 2 | 端口 27017 | `"MongoDB"` |
| 3 | 无法推断 | `""` (空) |

#### 本地突发信号

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `local_hit_count` | `int` | ❌ | 节点本地窗口内命中次数 |
| `local_window_sec` | `int` | ❌ | 统计窗口大小，秒 |
| `local_first_seen` | `uint64` | ❌ | 窗口内首次命中时间，微秒 |
| `local_scope` | `string` | ❌ | 固定 `"node"` |

---

### 2.2 `app` — 应用层上下文（AppContext）

| 字段 | 类型 | 说明 |
|------|------|------|
| `app.http_method` | `string` | HTTP 方法（`GET`/`POST`/…） |
| `app.http_host` | `string` | Host 头 |
| `app.http_url` | `string` | 请求路径 |
| `app.user_agent` | `string` | User-Agent |
| `app.http_headers` | `map<string,string>` | 安全头白名单（Host/Referer/Content-Type/Content-Length/Accept 等） |
| `app.http_body_sample` | `string` | 请求体样本（≤64 字节） |
| `app.dns_query` | `string` | DNS 查询名 |
| `app.dns_qtype` | `uint16` | DNS 查询类型 |
| `app.dns_answers` | `string[]` | DNS 应答 IP |
| `app.tls_sni` | `string` | TLS ClientHello SNI |
| `app.payload_sample` | `string` | 载荷样本（≤64 字节，可打印文本或十六进制） |
| `app.icmp_seq` | `uint32` | ICMP 序列号 |

---

### 2.3 `raw_packet` — 原始报文（RawPacketContext）

| 字段 | 类型 | 说明 |
|------|------|------|
| `raw_packet.session_start_time` | `string` | 流首包时间，RFC3339Nano |
| `raw_packet.session_start_time_usec` | `uint64` | 流首包时间，微秒 |
| `raw_packet.capture_time` | `string` | 触发包捕获时间，RFC3339Nano |
| `raw_packet.capture_time_usec` | `uint64` | 触发包捕获时间，微秒 |
| `raw_packet.packet_sequence` | `uint64` | 全局包序号 |
| `raw_packet.message_direction` | `string` | `request` / `response` / `unknown` |
| `raw_packet.packet_hex` | `string` | 完整帧（含以太网头）十六进制 |
| `raw_packet.payload_hex` | `string` | 传输层载荷十六进制（TCP SYN 时为空） |
| `raw_packet.payload_text` | `string` | 载荷可打印明文（二进制为空） |
| `raw_packet.captured_length` | `uint32` | 实际抓包长度 |
| `raw_packet.wire_length` | `uint32` | 线缆原始长度 |
| `raw_packet.capture_truncated` | `bool` | 是否被 snaplen 截断 |
| `raw_packet.request` | `RawMessageContext` | 请求方向子消息（当 `message_direction = "request"` 时填充） |
| `raw_packet.response` | `RawMessageContext` | 响应方向子消息（当 `message_direction = "response"` 时填充） |

**RawMessageContext**（request/response 子消息）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `capture_time` | `string` | RFC3339Nano |
| `capture_time_usec` | `uint64` | 微秒 |
| `packet_sequence` | `uint64` | 包序号 |
| `packet_hex` | `string` | 帧十六进制 |
| `payload_hex` | `string` | 载荷十六进制 |
| `payload_text` | `string` | 载荷明文 |
| `captured_length` | `uint32` | 抓包长度 |
| `wire_length` | `uint32` | 线缆长度 |
| `capture_truncated` | `bool` | 是否截断 |
| `tcp_seq` | `uint32` | TCP 序列号 |
| `tcp_ack` | `uint32` | TCP 确认号 |
| `retransmission` | `bool` | 是否重传 |

---

### 2.4 `session_summary` — 双向会话统计（SessionSummary）

| 字段 | 类型 | 说明 |
|------|------|------|
| `session_summary.first_time_usec` | `uint64` | 双向会话首包时间 |
| `session_summary.last_time_usec` | `uint64` | 双向会话末包时间 |
| `session_summary.client_packets` | `uint64` | 客户端 → 服务端 包数 |
| `session_summary.server_packets` | `uint64` | 服务端 → 客户端 包数 |
| `session_summary.client_wire_bytes` | `uint64` | 客户端 → 服务端 字节 |
| `session_summary.server_wire_bytes` | `uint64` | 服务端 → 客户端 字节 |
| `session_summary.hit_count` | `uint64` | 命中次数 |

客户端/服务端判定：IP 字节序较小者为 client。

---

### 2.5 `volume_role` 枚举

| 值 | 含义 |
|----|------|
| `"to_ioc"` | 流量流向 IOC（DstIP/Domain 匹配） |
| `"from_ioc"` | 流量来自 IOC（SrcIP 匹配） |
| `"client_only"` | 仅客户端有数据 |
| `"server_only"` | 仅服务端有数据 |
| `"upload_to_ioc"` | client_bytes ≥ server_bytes × 10（数据外泄） |
| `"download_from_ioc"` | server_bytes ≥ client_bytes × 10（载荷投递） |
| `"bidirectional"` | 双方均有数据，比例不悬殊 |
| `""` | 无法判定 |

---

### 2.6 `ioc_evidence` — IOC 证据详情

| 字段 | 类型 | 说明 |
|------|------|------|
| `ioc_evidence.activity` | `string` | 威胁活动描述 |
| `ioc_evidence.threat_labels` | `string[]` | 威胁标签 |
| `ioc_evidence.source` | `string` | 情报源（如 `otx`） |
| `ioc_evidence.cross_check` | `string` | 交叉验证信息 |
| `ioc_evidence.confidence` | `string` | 置信度（如 `high (1 source)`） |
| `ioc_evidence.tlp` | `string` | TLP 等级（如 `white`） |
| `ioc_evidence.misp_event_id` | `string` | MISP 事件 ID |
| `ioc_evidence.narrative` | `string` | 威胁叙述 |

---

## 3. Schema 1.6 新增字段

以下字段为 v1.6 新增，全部 `omitempty`，旧版管理端忽略即可。

### 3.1 `app_stats` — 应用层端点统计

| 字段 | 类型 | 说明 |
|------|------|------|
| `app_stats.window_start_usec` | `uint64` | 统计窗口起始 |
| `app_stats.window_end_usec` | `uint64` | 统计窗口结束 |
| `app_stats.request_count` | `uint64` | 请求数 |
| `app_stats.response_count` | `uint64` | 响应数 |
| `app_stats.http_4xx_count` | `uint64` | 4xx 响应数 |
| `app_stats.http_5xx_count` | `uint64` | 5xx 响应数 |
| `app_stats.p95_latency_ms` | `uint64` | P95 延迟 |
| `app_stats.max_latency_ms` | `uint64` | 最大延迟 |
| `app_stats.endpoints` | `AppEndpoint[]` | 端点聚合明细 |

**AppEndpoint**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `method` | `string` | HTTP 方法 |
| `path` | `string` | 请求路径 |
| `host` | `string` | Host |
| `count` | `uint64` | 命中次数 |
| `user_agents` | `string[]` | UA 列表（去重） |
| `sample_request_body` | `string` | 请求体样本 |

### 3.2 `payload_features` — 载荷特征分类

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | `string` | 特征名（`sqli` / `xss` / `c2_command` / …） |
| `count` | `uint64` | 命中次数 |
| `total_requests` | `uint64` | 参与统计的请求总数 |
| `sample` | `string` | 匹配文本样本（≤300 字符） |
| `confidence` | `int` | 置信度 0–100 |
| `evidence_ref` | `string` | 证据引用 |

### 3.3 `data_exfil` — 数据外传统计

| 字段 | 类型 | 说明 |
|------|------|------|
| `data_exfil.total_wire_bytes` | `uint64` | 双向总字节 |
| `data_exfil.total_packets` | `uint64` | 总包数 |
| `data_exfil.dest` | `string` | 目标 IP/域名 |
| `data_exfil.dest_port` | `uint32` | 目标端口 |
| `data_exfil.encrypted` | `bool` | 是否加密 |
| `data_exfil.sensitive_keywords` | `SensitiveKeyword[]` | 敏感字段命中 |
| `data_exfil.observed_entries` | `uint64` | 疑似外传记录数 |

> 方向由顶层 `volume_role` 提供，`data_exfil` 不重复带 role。

### 3.4 `ioc_stats` — IOC 命中时序

| 字段 | 类型 | 说明 |
|------|------|------|
| `ioc_stats[].ioc_value` | `string` | IOC 值 |
| `ioc_stats[].ioc_type` | `string` | IOC 类型 |
| `ioc_stats[].hit_count` | `uint64` | 窗口内命中次数 |
| `ioc_stats[].first_seen_usec` | `uint64` | 首次命中 |
| `ioc_stats[].last_seen_usec` | `uint64` | 末次命中 |
| `ioc_stats[].threat_source` | `string` | 情报源 |
| `ioc_stats[].confidence` | `string` | 置信度原文 |
| `ioc_stats[].expire_at_usec` | `int64` | 过期时间 |

### 3.5 `rule_stats` — 规则命中时序

| 字段 | 类型 | 说明 |
|------|------|------|
| `rule_stats[].rule_id` | `string` | 规则 ID |
| `rule_stats[].rule_name` | `string` | 规则名称 |
| `rule_stats[].hit_count` | `uint64` | 命中次数 |
| `rule_stats[].first_seen_usec` | `uint64` | 首次命中 |
| `rule_stats[].last_seen_usec` | `uint64` | 末次命中 |
| `rule_stats[].severity` | `string` | 规则级别 |

### 3.6 `impact_hints` — 影响线索

| 字段 | 类型 | 说明 |
|------|------|------|
| `impact_hints.error_rate_percent` | `float64` | 错误率 |
| `impact_hints.latency_degraded` | `bool` | 延迟是否劣化 |
| `impact_hints.latency_baseline_ms` | `uint64` | 基线 P95 |
| `impact_hints.latency_observed_ms` | `uint64` | 当前 P95 |
| `impact_hints.affected_entries` | `uint64` | 受影响条目数 |
| `impact_hints.observed_intent` | `string` | `brute_force` / `exfiltration` / `recon` / `payload_delivery` / `unknown` |
| `impact_hints.intent_basis` | `string` | 判定依据 |

### 3.7 `action_hints` — 处置建议

| 字段 | 类型 | 说明 |
|------|------|------|
| `action_hints[].action` | `string` | `block_ip` / `block_domain` / `save_evidence` / `notify_owner` |
| `action_hints[].priority` | `string` | `immediate` / `followup` |
| `action_hints[].reason` | `string` | 触发理由 |
| `action_hints[].evidence_ref` | `string` | 证据引用 |

### 3.8 `evidence_files` — 证据附件

| 字段 | 类型 | 说明 |
|------|------|------|
| `evidence_files[].id` | `string` | 附件 ID（完整本地路径） |
| `evidence_files[].name` | `string` | 文件名 |
| `evidence_files[].type` | `string` | `"pcap"`（PCAP 证据文件） |
| `evidence_files[].path_ref` | `string` | **下载 URL 路径**，管理端拼接 `http://<host>:<port><path_ref>` 即可下载，详见 §5.4 |
| `evidence_files[].sha256` | `string` | 文件哈希（预留） |
| `evidence_files[].size` | `uint64` | 文件大小（预留） |
| `evidence_files[].description` | `string` | 说明 |

### 3.9 `severity_basis` — 级别依据

| 字段 | 类型 | 说明 |
|------|------|------|
| `severity_basis.score` | `int` | 0–100 评分 |
| `severity_basis.reasons` | `string[]` | 评分理由列表 |

**计分规则**：

| 维度 | 分值 | 条件 |
|------|------|------|
| IOC/规则级别 | +40 | severity = `critical` |
| | +25 | severity = `high` |
| | +15 | severity = `medium` |
| | +5 | 其他 |
| 情报置信度 | +15 | 含 IOC evidence 信息 |
| 窗口高频命中 | +20 | `local_hit_count > 10` |
| 窗口低频命中 | +10 | `local_hit_count > 1` |
| 威胁类型 | +10 | category ≠ `network_activity` |
| C2 通信 | +10 | event_type = `c2` |
| 双向流量 | +10 | `data_exfil.total_wire_bytes > 0` |

总分封顶 100。

---

## 4. 完整示例

```json
{
  "event_id": "evt-a1b2c3d4e5f6789012345678abcdef01",
  "device_id": "node-001",
  "event_time": 1785389881000000,
  "occurrence_time": "2026-08-05T02:00:00Z",
  "event_type": "c2",
  "event_name": "192.185.86.177",
  "severity": "high",
  "model": "threat_intel",
  "src_ip": "172.16.100.16",
  "src_port": 54321,
  "dst_ip": "192.185.86.177",
  "dst_port": 443,
  "proto": "tcp",
  "protocol": "tcp",
  "direction": "outbound",
  "threat_source": "intel_ip",
  "ioc_type": "ip",
  "ioc_value": "192.185.86.177",
  "ioc_category": "c2",
  "ioc_id": "e7ad34cd80e6cb5a1e804e867b495f826aabf17c29f2c386db2e909c4f2dcaa6",
  "ioc_source": "Threat Intel Hub",
  "ioc_tags": ["source:otx", "tlp:white"],
  "ioc_description": "命中威胁: Unpacking Cruciferra...",
  "ioc_expire_at": 1785119525,
  "recommended_action": "block_and_report",
  "ioc_evidence": {
    "activity": "Unpacking \"Cruciferra\": An Analysis...",
    "threat_labels": ["adaptixc2", "defense-evasion"],
    "source": "otx",
    "confidence": "high (1 source)",
    "tlp": "white",
    "misp_event_id": "6a5dec09c0c4b7d2a00d7b2c"
  },
  "first_time": 1785389881000000,
  "duration_ms": 120,
  "flows": 1,
  "packets": 3,
  "bytes": 0,
  "wire_bytes": 222,
  "volume_role": "client_only",
  "app": {
    "tls_sni": "192.185.86.177"
  },
  "raw_packet": {
    "session_start_time": "2026-08-05T02:00:00.000000000Z",
    "session_start_time_usec": 1785389881000000,
    "capture_time": "2026-08-05T02:00:00.000000000Z",
    "capture_time_usec": 1785389881000000,
    "packet_sequence": 3,
    "message_direction": "request",
    "packet_hex": "5254001235020800278e5b3c0800...",
    "payload_hex": "",
    "payload_text": "",
    "captured_length": 74,
    "wire_length": 74,
    "capture_truncated": false,
    "request": {
      "capture_time": "2026-08-05T02:00:00.000000000Z",
      "capture_time_usec": 1785389881000000,
      "packet_sequence": 3,
      "packet_hex": "5254001235020800278e5b3c0800...",
      "payload_hex": "",
      "payload_text": "",
      "captured_length": 74,
      "wire_length": 74,
      "capture_truncated": false,
      "tcp_seq": 1000,
      "tcp_ack": 0,
      "retransmission": false
    }
  },
  "session_summary": {
    "first_time_usec": 1785389881000000,
    "last_time_usec": 1785389881500000,
    "client_packets": 2,
    "server_packets": 1,
    "client_wire_bytes": 148,
    "server_wire_bytes": 74,
    "hit_count": 1
  },
  "local_hit_count": 1,
  "local_window_sec": 60,
  "local_first_seen": 1785389881000000,
  "local_scope": "node",
  "evidence_file": "data/evidence/evt-a1b2c3d4e5f6789012345678abcdef01.pcap",
  "packet_time_usec": 1785389881000000,
  "schema_version": "1.6",
  "sensor_version": "ccb28036e527-dirty",
  "data_exfil": {
    "total_wire_bytes": 222,
    "total_packets": 3,
    "dest": "192.185.86.177",
    "dest_port": 443,
    "observed_entries": 2
  },
  "ioc_stats": [{
    "ioc_value": "192.185.86.177",
    "ioc_type": "ip",
    "hit_count": 1,
    "first_seen_usec": 1785389881000000,
    "last_seen_usec": 1785389881000000,
    "threat_source": "Threat Intel Hub",
    "confidence": "high (1 source)",
    "expire_at_usec": 1785119525
  }],
  "action_hints": [
    {"action": "block_ip", "priority": "immediate", "reason": "命中 IP 型 IOC: 192.185.86.177"},
    {"action": "block_and_report", "priority": "followup", "reason": "情报推荐动作"}
  ],
  "impact_hints": {
    "affected_entries": 3,
    "observed_intent": "exfiltration",
    "intent_basis": "单向大流量：客户端字节远超服务端"
  },
  "evidence_files": [{
    "id": "data/evidence/node-001/2026-08-06/a1/evt-a1b2c3d4...pcap",
    "name": "evt-a1b2c3d4...pcap",
    "type": "pcap",
    "path_ref": "/api/v1/evidence/node-001/2026-08-06/a1/evt-a1b2c3d4...pcap",
    "description": "触发包 PCAP 证据"
  }],
  "severity_basis": {
    "score": 70,
    "reasons": ["高级别 IOC/规则", "情报源置信度: high (1 source)", "C2 命令与控制通信", "观测到双向流量 0.2 KB"]
  },
  "service": "HTTPS"
}
```

---

## 5. 管理端接入

### 5.1 接收端处理

```go
func ingestEvent(data []byte) error {
    var ev event.ThreatEvent
    if err := json.Unmarshal(data, &ev); err != nil {
        return err
    }
    // ev.SchemaVersion == "1.6": 可读取新字段
    // ev.SchemaVersion == "1.5": 新字段为 null/空
    // 所有新字段均为 omitempty，旧版忽略即可
    //
    // 关键 v1.6 新增字段:
    //   ev.Service           — 应用协议（HTTP/HTTPS/DNS/SSH/MySQL...）
    //   ev.EvidenceFiles     — 证据 PCAP 下载 URL
    //   ev.SeverityBasis     — 0-100 评分 + 理由
    //   ev.DataExfil         — 外传统计
    //   ev.AppStats          — 端点聚合
    //   ev.PayloadFeatures   — 载荷特征分类
    //   ev.IOCStats          — IOC 窗口命中
    //   ev.RuleStats         — 规则窗口命中
    //   ev.ActionHints       — 处置建议
    //   ev.ImpactHints       — 影响线索
}
```

### 5.2 未知字段处理

所有字段均为 `omitempty`，旧版管理端直接忽略未知 JSON key 即可正常工作。新管理端对缺失字段隐藏对应的报告章节。

### 5.3 event_id 去重

`event_id` 为 SHA-256，管理端可用其做幂等去重。同包同规则重复推送 `event_id` 不变。

### 5.4 证据 PCAP 文件下载

节点提供证据文件下载接口，管理端通过事件中的 `evidence_files[].path_ref` 获取完整下载 URL。

**端点**：`GET /api/v1/evidence/{relative_path}`

**存储结构**：按设备 ID → 日期 → 哈希分桶（256 子目录）：

```
data/evidence/<device_id>/
    2026-08-10/
        a1/  evt-a1b2c3d4...pcap
        ff/  evt-ff2b3c4d...pcap
        ...
    2026-08-09/
        3c/  evt-3c...pcap
        ...
    2026-07.zip   ← 上月已归档
```

- **哈希分桶**：取 `event_id` 第 5-6 位 hex（`evt-` 后前 2 位），将单日文件均匀分布到 256 个子目录
- **过期清理**：每小时扫描，删除超出 `retain_days`（默认 7 天）的整个日级目录
- **月度归档**：每日滚动，将上月日级目录压缩为 `.zip` 后删除原目录

**示例**：

```
# 事件中的 evidence_files 字段（含哈希路径）
{
  "evidence_files": [{
    "id": "data/evidence/node-arm-offline-001/2026-08-06/a1/evt-xxx.pcap",
    "name": "evt-xxx.pcap",
    "type": "pcap",
    "path_ref": "/api/v1/evidence/node-arm-offline-001/2026-08-06/a1/evt-xxx.pcap",
    "description": "触发包 PCAP 证据"
  }]
}

# 管理端拼接完整 URL
GET http://<node_host>:25640/api/v1/evidence/node-arm-offline-001/2026-08-06/a1/evt-xxx.pcap
```

**响应**：`Content-Type: application/vnd.tcpdump.pcap`，标准 PCAP 文件（含全局头 + 触发包帧）。

**安全**：仅允许 `GET` 请求，拒绝含 `..` 的路径遍历。

### 5.5 证据文件管理

节点自动执行以下维护任务：

| 任务 | 频率 | 行为 |
|------|------|------|
| 过期清理 | 每小时 | 删除 `retain_days`（默认 7）之前的整个日级目录 |
| 月度归档 | 每日 | 将上月日级目录压缩为 `.zip`，删除原目录 |
| 哈希分桶 | 实时 | 写入时自动按事件 ID 前 2 位 hex 分到 256 子目录 |

**配置项**：

```yaml
evidence:
  retain_days: 7           # PCAP 保留天数，超期自动删除；0=不清理
  hash_evidence_dir: true  # 按事件 ID 前 2 位 hex 哈希分桶（256 子目录）
  archive_monthly: true    # 每月将上月目录压缩为 zip 归档
```

**归档文件命名**：`<YYYY-MM-DD>.zip`，存放在设备目录下，内含当日全部哈希子目录及 PCAP 文件。
