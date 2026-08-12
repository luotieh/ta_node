# ta_node 事件推送接口新增字段说明

> 版本标识：`schema_version: "1.5"`（未变，向下兼容）
> 所有新增字段均为 `omitempty`，旧版管理端忽略未知字段即可正常运作

---

## 新增顶级字段

### 1. `raw_packet` — 触发包原始报文（RawPacketContext）

包含命中规则/IOC的那个数据包的完整抓包证据。

| 字段 | 类型 | 说明 |
|------|------|------|
| `raw_packet.session_start_time` | `string` | 流首包时间，RFC3339Nano 格式 |
| `raw_packet.session_start_time_usec` | `uint64` | 流首包时间，微秒时间戳 |
| `raw_packet.capture_time` | `string` | 触发包捕获时间，RFC3339Nano |
| `raw_packet.capture_time_usec` | `uint64` | 触发包捕获时间，微秒 |
| `raw_packet.packet_sequence` | `uint64` | 全局包序号（单调递增） |
| `raw_packet.message_direction` | `string` | 报文方向：`"request"` / `"response"` / `"unknown"` |
| `raw_packet.packet_hex` | `string` | 完整帧（含链路/IP/TCP头）十六进制 |
| `raw_packet.payload_hex` | `string` | 传输层载荷十六进制 |
| `raw_packet.payload_text` | `string` | 可打印载荷明文（二进制为空） |
| `raw_packet.captured_length` | `uint32` | 实际抓包长度 |
| `raw_packet.wire_length` | `uint32` | 线缆原始长度 |
| `raw_packet.capture_truncated` | `bool` | `true` 表示 snaplen 截断 |
| `raw_packet.request` | `RawMessageContext` | 请求方向子消息（报文属性同上，增加 `tcp_seq`/`tcp_ack`/`retransmission`） |
| `raw_packet.response` | `RawMessageContext` | 响应方向子消息 |

**字段填充规则**：
- `message_direction == "request"` → `raw_packet.request` 填充
- `message_direction == "response"` → `raw_packet.response` 填充
- `message_direction == "unknown"` → 仅填充顶层字段，`request`/`response` 均为 `null`
- `payload_hex` 对 TCP SYN 握手包可能为空字符串（无应用载荷）

**方向判定逻辑**（`message_direction`）：

| 协议 | 判定依据 |
|------|---------|
| HTTP | 首行以 `GET`/`POST` 等开头 → `"request"`；以 `HTTP/` 开头 → `"response"` |
| DNS | QR 位=0 → `"request"`；=1 → `"response"` |
| TLS | ClientHello → `"request"` |
| TCP（裸）| SYN 不含 ACK → `"request"`；SYN/ACK → `"response"` |

### 2. `session_summary` — 双向会话统计（SessionSummary）

同一 IP 对间正反向流量的双向统计，帮助判断数据流向。

| 字段 | 类型 | 说明 |
|------|------|------|
| `session_summary.first_time_usec` | `uint64` | 双向会话首包时间 |
| `session_summary.last_time_usec` | `uint64` | 双向会话末包时间 |
| `session_summary.client_packets` | `uint64` | 客户端 → 服务端 包数 |
| `session_summary.server_packets` | `uint64` | 服务端 → 客户端 包数 |
| `session_summary.client_wire_bytes` | `uint64` | 客户端 → 服务端 字节 |
| `session_summary.server_wire_bytes` | `uint64` | 服务端 → 客户端 字节 |
| `session_summary.hit_count` | `uint64` | 会话命中次数 |

**客户端/服务端判定**：IP 地址字节序较小的为 client，较大的为 server（对 IPv4 即数值较小者）。

**填充条件**：仅当正反向流量均被捕获到同一个 Pair 时填充，否则为 `null`。

---

## 已有字段新增取值

### `volume_role` — 流量角色

在原有 `"to_ioc"` / `"from_ioc"` 基础上新增 5 个取值：

| 值 | 含义 | 触发条件 |
|----|------|---------|
| `"to_ioc"` | 流量流向 IOC（已有） | DstIP/Domain 匹配 IOC |
| `"from_ioc"` | 流量来自 IOC（已有） | SrcIP 匹配 IOC |
| **`"client_only"`** | **仅客户端有数据（新增）** | 双向统计中 server_bytes = 0 |
| **`"server_only"`** | **仅服务端有数据（新增）** | 双向统计中 client_bytes = 0 |
| **`"upload_to_ioc"`** | **数据外泄（新增）** | client_bytes ≥ server_bytes × 10 |
| **`"download_from_ioc"`** | **载荷投递（新增）** | server_bytes ≥ client_bytes × 10 |
| **`"bidirectional"`** | **双向等量（新增）** | 不符合上述比例 |
| `""` | 无法判定 | 双向统计不可用 |

前 2 个条件由 IOC 类型直接判定（IP/Domain/CIDR），后 5 个由双向流量统计反推。

---

## 完整事件 JSON 示例

```json
{
  "event_id": "evt-a1b2c3d4e5f6789012345678abcdef01",
  "device_id": "node-001",
  "event_time": 1785389881000000,
  "occurrence_time": "2026-07-30T11:51:21Z",
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
  "ioc_tags": ["source:otx", "tlp:white", "otx:tag=\"adaptixc2\""],
  "ioc_description": "[DNS解析自 almacensantangel.com] 命中威胁...",
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
  "duration_ms": 0,
  "flows": 1,
  "packets": 1,
  "bytes": 0,
  "wire_bytes": 74,
  "volume_role": "client_only",
  "raw_packet": {
    "session_start_time": "2026-07-30T11:51:21.000000000Z",
    "session_start_time_usec": 1785389881000000,
    "capture_time": "2026-07-30T11:51:21.000000000Z",
    "capture_time_usec": 1785389881000000,
    "packet_sequence": 1,
    "message_direction": "request",
    "packet_hex": "5254001235020800278e5b3c0800450000340000400040062c4f0a000001c0b956b1...",
    "payload_hex": "",
    "payload_text": "",
    "captured_length": 74,
    "wire_length": 74,
    "capture_truncated": false,
    "request": {
      "capture_time": "2026-07-30T11:51:21.000000000Z",
      "capture_time_usec": 1785389881000000,
      "packet_sequence": 1,
      "packet_hex": "5254001235020800278e5b3c0800450000340000400040062c4f0a000001c0b956b1...",
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
    "client_packets": 1,
    "server_packets": 1,
    "client_wire_bytes": 74,
    "server_wire_bytes": 74,
    "hit_count": 1
  },
  "local_hit_count": 1,
  "local_window_sec": 60,
  "local_first_seen": 1785389881000000,
  "local_scope": "node",
  "schema_version": "1.5",
  "sensor_version": "ccb28036e527-dirty"
}
```

---

## 管理端接入注意事项

1. **向下兼容**：所有新增字段均带 `omitempty`，旧版前端忽略未知 JSON key 即可
2. **`raw_packet.packet_hex`** 包含链路层头（以太网帧），可用于 AI 深度分析。如需仅看 IP 层以上，可跳过前 14 字节
3. **`raw_packet.payload_hex`** 对应传输层载荷，对于纯 TCP SYN 握手可能为空
4. **`session_summary`** 仅在能关联正反向流时填充（需同一 IP 对的两个方向都出现），否则为 `null`
5. **`volume_role`** 取值逻辑：优先用 IOC 类型直接判定（`to_ioc`/`from_ioc`），否则用双向字节比例判定新增的 5 个值
