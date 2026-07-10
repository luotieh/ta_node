# 安全事件推送 Schema 1.3 — 情报富化字段对接说明

面向管理端 / 后端团队。描述 `schema_version` 由 `1.2` 升到 `1.3` 时，节点推送的安全事件新增的两个情报富化字段。

## 1. 背景

内网节点通过网闸接收外网投递的 IOC 规则包（`/data/yt/ioc/*.zip`），规则携带
`evidence`（威胁证据）与 `recommended_action`（建议处置）等富字段。当流量命中这类
IOC 规则、形成安全事件时，节点会把这些富字段一并推送给管理端，供告警展示与 AI 分析。

**接口未变，仅在事件 JSON 上增量新增字段。**

## 2. 推送接口（不变）

- 方法 / 地址：`POST {management_url}`
  - 默认：`http://<host>:<port>/traffic/internal/event/push`
- 认证：`X-API-Key: <node.api_key>`（管理端设置了 `internal_api_key` 时必带；开放时可空）
- Content-Type：`application/json`
- Body：单个安全事件 JSON 对象（一个事件一次 POST）

## 3. 新增字段

均位于事件 JSON **顶层**，均 `omitempty`（缺省即不出现），纯增量、向后兼容。

| 字段 | 类型 | 出现条件 | 说明 |
|---|---|---|---|
| `recommended_action` | string | intel 命中且情报带该值 | 建议处置动作，如 `block_and_report` |
| `ioc_evidence` | object | intel 命中且情报带 evidence | 情报富化证据，嵌套对象，见下表 |

### `ioc_evidence` 对象

| 字段 | 类型 | 可空 | 说明 |
|---|---|---|---|
| `activity` | string | 是 | 关联威胁活动 / 战役名 |
| `threat_labels` | string[] | 是 | 威胁标签，如 `["ransomware","c2"]` |
| `source` | string | 是 | 情报来源，如 `otx` |
| `cross_check` | string | 是 | 交叉验证结论，如 `WhoisXML=malware, seen 2026-07-07~2026-07-09` |
| `confidence` | string | 是 | 置信度，如 `high (2 sources)` |
| `tlp` | string | 是 | TLP 等级，如 `white` |
| `misp_event_id` | string | 是 | MISP 事件 id |
| `narrative` | string | 是 | 中文告警叙述，供展示 / AI 分析 |

## 4. 出现范围与缺省语义

- 仅 **威胁情报（intel）命中**事件可能携带这两个字段；**指纹（fingerprint）命中**事件不带。
- 本地手工录入的 IOC、或情报未附带 evidence 时，字段不出现。
- 因均为 `omitempty`：解析方**必须容忍字段缺失**，不得假定一定存在。

## 5. 兼容性

- `schema_version` 由 `1.2` 升为 `1.3`；管理端可据此判断是否解析新字段。
- 纯增量新增，老消费者忽略未知字段即可正常解析，无需改造即兼容。
- `ioc_evidence` 为**嵌套对象**（非扁平字段）。若管理端为宽表存储，建议整列存 JSON，
  或按需摊平 `confidence` / `tlp` / `narrative` 等关键字段用于检索。

## 6. 推送 JSON 示例（节选）

```json
{
  "event_id": "…",
  "device_id": "node-001",
  "event_type": "c2",
  "event_name": "hygienehistory.com",
  "severity": "high",
  "model": "threat_intel",
  "src_ip": "10.0.0.5",
  "dst_ip": "…",
  "proto": "tcp",
  "direction": "outbound",
  "threat_source": "intel_domain",
  "ioc_type": "domain",
  "ioc_value": "hygienehistory.com",
  "ioc_category": "c2",
  "ioc_id": "otx-6a4bb565cb9499639bf4125b-4449246302",
  "ioc_source": "Threat Intel Hub",
  "ioc_tags": ["source:otx", "tlp:white"],
  "recommended_action": "block_and_report",
  "ioc_evidence": {
    "activity": "Cavern Manticore: Exposing Iran-Linked Modular C2 Framework",
    "threat_labels": ["modular c2 framework", "rmm abuse", "sysaid"],
    "source": "otx",
    "cross_check": "WhoisXML=malware, seen 2026-07-07~2026-07-09",
    "confidence": "high (2 sources)",
    "tlp": "white",
    "misp_event_id": "6a4bb565cb9499639bf4125b",
    "narrative": "【潜在C2通信告警】域名 hygienehistory.com 被 OTX 与 WhoisXML 标记为恶意，关联伊朗背景的 Cavern Manticore 模块化 C2 框架…"
  },
  "schema_version": "1.3",
  "sensor_version": "…",
  "occurrence_time": "2026-07-10T08:00:00Z"
}
```

## 7. 相关代码

- 事件结构：`internal/event/event.go`（`ThreatEvent.RecommendedAction` / `ThreatEvent.IOCEvidence`）
- 富字段类型：`internal/intel/types.go`（`Evidence`）
- 命中拷贝：`internal/detector/engine.go`（intel 命中分支）
- 推送：`internal/push/client.go`（`PushEvent` 整体序列化）
- 规则接入通道设计：`docs/superpowers/specs/2026-07-10-gateway-ioc-zip-watch-design.md`
