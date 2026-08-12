# ta_node 双向会话告警聚合任务计划书

## 1. 文档状态

- 状态：待审核，未批准前不实施代码改造。
- 适用仓库：`ta_node`。
- 建议事件版本：`schema_version=1.5`。
- 基线能力：事件版本 1.4 已支持每次命中的原始触发包，以及请求/响应标签展示。

## 2. 背景与现状

当前检测链路为：

```text
capture
  -> parser.Parse
  -> fingerprint / IOC match
  -> flow.Aggregator（单向五元组）
  -> detector.Detect（每次命中一个 event_id）
  -> SQLite queue
  -> management push
```

当前设计能准确保存“触发本次告警的数据包”，但存在以下限制：

1. A→B 与 B→A 使用不同的单向五元组，无法形成统一会话上下文。
2. 请求命中时通常尚未收到响应，不能在首次告警中直接携带后续响应。
3. TCP 报文可能存在分片、乱序、重传，一个应用层请求或响应可能跨多个包。
4. HTTP Keep-Alive 连接可能包含多个请求/响应，不能只按五元组将内容全部混合。
5. 当前队列以 `event_id` 唯一，缺少同一事件后续上下文补全的 revision/upsert 语义。

## 3. 设计结论

### 3.1 是否把双向所有包聚合成一个告警

建议聚合双向流量的**会话状态与统计信息**，但不把所有数据包直接平铺进单条告警 JSON，也不把同一会话内的多次命中合并成一个不可拆分的 `event_id`。

采用三层模型：

| 层级 | 标识 | 职责 |
|---|---|---|
| 双向会话 | `session_id` | 规范化端点、会话时间、双向包/字节统计、连接状态 |
| 请求响应事务 | `transaction_id` | 关联一次请求与其响应，保存有限重组内容和包引用 |
| 告警命中 | `event_id` | 每一次规则/IOC 命中保持独立、可审计、可幂等重试 |

同一会话中的多个 `event_id` 可以共享 `session_id`；属于同一请求响应事务的事件共享 `transaction_id`。这样既能展示完整上下文，又不会破坏“同一事件每一次命中都需要记录”的要求。

### 3.2 原始包保存原则

- 告警 JSON 保存触发包、事务相关包的有限索引及有限重组内容。
- ACK-only、重复重传等非必要包默认只计数，不全部写入 JSON。
- 完整会话包序列按需保存到 PCAP 证据文件，事件通过 `evidence_file` 引用。
- 所有字节和包数限制必须可配置；达到限制后设置截断标志，不能静默丢失。

## 4. 目标与非目标

### 4.1 本次目标

1. 建立稳定的双向 `session_id`，在 TCP 连接复用、超时和重新建连之间正确切分。
2. 保留每次命中的独立 `event_id`，同一包重试仍保持幂等。
3. 第一阶段支持 HTTP/1.x 请求/响应关联和有限 TCP 重组。
4. 支持响应晚于告警产生时，对原事件进行增量上下文补全。
5. 管理端页面支持会话、命中、请求/响应和原始分片的分层查看。
6. 对内存、单事务字节、包数、等待时间和并发事务设置硬上限。
7. 保持 1.4 消费方兼容；关闭新功能后恢复当前逐包行为。

### 4.2 非目标

- 不在本阶段实现 TLS 解密。
- 不在本阶段实现完整 HTTP/2、HTTP/3/QUIC 事务解析。
- 不将完整 PCAP 内容内嵌到事件 JSON。
- 不把同一会话内所有规则命中压缩成单个 `event_id`。
- 不承诺跨节点关联同一个网络会话。
- 不在节点侧实现长周期、跨节点的全局事件聚合。

## 5. 推荐事件模型

### 5.1 Schema 1.5 草案

```json
{
  "event_id": "evt-occurrence-id",
  "session_id": "ses-bidirectional-id",
  "transaction_id": "txn-request-response-id",
  "context_revision": 2,
  "context_final": true,
  "hit_packet": {
    "message_direction": "request",
    "packet_sequence": 1024,
    "packet_hex": "...",
    "payload_hex": "...",
    "payload_text": "..."
  },
  "exchange": {
    "request": {
      "capture_start_time_usec": 1000,
      "capture_end_time_usec": 1200,
      "packet_count": 3,
      "captured_bytes": 1460,
      "wire_bytes": 1514,
      "reassembled_hex": "...",
      "reassembled_text": "...",
      "truncated": false,
      "packets": []
    },
    "response": {
      "capture_start_time_usec": 1800,
      "capture_end_time_usec": 2200,
      "packet_count": 4,
      "captured_bytes": 4096,
      "wire_bytes": 4216,
      "reassembled_hex": "...",
      "reassembled_text": "...",
      "truncated": true,
      "packets": []
    }
  },
  "session_summary": {
    "first_time_usec": 900,
    "last_time_usec": 2300,
    "client_packets": 8,
    "server_packets": 12,
    "client_wire_bytes": 2048,
    "server_wire_bytes": 8192,
    "hit_count": 3
  },
  "schema_version": "1.5"
}
```

### 5.2 兼容策略

- 保留现有 `raw_packet`，并继续描述直接触发告警的单个包。
- 新增 `session_id`、`transaction_id`、`context_revision`、`exchange`、`session_summary`，全部使用 `omitempty`。
- `exchange.request/response` 是重组事务视图；`raw_packet.request/response` 保留旧页面和旧管理端兼容。
- 管理端 1.5 页面优先读取 `exchange`，不存在时回退到 `raw_packet`。
- 新增配置开关，初始默认关闭会话补全，完成联调后再灰度开启。

## 6. 双向会话和事务关联规则

### 6.1 双向会话键

将两个端点排序后生成规范化键：

```text
protocol + min(ip,port) + max(ip,port) + interface/vlan scope
```

TCP 会话不能只依赖规范化五元组，还需要结合 SYN/FIN/RST、TCP 序列空间和空闲超时区分端口复用后的新连接。中途开始抓包时允许创建 `midstream=true` 的会话。

### 6.2 客户端与服务端方向

按以下优先级判断：

1. TCP SYN 发起方。
2. 已识别协议的请求/响应语义。
3. 已知服务端口。
4. 无法判断时保留 endpoint A/B，不强行标记客户端。

### 6.3 HTTP/1.x 事务

- 请求头完整后创建 `transaction_id`。
- 非流水线连接按请求队列顺序关联响应。
- 支持 Content-Length、chunked 和连接关闭结束响应。
- 1xx 响应附着到当前事务，最终非 1xx 响应结束事务。
- Upgrade、CONNECT 和无法解析的协议切换只保留原始包与状态，不继续猜测 HTTP 事务。
- 请求或响应超过限制时停止复制正文，但继续计算包数、字节数和哈希。

### 6.4 重传、乱序与分片

- 使用 TCP sequence range 去重，重传计数单独记录。
- 设置有限乱序窗口；超过窗口的内容标记 `reassembly_incomplete=true`。
- IP 分片第一阶段只使用解析器当前可提供的数据；若需要完整 IP 重组，单列后续任务。
- 不因重传再次产生相同规则的重复告警；若重传包本身被检测链路重复命中，需要以包序列范围和规则键去重。

### 6.5 超时与不完整事务

- 告警命中立即产生 revision 1，不等待响应。
- 捕获响应或更多上下文后产生更高 revision。
- FIN/RST、事务完成或等待超时后写入 `context_final=true`。
- 最终未捕获响应时记录 `response_status="not_captured"`；等待期间使用 `response_status="pending"`。

## 7. 上报和队列方案

### 7.1 推荐方案：立即告警 + 增量补全

```text
命中包
  -> event_id + revision 1（立即入队和推送）
  -> 会话继续收包
  -> 请求/响应事务补全
  -> 同一 event_id + revision N（再次入队）
  -> 管理端按 event_id、revision 幂等 upsert
```

采用该方案的原因：不延迟首次告警，同时允许真实响应在随后到达时补充到同一事件。

### 7.2 队列改造

当前 `event_id UNIQUE` 无法保存多个 revision，需选择并实现以下方式之一：

- 推荐：队列记录增加独立 `queue_id`，唯一键改为 `(event_id, context_revision)`。
- 每个 revision 携带完整当前快照，而不是依赖前一 revision 的 JSON Patch，降低乱序和丢包恢复复杂度。
- 推送状态、重试次数按 revision 独立维护。
- 同一 revision 的网络重试必须复用相同幂等键。

### 7.3 管理端前置要求

执行节点改造前必须确认管理端具备：

1. 按 `event_id` 定位事件。
2. 仅接受大于当前 `context_revision` 的更新。
3. 重复 revision 幂等成功。
4. revision 乱序到达时不会用旧内容覆盖新内容。
5. `context_final=true` 后仍允许幂等重放，但拒绝更低 revision。

如果管理端暂时不能支持 upsert，备选方案是节点延迟推送直到事务完成或超时；该方案会增加告警延迟，不作为首选。

## 8. UI 调整方案

### 8.1 告警列表

列表仍按告警命中展示，每行对应一个 `event_id`。新增可选列：

- 会话命中次数。
- 请求/响应事务数。
- 上行/下行包数和字节数。
- 上下文状态：等待响应、已完成、已截断、不完整。

管理端可以按 `session_id` 折叠同一会话中的多条告警，但必须允许展开查看每个独立 `event_id`。

### 8.2 展开区

推荐使用“命中选择器 + 请求/响应标签 + 原始包折叠”的层级：

```text
▼ 会话：198.18.0.1:63756 ↔ 198.18.0.78:80
  首次/末次时间 | 3 次命中 | 上行 2 KB | 下行 8 KB

  [命中 #1 17:33:22] [命中 #2 17:33:25] [命中 #3 17:33:31]

  [请求报文] [响应报文]

  重组后的报文文本 / HEX

  ▸ 原始数据包（3 包，1460 字节）
```

交互规则：

- 外层三角继续控制整个会话详情，默认折叠。
- 只有一个命中时隐藏命中选择器，避免额外层级。
- 默认选中触发当前告警的命中。
- 默认选中实际存在的一侧；请求、响应都存在时默认请求。
- `pending` 显示“等待响应”；最终缺失显示“未捕获到响应”。
- 重组内容为主要视图，原始分片默认折叠。
- 原始分片按抓包序号列出方向、时间、TCP seq/ack、长度、重传/乱序/截断状态。
- 多包内容不能生成一个标签一个包；应在当前请求或响应标签内用折叠列表展示。
- 小屏页面将命中标签改为下拉选择，保留请求/响应双标签。

### 8.3 安全与可用性

- 报文文本必须继续做 HTML 转义。
- 超长文本采用虚拟滚动或最大高度，不一次渲染无限内容。
- 二进制内容默认显示 HEX，不强制转换为文本。
- Cookie、Authorization 等敏感字段是否脱敏沿用现有安全策略，并在 UI 标明“已脱敏”。

## 9. 配置草案

以下为建议默认值，需审核确认：

```yaml
aggregation:
  mode: packet                 # packet | session
  enable_transaction_link: false
  response_wait_sec: 30
  max_sessions: 100000
  max_transactions_per_session: 16
  max_packets_per_transaction: 128
  max_reassembly_bytes_per_side: 262144
  max_out_of_order_bytes: 65536
  store_packet_index: true
  save_full_session_pcap: false
```

限制达到后的统一行为：停止复制更多内容、继续累计统计、设置 `truncated=true` 并记录具体原因。

## 10. 分阶段任务

### 阶段 0：协议评审与基线冻结

- [ ] T0.1 确认本任务书第 15 节的审核项。
- [ ] T0.2 确认管理端 revision/upsert 能力及接口契约。
- [ ] T0.3 保存当前 1.4 JSON、队列和 UI 行为为兼容基线。
- [ ] T0.4 准备真实 PCAP 测试集并进行脱敏审查。

交付物：Schema 1.5 接口草案、管理端联调契约、基线测试报告。

### 阶段 1：事件结构与配置骨架

- [ ] T1.1 在 `internal/event` 增加 session、transaction、revision 和 exchange 类型。
- [ ] T1.2 在 `internal/config` 增加 aggregation 配置及校验。
- [ ] T1.3 保留 1.4 字段与 packet 模式兼容路径。
- [ ] T1.4 补充 Schema 1.5 文档和 JSON 示例。

交付物：仅数据结构和配置，不改变默认运行行为。

### 阶段 2：双向会话聚合器

- [ ] T2.1 实现规范化双向键和稳定 `session_id`。
- [ ] T2.2 记录 TCP 状态、客户端/服务端角色和双向计数。
- [ ] T2.3 处理 SYN/FIN/RST、空闲超时、中途抓包和端口复用。
- [ ] T2.4 实现有界会话表、淘汰和指标。
- [ ] T2.5 保持现有每次命中 `event_id` 语义不变。

交付物：会话摘要可用，但尚不补全请求/响应正文。

### 阶段 3：有限 TCP 重组与 HTTP/1.x 事务

- [ ] T3.1 解析并透传 TCP seq/ack/flags。
- [ ] T3.2 实现每方向有限重组、重传去重和乱序窗口。
- [ ] T3.3 实现 HTTP/1.x 请求边界、响应边界和事务队列。
- [ ] T3.4 生成 `transaction_id` 并维护命中与事务关联。
- [ ] T3.5 实现超限、超时、不完整、协议切换状态。

交付物：HTTP/1.x 请求响应可关联，资源使用有硬上限。

### 阶段 4：事件补全、队列和推送

- [ ] T4.1 命中时生成 revision 1 快照。
- [ ] T4.2 请求/响应更新时生成 revision N 完整快照。
- [ ] T4.3 改造 SQLite 队列支持 `(event_id, context_revision)` 幂等。
- [ ] T4.4 改造 push worker、失败重试和最近推送日志。
- [ ] T4.5 与管理端验证乱序、重复和最终状态处理。

交付物：真实响应可以在首次告警后补充到同一 `event_id`。

### 阶段 5：本地页面与管理端 UI

- [ ] T5.1 告警列表增加会话摘要和上下文状态。
- [ ] T5.2 增加命中选择器，单命中时自动隐藏。
- [ ] T5.3 请求/响应标签优先展示重组内容。
- [ ] T5.4 增加原始分片折叠列表及异常状态标签。
- [ ] T5.5 支持 revision 到达后的局部刷新且不改变用户当前选择。
- [ ] T5.6 完成桌面端和窄屏交互验收。

交付物：会话、命中、请求/响应和原始包四层信息可清晰查看。

### 阶段 6：稳定性、性能与灰度

- [ ] T6.1 完成单元、集成、PCAP 回放和浏览器测试。
- [ ] T6.2 增加会话数、淘汰数、重组字节、截断数、等待事务数等指标。
- [ ] T6.3 完成高并发连接和大响应压力测试。
- [ ] T6.4 packet 模式与 session 模式双运行比对。
- [ ] T6.5 小流量灰度开启，确认无误后扩大范围。
- [ ] T6.6 验证关闭开关可回退到 1.4 逐包行为。

交付物：性能报告、灰度报告、回滚说明。

## 11. 测试矩阵

### 11.1 单元测试

- 双向键在 A→B、B→A 下生成相同 `session_id`。
- 不同 TCP 连接复用相同端口时生成不同会话。
- 每次命中生成不同 `event_id`，同一次重试保持相同 ID。
- revision 单调递增且最终状态正确。
- TCP 重传不重复拼接，乱序可在窗口内恢复。
- 达到包数、字节数、会话数限制后正确截断或淘汰。

### 11.2 PCAP 集成测试

- 单包请求、单包响应。
- 请求跨多个 TCP segment。
- 响应跨多个 segment，包含 chunked body。
- HTTP Keep-Alive 多个顺序请求/响应。
- HTTP pipelining。
- 响应缺失、连接 RST、超时结束。
- 重传、乱序、重复 ACK、中途开始抓包。
- 大文件响应触发截断但统计准确。
- 非 HTTP TCP、DNS/UDP、TLS 流量不会被错误关联。

### 11.3 队列与管理端测试

- revision 重复投递幂等。
- revision 2 先于 revision 1 到达时不回退。
- 节点重启后未推送 revision 可继续重试。
- 管理端暂时不可用时队列不会丢失首次告警或最终补全。

### 11.4 UI 测试

- 默认折叠、默认命中、默认请求/响应标签正确。
- `pending`、`not_captured`、`complete`、`truncated` 状态正确。
- 多命中切换不会串用其他事务的报文。
- revision 更新后保持当前展开状态和滚动位置。
- 超长文本、二进制 HEX 和特殊字符安全显示。

## 12. 验收标准

1. 同一 TCP 会话双向包拥有相同 `session_id`，不同连接不会误合并。
2. 同一会话中的每一次命中仍拥有独立 `event_id`。
3. 首次告警不等待响应；响应到达后能以更高 revision 补充到同一事件。
4. HTTP/1.x 多请求连接能按事务正确关联，不把不同请求响应混合。
5. 重传不重复拼接，乱序和截断状态可见。
6. 所有缓存均有硬上限；压力测试下内存不会随流量无限增长。
7. 管理端能正确处理重复和乱序 revision。
8. UI 能查看会话摘要、命中明细、请求/响应重组内容和原始分片。
9. `go test ./...`、`go vet ./...`、构建和浏览器交互测试全部通过。
10. 关闭 aggregation 功能后，现有 1.4 事件和页面行为不受影响。

## 13. 风险与控制措施

| 风险 | 影响 | 控制措施 |
|---|---|---|
| 错误关联请求与响应 | 研判证据失真 | 事务状态机、协议测试集、无法确认时不猜测 |
| 重组缓存过大 | 节点内存压力 | 每会话/事务/方向硬上限和有界淘汰 |
| 等待响应导致告警延迟 | 降低检测时效 | 首次告警立即发送，后续 revision 补全 |
| revision 乱序覆盖 | 管理端显示旧数据 | revision 单调比较、完整快照、幂等 upsert |
| 敏感数据扩大采集 | 合规风险 | 字段脱敏、正文上限、配置开关和权限控制 |
| 高速流量下 CPU 增加 | 丢包或积压 | 功能开关、候选协议过滤、指标和压测 |
| 管理端未同步升级 | 新字段不可用 | 默认关闭、先完成契约、双版本兼容 |

## 14. 回滚方案

- 设置 `aggregation.mode=packet`，停止会话重组和 revision 补全。
- 保留 1.4 `raw_packet` 生成和现有请求/响应标签逻辑。
- 管理端忽略 1.5 可选字段仍可显示基础事件。
- 数据库迁移必须提供向前兼容路径；回滚程序不得读取失败或删除已入队 revision。
- 灰度阶段不移除任何 1.4 字段，不进行不可逆数据迁移。

## 15. 审核确认项

执行前请确认以下事项：

- [ ] A1 同意“三层模型”：会话、请求响应事务、独立告警命中。
- [ ] A2 同意所有包用于统计和可选 PCAP，告警 JSON 只保存有限事务内容及包索引。
- [ ] A3 同意采用“立即告警 + revision 增量补全”，而不是等待响应后才首次上报。
- [ ] A4 确认管理端可以按 `event_id + context_revision` 幂等 upsert。
- [ ] A5 同意第一阶段仅保证 HTTP/1.x；TLS 解密、HTTP/2、QUIC 不纳入本次。
- [ ] A6 确认第 9 节建议的默认资源上限，或给出调整值。
- [ ] A7 确认 UI 按“命中选择器 + 请求/响应标签 + 原始包折叠”实施。
- [ ] A8 同意事件 schema 从 1.4 升级到 1.5，并保留 1.4 兼容字段。

只有上述审核项确认后，才进入阶段 0 的接口冻结和后续代码实施。

