# Codex 实施任务书：Go 语言融合 `probe` 与 `analyser` 为 `ta_node`

> 目标：实现一个 Go 语言一体化节点 `ta_node`，融合原 `ly_probe` 的采集/协议解析/指纹匹配能力，以及原 `ly_analyser` 的威胁情报匹配、检测分析、事件生成能力。节点需要直接向管理端推送威胁事件及源信息，并支持动态添加威胁情报。

---

## 1. 背景与目标

当前架构中，`ly_probe` 负责网络流量采集、协议解析、payload 指纹匹配，并通过 NetFlow v9 向分析端发送流量和扩展字段；`ly_analyser` 负责读取 NetFlow v9，运行检测模型、威胁情报匹配、黑白名单匹配、事件生成与特征留存。

本次重构目标是使用 Go 语言实现新的融合节点：

```text
ta_node
```

`ta_node` 需要具备以下能力：

1. 从网卡或 pcap 文件采集流量。
2. 解析 TCP、UDP、HTTP、DNS、ICMP 等基础协议。
3. 加载原 `fp-patterns/threat.json` 风格的 payload 威胁规则。
4. 支持添加威胁情报，包括 IP、CIDR、域名、URL、Hash。
5. 本地完成威胁检测、IOC 匹配和事件生成。
6. 直接向管理端推送标准化威胁事件和源信息。
7. 管理端不可用时，将事件写入本地 SQLite 队列，恢复后补推。
8. 支持威胁情报热加载。
9. 支持证据字段：pcap 文件、命中包时间、payload 命中偏移、规则 ID。

---

## 2. 总体架构

融合后不要继续把 NetFlow 作为内部主链路。目标内部链路：

```text
Capture Packet
  -> Parse PacketFeature
  -> FingerprintEngine.Match
  -> FlowAggregator.Update
  -> IntelMatcher.Match
  -> DetectorEngine.Detect
  -> EventQueue.Enqueue
  -> PushWorker.PushPending
```

推荐模块边界：

```text
capture/       流量采集、pcap 读取
parser/        协议解析
fingerprint/   payload 指纹规则加载与匹配
intel/         威胁情报存储、加载、查询、热更新
flow/          flow 聚合与统计
detector/      检测逻辑与事件判定
event/         威胁事件构造与序列化
queue/         本地事件队列
push/          管理端推送客户端
evidence/      pcap 证据留存
server/        本地 API，用于添加/同步威胁情报
config/        配置加载与参数合并
```

原则：**部署融合，职责分层；数据通路融合，代码边界保留。**

---

## 3. 推荐目录结构

```text
ta_node/
  go.mod
  go.sum

  cmd/
    ta_node/
      main.go

  internal/
    config/
      config.go

    capture/
      capture.go
      interface_capture.go
      pcap_reader.go

    parser/
      parser.go
      http.go
      dns.go
      icmp.go

    fingerprint/
      engine.go
      pattern.go
      loader.go
      matcher.go

    intel/
      types.go
      store.go
      matcher.go
      file_loader.go
      api.go

    flow/
      flow.go
      aggregator.go

    detector/
      engine.go
      threat_detector.go
      intel_detector.go
      blacklist_detector.go

    event/
      event.go
      builder.go
      serializer.go

    queue/
      queue.go
      sqlite_queue.go

    push/
      client.go

    evidence/
      pcap_writer.go

    server/
      http_server.go

  configs/
    ta_node.yaml
    intel.yaml

  patterns/
    threat.json

  docs/
    ta_node.md
```

---

## 4. Go 依赖建议

初始化模块：

```bash
go mod init github.com/your-org/ta_node
```

推荐依赖：

```bash
go get github.com/google/gopacket
go get github.com/google/gopacket/pcap
go get github.com/mattn/go-sqlite3
go get github.com/google/uuid
go get gopkg.in/yaml.v3
```

说明：

- 抓包与 pcap 读取使用 `gopacket + pcap`。
- 本地事件队列使用 SQLite。
- 配置文件使用 YAML。
- 事件 ID 使用 UUID。
- payload 规则优先使用 Go 标准库 `regexp`；如果原 PCRE 规则存在不兼容表达式，需要记录并增加兼容处理。

---

## 5. 启动方式

命令行示例：

```bash
ta_node \
  --config ./configs/ta_node.yaml \
  --interface eth0 \
  --pcap-file ./test.pcap \
  --device-id node-001 \
  --management-url http://127.0.0.1:8080/api/events \
  --pattern-dir ./patterns \
  --intel-file ./configs/intel.yaml \
  --event-db ./data/event_queue.db \
  --enable-pcap-save=true
```

参数优先级：

```text
命令行参数 > 配置文件 > 默认值
```

需要支持在线采集和离线 pcap 检测两种模式：

```bash
# 在线采集
ta_node --interface eth0 --config ./configs/ta_node.yaml

# 离线 pcap 检测
ta_node --pcap-file ./test.pcap --config ./configs/ta_node.yaml
```

---

## 6. 配置文件示例

`configs/ta_node.yaml`：

```yaml
node:
  device_id: "node-001"
  management_url: "http://127.0.0.1:8080/api/events"
  token: ""

capture:
  interface: "eth0"
  pcap_file: ""
  bpf_filter: ""
  snaplen: 1600
  promiscuous: true

patterns:
  pattern_dir: "./patterns"

intel:
  intel_file: "./configs/intel.yaml"
  reload_interval_sec: 30
  enable_hot_reload: true

evidence:
  enable_pcap_save: true
  pcap_dir: "./data/evidence"

event:
  queue_db: "./data/event_queue.db"
  push_batch_size: 100
  retry_interval_sec: 30
  push_timeout_sec: 5

server:
  enable: true
  listen: "0.0.0.0:19090"
```

---

## 7. 核心数据结构

### 7.1 PacketFeature

```go
type PacketFeature struct {
    PacketTimeUsec uint64 `json:"packet_time_usec"`

    SrcIP   string `json:"src_ip"`
    SrcPort uint16 `json:"src_port"`
    DstIP   string `json:"dst_ip"`
    DstPort uint16 `json:"dst_port"`
    Proto   string `json:"proto"`

    HTTPHost   string `json:"http_host,omitempty"`
    HTTPURL    string `json:"http_url,omitempty"`
    HTTPMethod string `json:"http_method,omitempty"`
    UserAgent  string `json:"user_agent,omitempty"`

    DNSQuery   string   `json:"dns_query,omitempty"`
    DNSQType   uint16   `json:"dns_qtype,omitempty"`
    DNSAnswers []string `json:"dns_answers,omitempty"`

    ICMPPayloadLen uint32 `json:"icmp_payload_len,omitempty"`
    ICMPSeq        uint32 `json:"icmp_seq,omitempty"`

    Payload       []byte `json:"-"`
    PayloadSample string `json:"payload_sample,omitempty"`
    EvidenceFile  string `json:"evidence_file,omitempty"`
}
```

### 7.2 FingerprintHit

```go
type FingerprintHit struct {
    RuleID    string `json:"rule_id"`
    Type      string `json:"type"`
    Name      string `json:"name"`
    Version   string `json:"version,omitempty"`
    MatchFrom int    `json:"match_from"`
    MatchTo   int    `json:"match_to"`

    HitTimeUsec  uint64 `json:"hit_time_usec"`
    EvidenceFile string `json:"evidence_file,omitempty"`
}
```

### 7.3 ThreatIntel

```go
type ThreatIntel struct {
    ID          string   `json:"id" yaml:"id"`
    Type        string   `json:"type" yaml:"type"`             // ip, cidr, domain, url, hash
    Value       string   `json:"value" yaml:"value"`
    Category    string   `json:"category" yaml:"category"`     // c2, mining_pool, malware, scanner, botnet
    Severity    string   `json:"severity" yaml:"severity"`     // low, medium, high, critical
    Source      string   `json:"source" yaml:"source"`         // local, file, api, management
    Description string   `json:"description" yaml:"description"`
    Tags        []string `json:"tags" yaml:"tags"`

    Enabled   bool  `json:"enabled" yaml:"enabled"`
    CreatedAt int64 `json:"created_at" yaml:"created_at"`
    UpdatedAt int64 `json:"updated_at" yaml:"updated_at"`
    ExpireAt   int64 `json:"expire_at,omitempty" yaml:"expire_at,omitempty"`
}
```

### 7.4 FlowFeature

```go
type FlowFeature struct {
    FirstTime uint64 `json:"first_time"`
    LastTime  uint64 `json:"last_time"`

    SrcIP   string `json:"src_ip"`
    SrcPort uint16 `json:"src_port"`
    DstIP   string `json:"dst_ip"`
    DstPort uint16 `json:"dst_port"`
    Proto   string `json:"proto"`

    Packets uint64 `json:"packets"`
    Bytes   uint64 `json:"bytes"`

    HTTPHost string `json:"http_host,omitempty"`
    HTTPURL  string `json:"http_url,omitempty"`
    DNSQuery string `json:"dns_query,omitempty"`

    FingerprintHits []FingerprintHit `json:"fingerprint_hits,omitempty"`
    IntelHits       []ThreatIntel    `json:"intel_hits,omitempty"`
}
```

### 7.5 ThreatEvent

```go
type ThreatEvent struct {
    EventID   string `json:"event_id"`
    DeviceID  string `json:"device_id"`
    EventTime uint64 `json:"event_time"`

    EventType string `json:"event_type"`
    EventName string `json:"event_name"`
    Severity  string `json:"severity"`
    Model     string `json:"model"`

    SrcIP   string `json:"src_ip"`
    SrcPort uint16 `json:"src_port"`
    DstIP   string `json:"dst_ip"`
    DstPort uint16 `json:"dst_port"`
    Proto   string `json:"proto"`

    Direction    string `json:"direction"`
    ThreatSource string `json:"threat_source"` // payload_rule, intel_ip, intel_domain, intel_url, intel_cidr

    IOCType     string `json:"ioc_type,omitempty"`
    IOCValue    string `json:"ioc_value,omitempty"`
    IOCCategory string `json:"ioc_category,omitempty"`

    RuleID      string `json:"rule_id,omitempty"`
    ThreatIndex string `json:"threat_index,omitempty"`

    Flows   uint64 `json:"flows"`
    Packets uint64 `json:"packets"`
    Bytes   uint64 `json:"bytes"`

    EvidenceFile   string         `json:"evidence_file,omitempty"`
    PacketTimeUsec uint64         `json:"packet_time_usec,omitempty"`
    RawFeature     map[string]any `json:"raw_feature,omitempty"`
}
```

---

## 8. 威胁情报添加与管理

`ta_node` 必须支持三种添加方式：本地文件、HTTP API、命令行。

### 8.1 本地文件添加

`configs/intel.yaml`：

```yaml
items:
  - id: "ioc-001"
    type: "ip"
    value: "1.2.3.4"
    category: "c2"
    severity: "high"
    source: "local"
    description: "example c2 server"
    tags: ["apt", "c2"]
    enabled: true

  - id: "ioc-002"
    type: "domain"
    value: "evil.example.com"
    category: "malware"
    severity: "high"
    source: "local"
    enabled: true

  - id: "ioc-003"
    type: "cidr"
    value: "45.67.89.0/24"
    category: "scanner"
    severity: "medium"
    source: "local"
    enabled: true

  - id: "ioc-004"
    type: "url"
    value: "http://bad.example.com/shell.php"
    category: "webshell"
    severity: "critical"
    source: "local"
    enabled: true
```

### 8.2 本地 HTTP API 添加

新增本地 API：

```http
POST /api/v1/intel
Content-Type: application/json
```

请求：

```json
{
  "type": "ip",
  "value": "8.8.8.8",
  "category": "c2",
  "severity": "high",
  "source": "api",
  "description": "manual added ioc",
  "tags": ["manual"],
  "enabled": true
}
```

响应：

```json
{
  "success": true,
  "id": "ioc-xxxx"
}
```

还需要支持：

```http
GET    /api/v1/intel
DELETE /api/v1/intel/{id}
POST   /api/v1/intel/reload
POST   /api/v1/intel/sync
```

`/api/v1/intel/sync` 用于管理端批量下发威胁情报：

```json
{
  "items": [
    {
      "id": "mgmt-ioc-001",
      "type": "domain",
      "value": "malicious.example.com",
      "category": "c2",
      "severity": "critical",
      "source": "management",
      "enabled": true
    }
  ]
}
```

### 8.3 命令行添加

需要支持以下 CLI：

```bash
# 添加 IP 情报
ta_node intel add --type ip --value 1.2.3.4 --category c2 --severity high --description "c2 server"

# 添加域名情报
ta_node intel add --type domain --value evil.example.com --category malware --severity critical

# 查看情报
ta_node intel list

# 删除情报
ta_node intel delete --id ioc-001

# 重新加载情报
ta_node intel reload
```

---

## 9. 威胁情报匹配规则

| 情报类型 | 匹配字段 |
|---|---|
| `ip` | `src_ip`、`dst_ip`、DNS answer |
| `cidr` | `src_ip`、`dst_ip`、DNS answer |
| `domain` | `dns_query`、`http_host` |
| `url` | `http_url` |
| `hash` | 预留，当前可只入库不检测 |

匹配命中后生成事件：

```text
model = "threat_intel"
threat_source = "intel_ip" / "intel_domain" / "intel_url" / "intel_cidr"
event_type = intel.category
event_name = intel.value
severity = intel.severity
ioc_type = intel.type
ioc_value = intel.value
ioc_category = intel.category
```

---

## 10. Payload 指纹规则支持

继续支持原 `fp-patterns/threat.json` 风格：

```json
{
  "threat": {
    "rules": {
      "50001": {
        "type": "MINE",
        "name": "ETH",
        "version": "eth_method",
        "protocol": "tcp",
        "regex": "\\x22method\\x22: ?\\x22(eth_submitLogin|eth_getWork|eth_submitHashrate|eth_submitWork)\\x22"
      }
    }
  }
}
```

Go 结构：

```go
type PatternRule struct {
    ID       string `json:"-"`
    Type     string `json:"type"`
    Name     string `json:"name"`
    Version  string `json:"version"`
    Protocol string `json:"protocol"`
    Port     int    `json:"port"`
    IsHTTP   int    `json:"is_http"`
    Part     string `json:"part"` // head, body, total
    Regex    string `json:"regex"`
    Deleted  int    `json:"deleted"`
}
```

匹配要求：

1. `protocol` 为空则匹配所有协议。
2. `port=0` 或缺失则不限制端口。
3. `is_http=1` 时只匹配 HTTP。
4. `part=head` 只匹配 HTTP header。
5. `part=body` 只匹配 HTTP body。
6. `part=total` 匹配完整 HTTP payload。
7. 命中后生成 `FingerprintHit`。
8. 命中 payload 规则后生成 `model=threat_fingerprint` 的事件。
9. 事件必须包含 `rule_id` 和 `threat_index`。

---

## 11. 本地事件队列

使用 SQLite，避免管理端不可用导致事件丢失。

表结构：

```sql
CREATE TABLE IF NOT EXISTS event_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE NOT NULL,
  event_time INTEGER NOT NULL,
  payload TEXT NOT NULL,
  status INTEGER DEFAULT 0,
  retry_count INTEGER DEFAULT 0,
  last_error TEXT,
  created_at INTEGER,
  updated_at INTEGER
);
```

状态定义：

```text
0 = pending
1 = pushing
2 = pushed
3 = failed
```

Go 接口：

```go
type EventQueue interface {
    Enqueue(event ThreatEvent) error
    LoadPending(limit int) ([]ThreatEvent, error)
    MarkPushed(eventID string) error
    MarkFailed(eventID string, errMsg string) error
}
```

要求：

- 推送失败不丢事件。
- 节点重启后继续补推。
- 使用 `event_id` 去重。
- 推送逻辑不能阻塞采集主流程。
- 支持批量读取 pending 事件。

---

## 12. 管理端事件推送

HTTP 请求：

```http
POST /api/events
Content-Type: application/json
Authorization: Bearer <token>
```

事件示例：

```json
{
  "event_id": "uuid",
  "device_id": "node-001",
  "event_time": 1710000000,
  "event_type": "MINE",
  "event_name": "ETH",
  "severity": "high",
  "model": "threat_fingerprint",
  "src_ip": "192.168.1.10",
  "src_port": 52344,
  "dst_ip": "1.2.3.4",
  "dst_port": 3333,
  "proto": "tcp",
  "direction": "outbound",
  "threat_source": "payload_rule",
  "rule_id": "50001",
  "evidence_file": "./data/evidence/xxx.pcap",
  "packet_time_usec": 1710000000123456,
  "threat_index": "120,160",
  "flows": 1,
  "packets": 8,
  "bytes": 2048
}
```

要求：

- 支持 token。
- 支持超时配置。
- 支持失败重试。
- 支持批量推送或预留批量推送能力。
- 推送失败不得影响采集和检测主流程。

---

## 13. 检测流程伪代码

```go
for packet := range capture.Packets() {
    pf, err := parser.Parse(packet)
    if err != nil {
        continue
    }

    hits := fingerprintEngine.Match(pf)
    pf.FingerprintHits = hits

    intelHits := intelMatcher.MatchPacket(pf)

    flow := flowAggregator.Update(pf, hits, intelHits)

    events := detectorEngine.Detect(flow)
    for _, e := range events {
        _ = eventQueue.Enqueue(e)
    }
}
```

推送协程：

```go
for {
    events, err := eventQueue.LoadPending(config.PushBatchSize)
    if err != nil {
        sleep()
        continue
    }

    for _, e := range events {
        err := managementClient.PushEvent(e)
        if err != nil {
            eventQueue.MarkFailed(e.EventID, err.Error())
            continue
        }
        eventQueue.MarkPushed(e.EventID)
    }

    sleep(config.RetryInterval)
}
```

---

## 14. 证据留存

需要支持命中事件的证据字段：

- `evidence_file`：命中包或 flow 关联 pcap 文件。
- `packet_time_usec`：命中包时间，微秒级。
- `threat_index`：payload 命中偏移，格式建议为 `start,end`。
- `rule_id`：payload 规则 ID。

要求：

1. `enable_pcap_save=true` 时，payload 指纹命中或 IOC 命中可保存关联包。
2. 保存路径按设备和日期组织，例如：

```text
./data/evidence/{device_id}/2026-05-20/{event_id}.pcap
```

3. 事件中必须带证据文件路径。
4. 如果证据保存失败，事件仍应生成，但需要记录日志。

---

## 15. 测试要求

### 15.1 单元测试

至少覆盖：

1. YAML 配置加载。
2. `intel.yaml` 加载。
3. IP 情报匹配。
4. CIDR 情报匹配。
5. 域名情报匹配。
6. URL 情报匹配。
7. `threat.json` 加载。
8. payload 规则匹配。
9. HTTP head/body/total 匹配。
10. `ThreatEvent` JSON 序列化。
11. SQLite 队列入队、出队、去重、状态更新。
12. 管理端推送失败时事件保留。

### 15.2 集成测试

准备一个测试 pcap，包含：

1. 普通 HTTP 流量。
2. 命中 `threat.json` 的 payload。
3. 命中 IP 情报的连接。
4. 命中域名情报的 DNS 或 HTTP Host。
5. 命中 URL 情报的 HTTP 请求。

预期：

- 普通 HTTP 不生成威胁事件。
- payload 命中生成 `threat_fingerprint` 事件。
- IP/CIDR 命中生成 `threat_intel` 事件。
- Domain/URL 命中生成 `threat_intel` 事件。
- 管理端不可用时事件进入 SQLite 队列。
- 管理端恢复后事件成功补推。

---

## 16. 验收标准

完成后必须满足：

1. `ta_node` 可以从网卡采集流量。
2. `ta_node` 可以读取 pcap 文件进行离线检测。
3. 可以加载 `patterns/threat.json`。
4. 可以通过本地文件添加威胁情报。
5. 可以通过 HTTP API 添加、查看、删除、同步威胁情报。
6. 可以通过命令行添加、查看、删除、重载威胁情报。
7. IP 情报命中后生成威胁事件。
8. CIDR 情报命中后生成威胁事件。
9. 域名情报命中后生成威胁事件。
10. URL 情报命中后生成威胁事件。
11. payload 指纹规则命中后生成威胁事件。
12. 事件包含源 IP、目的 IP、端口、协议、规则 ID、情报来源、证据路径。
13. 管理端不可用时事件写入本地 SQLite 队列。
14. 管理端恢复后事件可补推。
15. 威胁情报支持热加载。
16. `docs/ta_node.md` 包含完整使用说明。

---

## 17. 实现优先级

```text
P0：Go 项目骨架
P0：配置加载
P0：pcap 文件读取
P0：网卡抓包
P0：PacketFeature 解析
P0：threat.json 规则加载
P0：payload 指纹匹配
P0：ThreatEvent 生成
P0：SQLite 事件队列
P0：管理端 HTTP 推送

P1：本地威胁情报文件加载
P1：IP / CIDR / Domain / URL 情报匹配
P1：HTTP API 添加威胁情报
P1：CLI 添加威胁情报
P1：情报热加载
P1：证据 pcap 保存

P2：批量推送
P2：管理端批量同步情报
P2：IPv6 完整支持
P2：Hash 情报检测
P2：统计聚合模型
P2：兼容更多原 analyser 检测模型
```

---

## 18. 不要做的事情

1. 不要再把 NetFlow 作为 `ta_node` 内部主链路。
2. 不要把威胁情报硬编码在代码里。
3. 不要让事件推送阻塞抓包。
4. 不要管理端不可用就丢事件。
5. 不要破坏原 `threat.json` 规则格式。
6. 不要把所有逻辑写进 `main.go`。
7. 不要只做 payload 规则，不做 IOC 情报。
8. 不要只做内存队列，必须支持落盘队列。
9. 不要把管理端 API 强耦合进检测逻辑。
10. 不要因为证据保存失败而丢弃威胁事件。

---

## 19. 最终交付内容

交付时请提供：

1. Go 代码工程 `ta_node/`。
2. `cmd/ta_node/main.go` 启动入口。
3. `configs/ta_node.yaml` 示例配置。
4. `configs/intel.yaml` 示例情报文件。
5. `patterns/threat.json` 示例规则。
6. `docs/ta_node.md` 使用文档。
7. 单元测试与集成测试说明。
8. 管理端事件 JSON 示例。
9. SQLite 队列表结构初始化逻辑。
10. README 编译、运行、排障说明。

最终目标：

```text
ta_node = Go 实现的一体化流量采集 + 协议解析 + payload 指纹检测 + 威胁情报匹配 + 事件缓存 + 管理端推送节点
```

它既要能识别 payload 威胁规则，也要能动态添加和匹配威胁情报，并将完整威胁事件与源信息可靠推送到管理端。
