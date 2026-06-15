# ta_node 使用说明

`ta_node` 将 `ly_probe` 的采集、协议解析和 `fp-patterns/threat.json` payload 指纹匹配能力，与 `ly_analyser` 侧的 IOC 匹配、事件生成、缓存和推送能力融合到一个 Go 节点内。内部数据通路不再使用 NetFlow，而是：

```text
Capture Packet -> Parse PacketFeature -> FingerprintEngine.Match -> FlowAggregator.Update -> IntelMatcher.Match -> DetectorEngine.Detect -> EventQueue.Enqueue -> PushWorker.PushPending
```

## 编译

```bash
go mod tidy
go build -o ta_node ./cmd/ta_node
```

在线网卡采集默认使用 Linux AF_PACKET，不再依赖系统 `libpcap` 头文件或动态库。需要 root 或 `CAP_NET_RAW` / `CAP_NET_ADMIN` 权限。

如果明确需要 libpcap 后端，部署机安装 `libpcap-dev` / `libpcap-devel` 后使用：

```bash
go build -tags pcap -o ta_node ./cmd/ta_node
```

## 配置

示例配置位于 `configs/ta_node.yaml`。命令行参数优先级高于配置文件：

```bash
./ta_node \
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

## 离线检测

```bash
./ta_node --config ./configs/ta_node.yaml --pcap-file ./test.pcap
```

## 在线采集

```bash
sudo ./ta_node --config ./configs/ta_node.yaml --interface eth0
```

## Payload 规则

规则文件为 `patterns/threat.json`，兼容原 `ly_probe/fp-patterns/threat.json` 风格：

```json
{
  "threat": {
    "rules": {
      "50001": {
        "type": "MINE",
        "name": "ETH",
        "version": "eth_method",
        "protocol": "tcp",
        "regex": "\\x22method\\x22: ?\\x22eth_getWork\\x22"
      }
    }
  }
}
```

支持 `protocol`、`port`、`is_http`、`part=head|body|total` 和 `deleted` 字段。Go 标准库 `regexp` 不兼容的 PCRE 规则会被跳过并写日志。

## 威胁情报

本地文件格式见 `configs/intel.yaml`。支持 `ip`、`cidr`、`domain`、`url`、`hash`，其中 `hash` 当前只存储不检测。

### 多文件切分与增量添加

`intel.intel_file`（`configs/intel.yaml`）是**主可写文件**，API、CLI 和 Hub 同步的改动都持久化到这里。为避免单文件过大、便于增量添加，可把额外的 `*.yaml`/`*.yml` 文件放入 `intel.intel_dir`（默认 `configs/intel.d/`）：这些文件会被**并发加载**并按 `id` 合并。于是大型情报可拆分到多个文件，新增情报只需放入新文件（热加载周期内自动生效，无需重启）。叠加目录中的文件为**只读**——API/CLI/同步只写主文件；`id` 冲突时以主文件为准。删除叠加文件中的 IOC 需直接编辑/删除对应文件。详见 `configs/intel.d/README.md`。

CLI：

```bash
./ta_node --config ./configs/ta_node.yaml intel add --type ip --value 1.2.3.4 --category c2 --severity high --description "c2 server"
./ta_node --config ./configs/ta_node.yaml intel list
./ta_node --config ./configs/ta_node.yaml intel delete --id ioc-001
./ta_node --config ./configs/ta_node.yaml intel reload
```

HTTP API：

```http
GET    /api/v1/intel
POST   /api/v1/intel
DELETE /api/v1/intel/{id}
POST   /api/v1/intel/reload
POST   /api/v1/intel/sync
POST   /api/v1/intel/sync-source
POST   /api/v1/intel/batch-upsert
POST   /api/v1/intel/stix
GET    /api/v1/intel/stats
GET    /api/v1/health
```

`/api/v1/intel/sync` 仍然是全量替换。Threat Intel Hub 推荐使用 `/api/v1/intel/sync-source`，只替换指定 `source` 的 IOC，保留 `local`、`cli`、`manual` 等本地情报：

```bash
curl -X POST http://127.0.0.1:19090/api/v1/intel/sync-source \
  -H 'Authorization: Bearer <server.token>' \
  -H 'Content-Type: application/json' \
  -d '{
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
  }'
```

增量推送使用 `/api/v1/intel/batch-upsert`：

```json
{
  "items": [
    {"id": "hub-domain-evil", "type": "domain", "value": "evil.example.com", "source": "Threat Intel Hub", "enabled": true}
  ]
}
```

轻量 STIX/TAXII Envelope 接收接口只解析 Indicator，不实现完整 TAXII Server：

```bash
curl -X POST 'http://127.0.0.1:19090/api/v1/intel/stix?source=Threat%20Intel%20Hub' \
  -H 'Authorization: Bearer <server.token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "objects": [
      {
        "type": "indicator",
        "pattern": "[domain-name:value = '\''evil.example.com'\'']",
        "labels": ["malware"],
        "confidence": 90,
        "valid_until": "2026-06-04T00:00:00Z"
      }
    ]
  }'
```

支持的 STIX pattern 范围包括 `ipv4-addr`、`ipv6-addr`、`domain-name`、`url`、`file:hashes.*` 和 `ipv4-addr ISSUBSET`。复杂 `AND/OR` pattern 会跳过并在响应中计入 `skipped`。

## Web 配置页

本地服务启用后可访问：

```text
http://127.0.0.1:19090/config
```

页面支持修改节点、采集、规则情报、证据、事件队列和本地服务参数，并写回启动时的 `--config` 文件。采集网卡、pcap 文件、推送地址、队列路径等运行时参数保存后需要重启 `ta_node` 生效。

`server.token` 为空时保持兼容，不启用本地 API 鉴权；非空时写接口要求：

```http
Authorization: Bearer <server.token>
```

受保护的写接口包括情报新增、删除、重载、同步、STIX 接收和配置保存。生产部署建议将 `server.listen` 绑定到 `127.0.0.1`，或通过反向代理提供 TLS 和访问控制。配置页不会明文回显 `server.token`。

如果部署机尚未具备在线采集权限，可以先只启动配置服务：

```bash
./ta_node --config ./configs/ta_node.yaml --config-only
```

配置 API：

```http
GET  /api/v1/config
POST /api/v1/config
```

## 事件推送

事件会先写入 SQLite 表 `event_queue`，再由推送协程发送到 `node.management_url`：

```http
POST /api/events
Content-Type: application/json
Authorization: Bearer <token>
```

管理端不可用时，事件保留在本地队列，状态更新为 `failed` 并持续重试。

事件示例：

```json
{
  "event_id": "uuid",
  "device_id": "node-001",
  "event_type": "MINE",
  "event_name": "ETH",
  "severity": "high",
  "model": "threat_fingerprint",
  "src_ip": "192.168.1.10",
  "src_port": 52344,
  "dst_ip": "1.2.3.4",
  "dst_port": 3333,
  "proto": "tcp",
  "threat_source": "payload_rule",
  "rule_id": "50001",
  "threat_index": "120,160",
  "packet_time_usec": 1710000000123456
}
```

## 证据留存

启用 `evidence.enable_pcap_save=true` 后，命中事件的原始包会保存到：

```text
./data/evidence/{device_id}/{yyyy-mm-dd}/{event_id}.pcap
```

证据保存失败不会丢弃事件。

## 测试

```bash
go test ./...
```

单元测试覆盖配置加载、情报加载和匹配、payload 规则加载、HTTP head/body/total 匹配、事件 JSON、SQLite 队列去重与状态更新、推送失败保留事件。
新增测试覆盖 source-scoped 同步、批量 upsert、STIX Bundle/TAXII Envelope 解析、情报统计、API 鉴权、过期 IOC 清理和索引化匹配。
