# ta_node 2x10GE 高速网口支持计划任务书

## 1. 背景

当前 ta_node 已具备流量采集、协议解析、payload 指纹规则匹配、IOC 匹配、事件入队和管理端推送能力。现有实现适合作为轻量威胁情报消费与流量检测节点，但主处理链路为单 goroutine 串行处理：

```text
capture -> parser.Parse -> fingerprint.Match -> intel.MatchPacket -> flow.Update -> detector.Detect -> queue.Enqueue
```

在 2 个 10GE 光纤网口满速接入场景下，最坏小包流量可接近 29.76 Mpps，大包场景也可达到约 1.6 Mpps。当前 gopacket + 单处理链路 + 串行 regex + 同步 SQLite 入队架构无法保证 2x10GE 线速处理。

本任务书用于指导 ta_node 从轻量节点演进为可承载 2x10GE 接入的高性能流量检测节点。

## 2. 总体目标

目标是让 ta_node 能够稳定接入 2 个 10GE 光纤网口，并按业务策略完成威胁情报匹配、载荷规则检测、事件生成和管理端推送。

分层目标：

- 支持多网口采集：至少支持 2 个 10GE 接口并行接入。
- 支持多队列处理：读取、解析、匹配、事件入队解耦。
- 支持流表分片：避免单 mutex flow map 成为瓶颈。
- 支持流表过期：避免长期运行内存持续增长。
- 支持可观测性：能看到 PPS、drop、队列长度、事件积压、推送失败等指标。
- 支持按部署能力降级：可通过 BPF、snaplen、payload 截断、采样降低处理压力。

非目标：

- 第一阶段不承诺 2x10GE 小包满线速 DPI。
- 第一阶段不实现完整 DPDK/AF_XDP 数据面。
- 第一阶段不做复杂 TCP 重组。

## 3. 性能边界判断

当前技术栈适合：

- 中低速镜像流量检测。
- IOC/IP/domain/url 快速匹配。
- 少量 payload regex 规则检测。
- 离线 PCAP 分析。

当前技术栈不适合直接承诺：

- 2x10GE 小包满线速全包处理。
- 全量 payload 深度正则检测。
- 高并发连接下无过期流表长期运行。

如果最终验收要求为 2x10GE 小包线速并做 payload DPI，应另起 DPDK 或 AF_XDP 数据面专项。

## 4. 架构改造方案

推荐架构：

```text
eth0/eth1
  -> capture readers
  -> bounded packet channels
  -> parser/matcher worker pool
  -> sharded flow aggregator
  -> event channel
  -> batch SQLite writer
  -> concurrent push workers
```

关键原则：

- 热路径不做阻塞 HTTP 推送。
- 热路径尽量不做文件 IO。
- 热路径减少 payload copy。
- 用有界 channel 暴露背压。
- 关键 map 使用 hash 分片。
- 对 payload 检测设置最大字节数。

## 5. 阶段任务

### 阶段 1：多网口配置与采集

新增配置：

```yaml
capture:
  interfaces: ["eth0", "eth1"]
  worker_per_interface: 8
  channel_size: 65536
  snaplen: 1600
  payload_max_bytes: 1024
  drop_when_busy: true
```

任务：

- 保留兼容字段 `capture.interface`。
- 新增 `capture.interfaces`，优先使用多网口配置。
- 每个网口启动独立 capture reader。
- 每个 reader 写入有界 packet channel。
- 增加 channel 满时的 drop 计数。
- 记录每个网口读包数、drop 数、错误数。

验收：

- 同时启动 eth0、eth1 采集。
- 任一网口不可用时明确报错。
- 可通过日志或 API 看到每个网口统计。

### 阶段 2：处理 worker pool

任务：

- 将主循环改为 dispatcher + worker pool。
- parser、fingerprint、intel match 在 worker 中执行。
- worker 数支持配置。
- packet channel 和 event channel 均为有界队列。
- 增加处理耗时和队列长度指标。

验收：

- `worker_per_interface=8` 时至少启动 16 个处理 worker。
- 高流量下不会因单 goroutine 处理链路导致明显积压。
- 关闭时 goroutine 可正常退出。

### 阶段 3：Flow Aggregator 分片与过期

新增配置：

```yaml
flow:
  shard_count: 128
  idle_timeout_sec: 120
  cleanup_interval_sec: 30
  max_flows: 1000000
```

任务：

- 将单 map + mutex 改为 sharded map。
- 按五元组 hash 路由到 shard。
- 新增流过期清理。
- 超过 `max_flows` 时按策略丢弃新流或清理旧流。
- 避免单个 shard 锁长时间占用。

验收：

- 长时间运行时内存不因 flow map 无限增长。
- 高并发连接下锁竞争可控。
- 单元测试覆盖流更新、分片、过期清理。

### 阶段 4：Payload 检测优化

任务：

- 新增 `payload_max_bytes`。
- parser 不再无条件复制完整 payload。
- payload regex 只对满足协议、端口、HTTP 条件的候选流量执行。
- 支持按规则声明检测范围：head/body/total/max_bytes。
- 统计每条规则命中和耗时。

验收：

- payload 最大检测长度可配置。
- 16 条规则下 CPU 开销可观测。
- 规则异常或过慢时可定位。

### 阶段 5：事件队列异步化

任务：

- 热路径只写 event channel。
- 单独 SQLite writer 批量写入。
- 批量大小和 flush interval 可配置。
- 保留 event_id 去重。
- 队列满时记录 drop 或 fallback 策略。

新增配置：

```yaml
event:
  event_channel_size: 65536
  sqlite_batch_size: 500
  sqlite_flush_interval_ms: 200
```

验收：

- 命中高峰时包处理不被 SQLite 单条写阻塞。
- 重复事件仍由 event_id 去重。
- SQLite 写入失败可记录并告警。

### 阶段 6：推送并发化

新增配置：

```yaml
event:
  enable_push: true
  push_workers: 4
  push_batch_size: 500
  retry_interval_sec: 30
  push_timeout_sec: 5
```

任务：

- 启动多个 push worker。
- 避免多个 worker 同时取到同一 pending 事件。
- 可通过状态标记 `inflight` 或事务抢占。
- 推送失败回到 retry 状态。
- 推送日志展示 worker、状态、错误。

验收：

- 管理端慢响应时不会阻塞检测链路。
- 不重复推送同一 event_id。
- 并发推送下事件状态一致。

### 阶段 7：可观测性与压测

新增 API：

```http
GET /api/v1/metrics
GET /api/v1/capture/stats
GET /api/v1/runtime/stats
```

指标：

- 每网口 PPS、bytes/sec、drop。
- packet channel 长度。
- worker 处理速率和耗时。
- flow 数量、分片分布、过期清理数量。
- IOC 数量、matcher 版本。
- 事件生成速率、队列积压、推送成功/失败。
- Go runtime：goroutine、GC、heap。

压测任务：

- 使用 tcpreplay 或硬件流量发生器回放 PCAP。
- 分别测试 1GE、5GE、10GE、2x10GE。
- 分别测试小包、大包、HTTP payload、DNS、混合流量。
- 记录丢包、CPU、内存、事件延迟。

验收：

- 有完整压测报告。
- 明确当前版本可支撑的 PPS、Gbps、active flows。
- 明确不同规则数量、IOC 数量下的性能曲线。

## 6. 系统调优建议

网卡队列：

```bash
ethtool -L eth0 combined 8
ethtool -L eth1 combined 8
ethtool -G eth0 rx 4096
ethtool -G eth1 rx 4096
```

RSS 与中断亲和性：

```bash
ethtool -x eth0
ethtool -x eth1
cat /proc/interrupts
```

建议：

- 为两个 10GE 网口开启 RSS 多队列。
- 将网卡 IRQ 绑定到独立 CPU core。
- ta_node worker 绑定或调度到同 NUMA 节点 CPU。
- 管理端推送走独立管理网口，避免与镜像流量争抢。
- 如果使用虚拟机，应确认 SR-IOV 或直通能力。

## 7. 风险与约束

主要风险：

- gopacket 解码和 Go regex 在高 PPS 下 CPU 成本较高。
- SQLite 不适合作为高频事件的同步热路径。
- payload 深度检测会显著降低吞吐。
- flow map 无上限会造成内存风险，必须先做 TTL 和 max_flows。
- 管理端响应慢会造成推送积压，必须隔离推送链路。

约束：

- 2x10GE 小包满线速需要专门数据面方案。
- 若必须做全流量 payload DPI，应评估 AF_XDP/DPDK。
- 若只做 IP/CIDR IOC 匹配，可通过更轻量解析路径显著提升吞吐。

## 8. 验收标准

功能验收：

- 支持两个 10GE 接口同时采集。
- 支持 worker pool 并行解析和匹配。
- 支持 flow 分片和过期清理。
- 支持 payload 最大检测长度。
- 支持异步批量事件入队。
- 支持并发推送且不重复推送。
- 配置页展示相关参数和运行指标。

性能验收：

- 给出 1GE、10GE、2x10GE 三档压测结果。
- 给出不同 packet size 下的 PPS。
- 给出 drop rate、CPU、内存、队列积压。
- 明确当前版本的安全运行水位。

稳定性验收：

- 连续运行 24 小时内存无持续线性增长。
- 管理端不可用时事件不阻塞包处理。
- 情报热更新不阻塞主处理链路。
- 关闭进程时 goroutine 和文件句柄正常释放。

## 9. 建议里程碑

### M1：可并行接入

- 多网口配置。
- 多 capture reader。
- worker pool。
- 基础指标。

### M2：可长期运行

- flow sharding。
- flow TTL。
- event channel。
- SQLite batch writer。

### M3：可生产观测

- metrics API。
- 配置页运行状态。
- drop/queue/event/push 指标。
- 压测脚本和报告模板。

### M4：高性能数据面评估

- AF_PACKET fanout 优化。
- AF_XDP PoC。
- DPDK PoC。
- 结合压测结果确定最终技术路线。

## 10. 结论

ta_node 当前不能直接承诺支持 2x10GE 满线速检测。要稳定接入 2 个 10GE 光纤网口，必须先完成多网口、多 worker、flow 分片、事件异步化、推送并发化和可观测性改造。

如果业务目标是 2x10GE 小包线速并进行 payload 深度检测，应启动 AF_XDP/DPDK 高性能数据面专项；如果目标是威胁情报 IOC 匹配和有限 payload 规则检测，则可按本任务书分阶段改造当前 Go 实现。
