# 仅出现少量告警来源的现场排查

告警列表不等于抓包列表。当前程序只有命中启用且未过期的 IOC 或指纹规则才入库，`src_ip` 为触发报文的发送端，DNS 应答也可触发告警，因此它不一定是攻击者。仓库中的 `docs/ip.xlsx` 不被运行中的检测程序读取。

## 1. 只读采集节点状态

将 `scripts/diagnose_node.py` 复制到服务器，使用 Python 3 运行，不需要额外 Python 库。它不会修改配置、IOC 或队列，也不会发送测试告警。

```sh
python3 diagnose_node.py --base-dir /opt/ta_node > ta-node-diagnosis.json
```

`--base-dir` 必须是进程实际工作目录。脚本不带此参数时，会尝试读取 systemd 的 MainPID 及 `/proc/PID/cwd`。非 systemd 安装可以用 `--pid PID`。Docker 安装应在与节点相同的容器/网络环境运行，或显式指定可访问的 API 地址和数据库路径。

```sh
systemctl show ta_node -p MainPID -p WorkingDirectory
python3 diagnose_node.py --pid 1234 --source 完整来源IP --source 另一个完整来源IP
```

API 不是默认端口时使用 `--api http://127.0.0.1:实际端口`。API 不可访问时，仍可指定实际数据库：

```sh
python3 diagnose_node.py --db /实际路径/event_queue.db --max-retry 20
```

报告中 `errors` 必须一起检查。API 返回的配置可能是已保存、等待重启的配置，要与本次启动日志比较。输出省略 Token、API Key、原始报文和载荷。

重点字段：

- `settings.capture`：网卡、离线 PCAP、BPF；只能抓到指定网卡可见的流量。
- `intel_stats`：运行进程实际加载的规则数量、类型及过期情况。
- `queue.top_sources`：最近队列样本的来源及去除上下文修订后的事件数。
- `queue.top_pairs`：来源、目的、端口、协议和推送状态；若来源端口为 53，应先辨认是否 DNS 应答。
- `queue.next_100_eligible_rows`：下一批可推送记录，是否被旧失败事件占据。
- `queue.oldest_occurrence_utc` / `newest_occurrence_utc`：样本时间范围。

默认读取最新 20000 条队列记录，包含上下文修订，不代表全量历史；可用 `--sample 100000` 扩大范围。`--source` 也是在该样本内查询。`pushed` 表示 HTTP 返回 2xx，不能单独证明平台成功落库或展示。

## 2. 对照同一时段的真实网卡流量

在预期的其他来源实际产生流量时执行，下列占位符需替换。命令只打印包头摘要，30 秒或 200 条后结束：

```sh
sudo timeout 30 tcpdump -ni 实际抓包网卡 -nn -c 200 'host 缺失来源完整IP'
```

若是 VLAN 镜像，另运行一次带链路层头的短采样，避免仅凭 IP 过滤没有输出就判定无包：

```sh
sudo timeout 15 tcpdump -eni 实际抓包网卡 -nn -c 100
```

混杂模式不能让交换机自动复制其他端口的单播流量。检查 SPAN/TAP 覆盖的源端口、VLAN、方向，以及采集点是否位于 NAT、代理、DNS 转发器之后。短采样没看到包只代表该时间窗口内未观察到，不能证明一直无流量。

## 3. 用证据定位层级

| 同时段观察 | 优先排查 |
|---|---|
| 网卡只见两个地址，其他预期流量在该时段确实发生 | 错网卡、镜像范围、NAT/代理、DNS 转发位置 |
| 网卡可见其他来源，队列没有对应事件 | 实际规则文件、enabled/expire_at、是否确有 IOC 命中、解析/跨包边界、入库错误 |
| 队列有其他来源，状态 pending/failed | 推送积压、接收端不可达/拒收、旧事件反复重试 |
| 队列有其他来源且 pushed，平台列表没有 | 平台时间筛选、节点筛选、归并逻辑、HTTP 2xx 业务响应和接收端日志 |
| 两个地址主要发出 DNS 应答 | 来源字段可能显示 DNS 服务器，需同时分析请求方向和实际客户端 |

读取启动与运行错误（输出可能包含内部地址，不要公开发布）：

```sh
journalctl -u ta_node --since '2 hours ago' --no-pager | grep -E 'version|loaded .*IOC|iocsync|enqueue|reload failed|save evidence|api stopped'
```

本地源码规则与已打包目录的规则可能不同，升级脚本会保留已有配置，因此不能用开发机文件数量推断服务器已加载数量。排查期间不要替换 IOC、清空队列或调用 `gen_events.py` 发送模拟告警，以免混淆真实证据。
