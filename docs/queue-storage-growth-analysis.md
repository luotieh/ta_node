# event_queue 数据库持续增长排查（2026-09-18）

现场提供的文件是 `/data/ta_node-archive/event_queue.db.archived`。以下根因已在当前源码确认并复现；尚未读取服务器数据库，不能把本地实验数字直接当成现场增长速度。

## 已确认的增长机制

1. **没有数据库保留和容量策略。** `SQLiteQueue.Enqueue` 存储完整事件 JSON；`MarkPushed` 只改状态为 2，`MarkFailed` 只增加重试次数。没有删除已推送记录、清理超期记录或限制总容量的实现。达到重试上限只是停止发送，记录仍保留。关闭推送也不关闭入库。
2. **会话修订按事件数放大。** 同一事务每个命中包创建新的 EventID；下一包到来，`reviseTransaction` 为该事务已有每个事件生成新版本。队列键包含 revision 后缀，因此各版本均新增记录，不覆盖旧版本。
3. **每次修订写入会话全文。** `snapshotSide` 保存累计的 `reassembled_hex`、可打印的 `reassembled_text` 和包列表；列表还含 packet_hex、payload_hex、payload_text。Hex 本身约为原始二进制的两倍，同一内容又出现在多个字段中。`store_packet_index` 实际保存包内容，不只是轻量索引。
4. **PCAP 清理不影响数据库。** `evidence.retain_days` 仅清理证据日期目录。即便 `enable_pcap_save: false`，事件 JSON 中的原始报文和会话内容仍会入库。ZIP 归档文件也未被该日期目录清理逻辑覆盖。
5. **推送不构成回收机制。** 默认 100 条/30 秒，快速响应时约 3.3 条/秒；即使推送全部成功，数据库仍不回收记录。

同一事务 N 个包分别命中一个 IP IOC、并在结束时 Flush，产生 N(N+1)/2 + N 条记录。上下文逐步变大，在达到内容上限前，累计序列化字节可呈近似三次增长；达到包列表/重组上限也只是限制单行内容，并不限制历史行数。仅一两个来源产生连续命中，仍能占用大量磁盘。

## 本地复现

复现代码 `.analysis/queue_growth_repro.go` 调用真实 flow、detector 和 correlation 模块，构造单个未完成的 HTTP POST 事务，每个包命中一个 IP IOC。首包为 HTTP 头，后续为 1024 字节载荷。无网络发送、无生产文件读取、无实际数据库写入；统计的 JSON 字节就是 Enqueue 会序列化保存的内容，不含 SQLite 页、索引等开销。

```sh
go run -mod=vendor .analysis/queue_growth_repro.go
```

| 模式 | 包数 | 报文总字节 | 独立事件 | 待入库行数 | JSON 总字节 |
|---|---:|---:|---:|---:|---:|
| packet | 20 | 20,606 | 20 | 20 | 133,833 |
| session | 20 | 20,606 | 20 | 230 | 27,807,966 |
| packet | 40 | 42,166 | 40 | 40 | 271,771 |
| session | 40 | 42,166 | 40 | 860 | 202,140,279 |
| packet | 80 | 85,286 | 80 | 80 | 547,647 |
| session | 80 | 85,286 | 80 | 3,320 | 1,535,062,685 |

这证明源码存在足以解释快速膨胀的机制，不证明现场所有记录均来自此种事务。若实际运行模式为 packet，则仍有逐包告警、JSON 内容冗余及无限保留的问题。

## 对现场归档库的只读检查

将 `scripts/diagnose_queue_storage.py` 复制到服务器，用 Python 3 运行（只需标准库）：

```sh
python3 diagnose_queue_storage.py /data/ta_node-archive/event_queue.db.archived --sample 200
```

读取数据库页信息和最新 200 行元数据，不全表统计 500GB 数据，也不输出报文内容。重点看：

- `sample_revision_rows`、`sample_max_context_revision`、`sample_distinct_event_ids`：版本放大。
- `sample_avg_json_bytes`、`sample_max_json_bytes`：单条事件大小。
- `sample_status_json_bytes`：成功记录、待发记录、失败记录分别占多少样本 JSON 字节。
- `page_count`、`freelist_count`、`files_bytes`：有效数据、库内空闲页与旁路日志的区别。

样本不能直接代表全库分布。读取失败时应保留报错，不对原库执行自动修复。

当前源码没有把队列重命名为 `.archived` 的逻辑。该文件可能是人工或外部脚本归档，需检查仍被哪个进程打开，以及 `/data` 是否真的位于独立磁盘：

```sh
sudo lsof /data/ta_node-archive/event_queue.db.archived
findmnt -T /data/ta_node-archive/event_queue.db.archived
df -h / /data
```

Linux 上重命名一个打开的文件，不会使进程自动停止向其原 inode 写入。同一文件系统内的移动也不会释放该文件系统的空间。需要核查当前 `event.queue_db` 和进程启动工作目录，不能仅凭 `.archived` 扩展名判断已经停止写入。

## 止血与修复方向

- 确认运行配置确实为 session 后，可临时改为 `aggregation.mode: packet` 并关闭 `enable_transaction_link`，重启生效。这会失去双向会话上下文，保留逐包 IOC 告警；只降低放大，不能解决无限保留。
- 根分区已满时，应先停止实际写入进程或把数据迁往有空间的独立文件系统，再制定清理范围。没有执行任何线上停止或删除动作。
- 对大库直接 DELETE 通常不会缩小文件；VACUUM 可能需要大量额外空间，不应在已满的根分区直接执行。不能直接删除仍在使用的 WAL/SHM。
- 正式修复应让事务上下文按完成/受控频率更新，合并未发送的旧修订，限制单条证据大小，并建立成功记录保留期、失败记录策略、总容量/可用空间阈值及告警。保留期限和超限丢弃策略涉及证据保留要求，应明确后实施。
