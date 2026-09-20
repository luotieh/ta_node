# Windows 本地测试与 Linux 迁移

此目录可独立运行，不需要 Docker、Go 或外部数据库。Windows 和 Linux
使用相同的 configs、patterns、data 目录，只需更换对应系统/架构的 bin 程序。
所有相对路径以此目录为工作目录；启动脚本已自动设置。

## Windows 使用

在本目录打开 PowerShell：

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
powershell -ExecutionPolicy Bypass -File .\stop.ps1
```

配置页面：http://127.0.0.1:19090/config

健康检查：http://127.0.0.1:19090/api/v1/health

情报列表：http://127.0.0.1:19090/api/v1/intel

启动默认为 `--config-only`，可测试配置保存、IOC 增删改查、来源同步、STIX、
ZIP 定时导入等功能，不会采集 Windows 网卡流量。日志在 logs 目录。
配置写回 configs/ta_node.yaml，修改运行参数后停止并重新启动。
初始 configs/intel.yaml 包含仓库的 4 条示例 IOC，可通过 API 管理。

离线分析自己的 PCAP（停止管理进程后运行）：

```powershell
.\stop.ps1
.\replay.ps1 -PcapFile C:\captures\sample.pcap
.\start.ps1
```

离线模式可以测试协议解析、IOC 匹配、SQLite 事件入队和证据保存。PCAP
读完即退出；默认指纹规则和事件推送关闭。启用指纹需配置 patterns.enable。
测试推送前配置 node.management_url 和 event.enable_push，再启动常驻管理服务，
推送工作线程会处理待发事件。未配置实际接收端前不要启用推送。

## 编译

在源码根目录运行 scripts/build-portable.ps1，可用 -Go 指定 go.exe 的绝对路径。
需要 Go >= 1.22，使用仓库 vendor 离线构建，禁用 CGO。
默认生成 dist/windows-amd64、dist/linux-amd64、dist/linux-arm64 和两个 Linux tar.gz。
重建保留已有配置、IOC 和 data；重建 Windows 前先停止运行中的程序。

## Linux 部署

服务器 `uname -m` 为 x86_64 时选择 linux-amd64；为 aarch64 时选择 linux-arm64。
以下以 amd64 为例。将对应 tar.gz 上传到服务器后执行：

```sh
sudo mkdir -p /opt/ta_node
sudo tar -xzf ta_node-linux-amd64.tar.gz -C /opt/ta_node
sudo chmod +x /opt/ta_node/bin/ta_node /opt/ta_node/start.sh
```

迁移本地测试状态时：先运行 Windows stop.ps1，将整个 configs、patterns、data
复制到服务器 /opt/ta_node 下，替换发行包初始内容。SQLite 文件可跨系统使用；
若存在 -wal/-shm 辅助文件，要连同整个 data 一起复制。请勿在运行期间直接复制数据库。
测试产生的事件也会随 data 迁移；正式环境若不需要测试数据，就保留发行包的空 data。
发行压缩包不会自动包含 Windows 测试目录后续产生的数据。

修改 configs/ta_node.yaml：设置唯一 device_id；用 `ip -br link` 确认实际抓包
网卡并修改 capture.interface；按需填写 home_net、management_url、api_key 并启用推送。
默认管理端口只监听 127.0.0.1。可用 SSH 端口转发访问：

```sh
ssh -L 19090:127.0.0.1:19090 user@server
```

本地服务需先停止以释放 19090。若改为对外监听，应设置 server.token 并限制防火墙访问。

先验证配置服务（Ctrl+C 停止）：

```sh
cd /opt/ta_node
./start.sh --config-only
```

再启用 Linux 实时抓包及开机启动：

```sh
sudo cp /opt/ta_node/ta_node.service /etc/systemd/system/ta_node.service
sudo systemctl daemon-reload
sudo systemctl enable --now ta_node
sudo systemctl status ta_node
sudo journalctl -u ta_node -f
```

服务使用 Linux AF_PACKET，限制能力为 CAP_NET_RAW；不需要 libpcap/Npcap。
capture.bpf_filter 必须保持空值。Linux 二进制已交叉编译，实时抓包需在目标服务器验证。
