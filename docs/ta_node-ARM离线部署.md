# ta_node ARM 离线部署说明

本文档描述如何为 ARM 设备交叉编译 `ta_node`，打包为离线发布包，并在目标机上以 systemd 服务安装运行。整个流程分两段：**联网开发机**准备依赖并构建打包，**离线 ARM 目标机**解包安装，目标机全程无需联网、无需安装编译器或运行时库。

## 适用目标

```text
Linux arm64   (aarch64，64 位)
Linux armv7   (ARMv7 EABI，32 位，GOARM=7)
```

构建产物为**纯静态可执行文件**（`CGO_ENABLED=0`），目标机不依赖 `libc`、`libpcap` 等动态库。在线采集默认使用 Linux AF_PACKET，不需要 libpcap。

## 一、联网开发机：准备依赖

构建机需安装 Go 1.22+ 工具链（交叉编译 arm64/armv7 无需安装 ARM C 工具链，因为关闭了 CGO）。首次或依赖变更后，在联网环境准备 vendor 目录：

```bash
go mod tidy
go mod vendor
go mod verify
```

`vendor/` 已随仓库提交，后续构建完全离线（脚本内不访问网络）。

## 二、构建离线 ARM 二进制

一键构建两个架构：

```bash
./scripts/build-all-offline.sh
```

它分别调用 `scripts/build-arm64-offline.sh` 和 `scripts/build-armv7-offline.sh`，产物输出到 `dist/`：

```text
dist/ta_node-linux-arm64    ELF 64-bit aarch64, statically linked, stripped
dist/ta_node-linux-armv7    ELF 32-bit ARM EABI5, statically linked, stripped
```

构建命令的关键参数（以 arm64 为例）：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -mod=vendor -trimpath -ldflags="-s -w" \
  -o dist/ta_node-linux-arm64 ./cmd/ta_node
```

| 参数 | 作用 |
|------|------|
| `CGO_ENABLED=0` | 纯静态编译，目标机无任何动态库依赖，无需 ARM C 工具链 |
| `GOARCH=arm64` / `GOARCH=arm GOARM=7` | 选择目标架构（armv7 需 `GOARM=7`） |
| `-mod=vendor` | 只使用 `vendor/`，构建不联网 |
| `-trimpath` | 去除二进制中的本地构建路径 |
| `-ldflags="-s -w"` | 去除符号表与调试信息，减小体积 |

如需强制校验离线可构建（vendor 不完整会直接报错而非联网拉取）：

```bash
GOPROXY=off GOFLAGS=-mod=vendor ./scripts/build-all-offline.sh
```

## 三、构建前自检（可选）

`scripts/verify-offline.sh` 串联格式化、测试与两架构构建，适合发布前一键自检：

```bash
./scripts/verify-offline.sh
```

依次执行：`gofmt -w .` → `go test ./...` → 构建 arm64 → 构建 armv7 → 列出 `dist/` 并打印 `file` 结果。注意它会用 `gofmt -w` 原地格式化代码。

## 四、打包离线发布包

```bash
./scripts/package-offline.sh
```

生成 `release/ta_node-offline-<时间戳>.tar.gz`（可用 `VERSION=xxx ./scripts/package-offline.sh` 自定义版本号）。包内结构：

```text
ta_node-offline-<版本>/
├── dist/
│   ├── ta_node-linux-arm64
│   └── ta_node-linux-armv7
├── configs/
│   ├── ta_node.offline.yaml      # 离线部署默认配置（systemd 使用）
│   ├── ta_node.yaml
│   ├── intel.yaml                # 主可写情报文件
│   └── intel.d/                  # 情报叠加目录（只读、并发加载）
├── patterns/                     # payload 指纹规则
├── deploy/
│   ├── install-offline.sh
│   └── systemd/ta_node.service
├── scripts/
├── data/evidence/                # 证据留存目录（预创建）
└── README.md
```

将 `tar.gz` 拷贝到目标 ARM 机器（U 盘、内网传输等任意离线方式）。

## 五、离线 ARM 目标机：安装

解包后用 `deploy/install-offline.sh` 按架构安装，需 root：

arm64：

```bash
tar -xzf ta_node-offline-*.tar.gz
cd ta_node-offline-*
sudo ./deploy/install-offline.sh arm64
```

armv7：

```bash
sudo ./deploy/install-offline.sh armv7
```

安装脚本做的事：

- 创建 `/opt/ta_node` 与 `/opt/ta_node/data/evidence`
- 拷贝对应架构二进制到 `/opt/ta_node/ta_node`
- 拷贝 `configs/`、`patterns/` 到 `/opt/ta_node/`
- 安装 `deploy/systemd/ta_node.service` 到 `/etc/systemd/system/`
- `daemon-reload` → `enable` → `restart` → 打印服务状态

systemd 服务以 `--config /opt/ta_node/configs/ta_node.offline.yaml` 启动，并授予 `CAP_NET_RAW`、`CAP_NET_ADMIN`（在线抓包所需），同时 `NoNewPrivileges=true`。

## 六、离线配置说明

默认配置 `configs/ta_node.offline.yaml` 的关键项：

| 配置 | 默认值 | 说明 |
|------|--------|------|
| `event.enable_push` | `false` | 离线场景默认关闭事件上送，事件仅本地入队留存 |
| `server.listen` | `127.0.0.1:19090` | 本地配置/情报服务仅绑定回环 |
| `server.token` | `CHANGE_ME_TO_A_RANDOM_TOKEN` | **务必改成强随机值** |
| `capture.interface` | `eth0` | 改成目标机实际采集网卡 |
| `capture.bpf_filter` | 空 | 默认 AF_PACKET 构建下保持为空（见下文 pcap 说明） |
| `intel.intel_file` | `./configs/intel.yaml` | 主可写情报文件 |

情报叠加目录 `intel.intel_dir`（默认 `configs/intel.d/`）虽未在该 yaml 中显式写出，但程序内置默认值会自动加载该目录；大型情报可拆分多个 `*.yaml`/`*.yml` 放入其中，并发加载并按 `id` 合并，详见 `configs/intel.d/README.md`。

部署后按需修改：

```bash
sudo vi /opt/ta_node/configs/ta_node.offline.yaml   # 至少改 server.token 和 capture.interface
sudo systemctl restart ta_node
```

如需远程访问配置页 `http://<ip>:19090/config`，请把 `server.listen` 改为对外地址、设置强 `server.token`，并自行配置防火墙或 TLS 反向代理。

## 七、服务管理

```bash
sudo systemctl status ta_node
sudo journalctl -u ta_node -f
sudo systemctl restart ta_node
sudo systemctl stop ta_node
```

工作目录为 `/opt/ta_node`，证据 pcap 留存于 `/opt/ta_node/data/evidence/`。

## 八、可选：libpcap（pcap）高级路径

默认离线包使用 AF_PACKET，**不**使用 `-tags pcap`，此模式下 `capture.bpf_filter` 须留空。仅当确需 BPF 过滤时，才单独构建 `-tags pcap` 版本，并为目标 ARM 提供对应的 libpcap 开发库（需 ARM C 交叉工具链、开启 CGO）。该路径不属于默认离线包，按需自行处理。

## 九、常见问题

- **`binary not found: dist/...`**：安装脚本未找到对应架构二进制，确认已执行 `build-all-offline.sh` 且选对了 `arm64`/`armv7` 参数。
- **构建联网失败 / 校验和错误**：vendor 目录不完整，回到联网开发机重跑 `go mod vendor && go mod verify`。
- **服务起来但抓不到包**：确认 `capture.interface` 为真实网卡，且服务具备 `CAP_NET_RAW`/`CAP_NET_ADMIN`（默认 service 已授予）。
- **`file dist/ta_node-linux-arm64` 不是 aarch64**：检查构建环境变量是否被覆盖，应为 `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`。
