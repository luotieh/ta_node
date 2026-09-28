# ta_node 内网镜像部署（另一台服务器）

## 交付物

| 文件 | 说明 |
| --- | --- |
| `ta_node-cb04704-arm64.tar.gz` | Docker 镜像（ARM64，含新版二进制 vcb04704） |
| `ta_node-cb04704-arm64.tar.gz.sha256` | 镜像包 SHA256 校验文件 |

镜像由运行容器 `docker commit` 生成，内嵌二进制 SHA256：
`8f1ee3f6de0bdb2144e782193f60d4eb9bb911dc1ab33e1686e85e72b33daca0`（`/usr/local/bin/ta_node`）

## 前置条件

- 目标机：Linux ARM64，已安装 Docker，内核支持 AF_PACKET（常规内核即可）
- 不需要 libpcap（默认 AF_PACKET 后端）

## 部署步骤

```bash
# 1. 校验镜像包完整性（在包所在目录执行）
sha256sum -c ta_node-cb04704-arm64.tar.gz.sha256

# 2. 导入镜像
gunzip -c ta_node-cb04704-arm64.tar.gz | docker load
docker images | grep ta_node        # 应出现 ta_node:cb04704

# 3. 准备目录
mkdir -p /opt/ta_node/configs /opt/ta_node/data/evidence /data/yt/ioc
# 将本包同目录的 configs/ta_node.offline.yaml 和 configs/intel.yaml
# 放入 /opt/ta_node/configs/，并按下方「必改配置」修改

# 4. 启动容器
docker run -d --name ta_node_01 \
  --restart unless-stopped \
  --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v /opt/ta_node:/opt/ta_node \
  -v /data/yt:/data/yt \
  -v /etc/localtime:/etc/localtime:ro \
  ta_node:cb04704

# 5. 验证
curl -s http://127.0.0.1:25640/api/v1/health
# 期望: "status":"ok", "version":"cb0470415d81-dirty"
```

## 必改配置（`configs/ta_node.offline.yaml`）

| 配置项 | 当前值 | 部署时必须改为 |
| --- | --- | --- |
| `node.device_id` | `node-arm-offline-001` | 新节点唯一标识，如 `node-arm-offline-002`，**不可与其他节点重复** |
| `capture.interface` | `enp125s0f0` | 目标机实际镜像/抓包网卡名（`ip link` 查看） |
| `node.management_url` | `http://127.0.0.1:22123/api/traffic/internal/event/push` | 平台与节点同机时保留；否则改为平台实际地址 |
| `event.api_key` | `change-me-internal-key` | 平台侧若设置 internal_api_key，此处必须一致 |
| `server.token` | `CHANGE_ME_TO_A_RANDOM_TOKEN` | **必改**：强随机串，如 `openssl rand -hex 32`（当前为占位符，任何人可调用写接口） |
| `server.listen` | `0.0.0.0:25640` | 仅需本机访问改 `127.0.0.1:25640`；对外必须配合强 token |
| `intel.ioc_sync_dir` / `ioc_sync_dir2` | `/data/yt`、`/data/yt/ioc` | 确认与网闸实际投递目录一致 |

相对路径（`./data/event_queue.db`、`./data/evidence`、`./configs/intel.yaml`）无需改，容器工作目录为 `/opt/ta_node`。

## 注意事项

- 版本：本镜像含队列 WAL 模式与分片写入修复（本地提交 `2823f94`、`cb04704`），启动后 `event_queue.db` 自动进入 WAL 模式
- 情报规则来源：`configs/intel.yaml` 为主文件，网闸投递 zip 到 `ioc_sync_dir` 后由节点每小时增量合并
- 防火墙：如需远程访问配置页（`/config`），放行 25640 并确保已设强 token；写接口需带 `Authorization: Bearer <token>`
- 升级方式：新二进制 `docker cp` 进容器 `/usr/local/bin/ta_node` 后 `docker restart` 即可；配置与数据在挂载卷中不受影响
- 事件积压兜底：平台不可达时事件留存 `event_queue.db`（SQLite），恢复后自动续推，单事件最多重试 `event.max_push_retry`（默认 20）次
