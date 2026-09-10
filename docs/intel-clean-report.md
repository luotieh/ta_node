# intel.yaml 清洗报告(实战规则包)

> 生成: 2026-08-21 15:07 | 输入 docs/intel.yaml (363条) -> 清洗后 279 条启用规则


## 清洗动作

| 动作 | 数量 | 说明 |
|---|---|---|
| 重复IP去重 | 23 条移除 | 103.23.172.117×14→1、45.11.36~39.254 各×3→1、45.137.205.53×2→1、75.98.162.139×2→1; ip 规则 102→79 唯一, 移除件归档于 intel-removed.yaml |
| 共享CDN/云IP降级 | 42 条 | Cloudflare 30条 / Backblaze B2 4个 / Wix 3条 / 共享主机 5条; IP级阻断误伤大, 移至 monitor(enabled=false), 相关威胁由域名规则覆盖 |
| URL主机失效移除 | 19 条 | 主机无解析则URL规则永不命中 |
| 失效域名保留 | 64 个 | ta_node 匹配 DNS 查询, 失效C2/钓鱼域名仍可检出失陷主机信标; expire_at=30天, 正常域名90天 |

## 产物

| 文件 | 用途 | 数量 |
|---|---|---|
| docs/intel-clean.yaml | ta_node --intel-file 直接替换 | 279 条 (domain 157 / ip 37 / url 85) |
| docs/intel-monitor.yaml | 共享CDN/云IP, enabled=false, 仅审计参考 | 42 条 |
| docs/intel-removed.yaml | 清洗归档(重复/失效URL), 可回溯 | 42 条 |
| docs/rules/domains.txt | 域名黑名单(每行1个) | 157 |
| docs/rules/ips-block.txt | IP阻断清单(已去重, 剔除CDN/云) | 37 |
| docs/rules/ips-monitor-only.txt | 高风险误伤IP(建议只监控不阻断) | 42 |
| docs/rules/urls.txt | URL黑名单 | 85 |
| docs/rules/dnsmasq-block.conf | dnsmasq/AdGuardHome sinkhole 配置 | 157×2 行 |
| docs/rules/hosts-block.txt | hosts 文件格式 | 157×2 行 |
| docs/rules/suricata-dns.rules | Suricata DNS 查询告警规则 | 157 条 |
| docs/rules/domain-status.csv | 域名解析状态明细(5解析器) | 157 行 |

## 关键处置说明

1. **保留解析异常域名规则**: walter.filloco.icu(轮换返回127.0.0.1)、ashx.lhlsjcb.com(AAAA=::1)、2-api.mooo.com(AAAA=2001::1, fast-flux) —— 三者均保留域名规则: ta_node 对 DNS 查询做匹配, 域名级检测不受其IP异常影响; 这些IP未进入IP阻断清单, 不会误伤本机/内网。

2. **不阻断公共DNS/IP**: 全量数据中不存在指向公共DNS服务器IP或内网IP的 ip 规则; 若发现内网设备解析出 127.0.0.1/::1, 属于上述域名自身投毒行为, 用域名规则即可覆盖。

3. **Cloudflare/Backblaze/Wix 等共享IP不阻断**: 30 条 Cloudflare、12 条 Backblaze B2(去重后4个IP)、3 条 Wix 等IP规则移入 monitor, 相关威胁已由域名规则覆盖(如 *.s3.eu-central-003.backblazeb2.com 桶域名)。

4. **过期机制**: 全部规则带 expire_at(正常90天/失效域名与monitor 30天), ta_node store 的 PruneExpired 可自动清理。

5. **用法**: ta_node: `--intel-file ./docs/intel-clean.yaml`; dnsmasq: `conf-file=/path/dnsmasq-block.conf`; Suricata: 复制 rules 至 suricata.rules 目录并 reload。
## 内网解析行为说明(内网端这些域名会解析成什么)

**ta_node 本身不做域名解析**(源码中无任何 LookupHost/Resolver 调用),它是旁路流量检测:匹配内网流量里的 DNS 查询、DNS 应答、SNI、HTTP Host 与情报库比对。真正"解析"域名的是内网的递归 DNS / 安全设备。

内网解析结果取决于是否部署 sinkhole:

**场景A - 无 sinkhole(正常递归转发),157 个域名的解析去向:**

| 去向 | 域名数 | 说明 |
|---|---|---|
| 独立服务器(无PTR) | 61 | 直连 C2/VPS 专线 IP,IP 阻断有效 |
| Cloudflare 公共 CDN | 24 | 104.21.x / 172.67.x,共享 IP,不能按 IP 阻断(已移入 monitor),按域名阻断 |
| Backblaze B2 | 3 | 45.11.36~39.254 存储桶,按桶域名阻断 |
| 云厂商(Google/AWS) | 3 | GCP/AWS 虚拟机 |
| Wix | 1 | 185.230.63.x 建站平台 |
| 已失效(NXDOMAIN等) | 65 | 权威侧已无解析 |
| 自身投毒/特殊地址 | 3 | walter.filloco.icu(轮换返回 127.0.0.1)、ashx.lhlsjcb.com(AAAA=::1)、2-api.mooo.com(AAAA=2001::1)——这是域名权威侧自身行为,不是内网 sinkhole |

**场景B - 部署 sinkhole(推荐,直接用 docs/rules/dnsmasq-block.conf):** 157 个域名全部由内网 DNS 返回 0.0.0.0 / ::(本地应答),或安全设备配置的 sinkhole 内网 IP(如 10.x)。此时:

- 终端发出的 DNS 查询仍会被 ta_node 命中(匹配的是查询里的域名,与应答无关),照常产生告警;
- 若观察到域名被解析成内网 DNS 网关自身 IP(如 10.255.255.254),说明 sinkhole/重定向配置错误,应检查转发规则;
- 3 个自身投毒域名即使被解析为 127.0.0.1/::1,流量也不会出网,不影响检测(查询级命中)。
