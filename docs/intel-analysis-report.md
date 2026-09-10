# intel.yaml 规则数据分析报告

> 生成时间: 2026-08-21 14:50 | 数据文件: docs/intel.yaml | 规则总数: 363

> 解析对比: 系统DNS 10.255.255.254 (WSL内网) + 4个公共DNS (阿里223.5.5.5 / 谷歌8.8.8.8 / DNSPod 119.29.29.29 / 114DNS 114.114.114.114)


## 1. 规则总览

| 维度 | 分布 |
|---|---|
| 类型 domain | 157 条 |
| 类型 url | 104 条 |
| 类型 ip | 102 条 |
| 类别 | c2=232 / network_activity=70 / phishing=57 / botnet=4 |
| 严重度 | high=359 / medium=4 |
| 来源 | Threat Intel Hub=359 / ThreatBook=4 |
| TLP | WHITE=359 / (none)=4 |
| enabled | 363 条全部为 true |
| 处置建议 | block_and_report=363 |
| 创建时间 | 2026-07-07 16:20 ~ 2026-07-24 13:54 |
| 更新时间 | 2026-07-07 17:21 ~ 2026-07-24 13:54 |
| 重复 value | 7 个: 103.23.172.117×14, 45.11.36.254×3, 45.11.37.254×3, 45.11.38.254×3, 45.11.39.254×3, 45.137.205.53×2, 75.98.162.139×2 |

| 类型/类别 | c2 | network_activity | phishing | botnet |
|---|---|---|---|---|
| domain | 95 | 29 | 33 | 0 |
| url | 73 | 14 | 17 | 0 |
| ip | 64 | 27 | 7 | 4 |

## 2. 域名/主机解析概况 (188 个去重主机)

| 解析器 | 可解析 | NXDOMAIN | 其他错误 | 其他错误明细 |
|---|---|---|---|---|
| 系统DNS | 123 | 46 | 19 | ESERVFAIL=11 / ENODATA=7 / ETIMEOUT=1 |
| 阿里223.5.5.5 | 109 | 57 | 22 | ESERVFAIL=9 / ENODATA=7 / ETIMEOUT=6 |
| 谷歌8.8.8.8 | 100 | 50 | 38 | ETIMEOUT=27 / ENODATA=5 / ESERVFAIL=5 / EREFUSED=1 |
| DNSPod119.29.29.29 | 114 | 56 | 18 | ENODATA=7 / ESERVFAIL=7 / ETIMEOUT=4 |
| 114DNS114.114.114.114 | 94 | 52 | 42 | ETIMEOUT=35 / ENODATA=5 / ESERVFAIL=2 |

系统DNS解析到的 A/AAAA 记录类型分布:

| 类型 | 数量 |
|---|---|
| 公网IP | 165 |
| 公网IPv6 | 62 |
| 内网/特殊地址v6 | 1 |
| 回环地址v6 | 1 |

## 3. 异常域名(公共DNS服务器IP / 内网及特殊地址)

### 3.1 解析到公共DNS服务器IP的域名

未发现。5 个解析器均未返回已知公共DNS服务器IP(8.8.8.8 / 114.114.114.114 / 223.5.5.5 等 60+ 个知名递归解析器地址)。

### 3.2 解析到内网/回环/特殊地址的域名(重点异常)

| 域名 | 解析器 | IP | 地址类型 | 类别 | 备注 |
|---|---|---|---|---|---|
| 2-api.mooo.com | alidns / cn114 / dnspod / google / sys / 首轮系统DNS | 2001::1 | 内网/特殊地址v6 | network_activity | Teredo特殊用途地址,所有解析器一致返回 |
| ashx.lhlsjcb.com | alidns / sys / 首轮系统DNS | ::1 | 回环地址v6 | network_activity | 回环地址,典型sinkhole/投毒特征 |
| walter.filloco.icu | 首轮系统DNS | 127.0.0.1 | 回环地址 | c2 | 回环地址,典型sinkhole/投毒特征 |

### 3.3 公网IP的 PTR 带 DNS 服务特征(疑似公共DNS被域名引用)

未发现。

## 4. 各解析器返回不一致的域名(疑似 fast-flux / CDN 差异)

| 域名 | 系统DNS | 阿里DNS | 谷歌DNS | DNSPod | 114DNS | 备注 |
|---|---|---|---|---|---|---|
| 2-api.mooo.com | 188.5.4.96 | - | 54.76.135.1 | 77.4.7.92 | 77.4.7.92 | fast-flux(各解析器均不同) |
| ashx.lhlsjcb.com | 221.228.32.13 | 221.228.32.13 | 104.251.55.114 | 104.251.55.114 | - | 差异 |
| pois43.s3.eu-central-003.backblazeb2.com | 45.11.36.254,45.11.37.254,45.11.38.254,45.11.39.254 | 45.11.36.254,45.11.37.254,45.11.38.254,45.11.39.254 | 45.11.36.254,45.11.37.254,45.11.38.254,45.11.39.254 | 45.11.36.254,45.11.37.254,45.11.38.254,45.11.39.254 | 45.11.37.254,45.11.38.254,45.11.39.254 | 差异 |
| sentiwaw.s3.eu-central-003.backblazeb2.com | 45.11.36.254,45.11.37.254,45.11.38.254,45.11.39.254 | 45.11.36.254,45.11.37.254,45.11.38.254,45.11.39.254 | 45.11.36.254,45.11.37.254,45.11.38.254,45.11.39.254 | 45.11.36.254,45.11.37.254,45.11.38.254,45.11.39.254 | 45.11.36.254,45.11.38.254,45.11.39.254 | 差异 |

### 4.1 系统DNS(内网)与公共DNS 方向性差异

| 域名 | 系统DNS | 公共DNS | 现象 |
|---|---|---|---|
| walwood.be | 无法解析(ESERVFAIL) | 212.227.173.102; 212.227.173.102; 212.227.173.102; 212.227.173.102 | 内网DNS解析失败但公共DNS可解析 |

## 5. 各解析器均无法解析的域名

共 64 个域名在全部解析器上均无 A 记录:

| 域名 | 类别 | 系统 | 阿里 | 谷歌 | DNSPod | 114 |
|---|---|---|---|---|---|---|
| 1drvms.store | phishing | ENODATA | ENODATA | ENODATA | ENODATA | ENODATA |
| 2rxyt9urhq0bgj.org | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| aerobickarlaurbanovas.top | c2 | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND | ENOTFOUND |
| almersalstore.com | phishing | ENODATA | ENODATA | ENODATA | ENODATA | ENODATA |
| amazonalert.xyz | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| ametax.net | c2 | ENOTFOUND | ENOTFOUND | ETIMEOUT | ETIMEOUT | ENOTFOUND |
| angryipscanner.org | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| anus-staylard.xyz | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| apdhlhs3.xyz | c2 | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND | ENOTFOUND |
| apigrokcloud.icu | c2 | ENOTFOUND | ESERVFAIL | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| auramatrixa.com | c2 | ESERVFAIL | ESERVFAIL | ESERVFAIL | ESERVFAIL | ETIMEOUT |
| auth.samecloud.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| axiscamerastation.org | c2 | ENOTFOUND | ESERVFAIL | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| bqdrzbyq.cn | phishing | ENODATA | ENODATA | ENODATA | ENODATA | ENODATA |
| breaksd.wifihot.icu | c2 | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND | ENOTFOUND |
| cartaobb.com | network_activity | ENODATA | ENODATA | ENODATA | ENODATA | ENODATA |
| cl.distritovagas.com | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| cloudlanecdn.com | c2 | ESERVFAIL | ESERVFAIL | ETIMEOUT | ESERVFAIL | ETIMEOUT |
| commit.hanbiro.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| comunidadesparentais.com.br | network_activity | ESERVFAIL | ESERVFAIL | ESERVFAIL | ESERVFAIL | ETIMEOUT |
| creativecommunityinfo.art | c2 | ENODATA | ENODATA | ETIMEOUT | ENODATA | ENODATA |
| crefisa.online | network_activity | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| fair-bath-fond.xyz | c2 | ESERVFAIL | ENOTFOUND | ETIMEOUT | ENOTFOUND | ENOTFOUND |
| fast.raidher.icu | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| fiusyevr.live | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| global.webjine.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| hcgos.com | network_activity | ENODATA | ENODATA | ETIMEOUT | ENODATA | ETIMEOUT |
| hospitalinstallation.com | c2 | ENODATA | ENODATA | ENODATA | ENODATA | ETIMEOUT |
| hygienehistory.com | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| investigation-launches-hearings-copying.trycloudflare.com | network_activity | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| ip-scanner.org | c2 | ESERVFAIL | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| jzluw.com | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| lmaxjuyh.cn | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| mysimerp.net | network_activity | ESERVFAIL | ESERVFAIL | ESERVFAIL | ETIMEOUT | ESERVFAIL |
| networkservice.cyou | c2 | ESERVFAIL | ESERVFAIL | ETIMEOUT | ESERVFAIL | ETIMEOUT |
| oauth.shacloud.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| oobe.webjine.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| opmanager.pro | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| p.cloudlanecdn.com | c2 | ESERVFAIL | ETIMEOUT | ESERVFAIL | ESERVFAIL | ETIMEOUT |
| pestrear-lamp.xyz | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT |
| professionalhomebasedbusiness.com | network_activity | ETIMEOUT | ENOTFOUND | ETIMEOUT | ENOTFOUND | ENOTFOUND |
| q.cloudlanecdn.com | c2 | ESERVFAIL | ETIMEOUT | ESERVFAIL | ESERVFAIL | ETIMEOUT |
| rule-bead-dust.xyz | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| security.amazonassist.xyz | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| smallmartdirectintense.com | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| sonra.eutialyson.com | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| souls-entire-defined-routes.trycloudflare.com | network_activity | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND |
| statementstview.online | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| stewise.top | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| support.almersalstore.com | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| svuatwea.love | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT |
| taxfnat.tw | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| taxhub.tw | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| taxpro.tw | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| telesupportgroup.com | network_activity | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| tmodloader.org | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| tmodloader.pro | c2 | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND | ETIMEOUT |
| uglyshop-mare.xyz | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND |
| ux.strainedeasily.icu | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| vusuydryt.love | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT |
| walter.filloco.icu | c2 | ESERVFAIL | ESERVFAIL | EREFUSED | ESERVFAIL | ESERVFAIL |
| war.analyse.ltd | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |
| wawsenti.duckdns.org | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT |
| www.ilskdeid.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND |

## 6. 全部域名解析明细(157 条 domain 规则)

| # | 域名 | 类别 | 系统DNS A | 阿里DNS A | 谷歌DNS A | DNSPod A | 114DNS A | AAAA异常 |
|---|---|---|---|---|---|---|---|---|
| 1 | 0zbqnac1t4dv2t2wuodv1m.com | c2 | 85.239.149.178 | 85.239.149.178 | 85.239.149.178 | 85.239.149.178 | 85.239.149.178 | - |
| 2 | 1drvms.store | phishing | ENODATA | ENODATA | ENODATA | ENODATA | ENODATA | - |
| 3 | 2-api.mooo.com | network_activity | 188.5.4.96 | ETIMEOUT | 54.76.135.1 | 77.4.7.92 | 77.4.7.92 | 系统DNS=2001::1(内网/特殊地址v6); 阿里223.5.5.5=2001::1(内网/特殊地址v6); 谷歌8.8.8.8=2001::1(内网/特殊地址v6); DNSPod119.29.29.29=2001::1(内网/特殊地址v6); 114DNS114.114.114.114=2001::1(内网/特殊地址v6) |
| 4 | 2rxyt9urhq0bgj.org | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 5 | adobe.caladzy.com | c2 | 193.233.112.90 | 193.233.112.90 | 193.233.112.90 | 193.233.112.90 | 193.233.112.90 | - |
| 6 | adserviceupdate.com | c2 | 65.109.197.222 | 65.109.197.222 | 65.109.197.222 | 65.109.197.222 | 65.109.197.222 | - |
| 7 | aerobickarlaurbanovas.top | c2 | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND | ENOTFOUND | - |
| 8 | almacensantangel.com | c2 | 192.185.86.177 | 192.185.86.177 | 192.185.86.177 | 192.185.86.177 | 192.185.86.177 | - |
| 9 | almersalstore.com | phishing | ENODATA | ENODATA | ENODATA | ENODATA | ENODATA | - |
| 10 | amazonalert.xyz | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 11 | amazonattention.com | phishing | 172.67.190.89,104.21.57.117 | 104.21.57.117,172.67.190.89 | 172.67.190.89,104.21.57.117 | 104.21.57.117,172.67.190.89 | ETIMEOUT | - |
| 12 | ametax.net | c2 | ENOTFOUND | ENOTFOUND | ETIMEOUT | ETIMEOUT | ENOTFOUND | - |
| 13 | angryipscanner.org | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 14 | anus-staylard.xyz | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 15 | apdhlhs3.xyz | c2 | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND | ENOTFOUND | - |
| 16 | apigrokcloud.icu | c2 | ENOTFOUND | ESERVFAIL | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 17 | ashx.lhlsjcb.com | network_activity | 221.228.32.13 | 221.228.32.13 | 104.251.55.114 | 104.251.55.114 | ETIMEOUT | 系统DNS=::1(回环地址v6); 阿里223.5.5.5=::1(回环地址v6) |
| 18 | auramatrixa.com | c2 | ESERVFAIL | ESERVFAIL | ESERVFAIL | ESERVFAIL | ETIMEOUT | - |
| 19 | auth.hospitalinstallation.com | c2 | 45.137.205.53 | 45.137.205.53 | 45.137.205.53 | 45.137.205.53 | 45.137.205.53 | - |
| 20 | auth.samecloud.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 21 | axiscamerastation.org | c2 | ENOTFOUND | ESERVFAIL | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 22 | bduwih8.pro | c2 | 104.21.61.3,172.67.204.80 | 172.67.204.80,104.21.61.3 | 172.67.204.80,104.21.61.3 | 172.67.204.80,104.21.61.3 | 104.21.61.3,172.67.204.80 | - |
| 23 | beta.padmin.com | network_activity | 4.174.244.151 | 4.174.244.151 | 4.174.244.151 | 4.174.244.151 | 4.174.244.151 | - |
| 24 | bqdrzbyq.cn | phishing | ENODATA | ENODATA | ENODATA | ENODATA | ENODATA | - |
| 25 | breaksd.wifihot.icu | c2 | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND | ENOTFOUND | - |
| 26 | c.windowsupdate-cdn.com | network_activity | 162.141.111.227 | 162.141.111.227 | 162.141.111.227 | 162.141.111.227 | 162.141.111.227 | - |
| 27 | cartaobb.com | network_activity | ENODATA | ENODATA | ENODATA | ENODATA | ENODATA | - |
| 28 | cartaobrb.com.br | network_activity | 189.125.201.196 | 189.125.201.196 | 189.125.201.196 | 189.125.201.196 | 189.125.201.196 | - |
| 29 | cdnwoopress.com | network_activity | 172.67.189.35,104.21.65.69 | 172.67.189.35,104.21.65.69 | 172.67.189.35,104.21.65.69 | 104.21.65.69,172.67.189.35 | ETIMEOUT | - |
| 30 | cl.distritovagas.com | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 31 | cloudlanecdn.com | c2 | ESERVFAIL | ESERVFAIL | ETIMEOUT | ESERVFAIL | ETIMEOUT | - |
| 32 | commit.hanbiro.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 33 | computer.kplus.com | network_activity | 104.21.74.212,172.67.206.120 | 104.21.74.212,172.67.206.120 | 104.21.74.212,172.67.206.120 | 172.67.206.120,104.21.74.212 | 172.67.206.120,104.21.74.212 | - |
| 34 | comunidadesparentais.com.br | network_activity | ESERVFAIL | ESERVFAIL | ESERVFAIL | ESERVFAIL | ETIMEOUT | - |
| 35 | contrite.quirksturdy.icu | c2 | 104.21.44.89,172.67.198.57 | 172.67.198.57,104.21.44.89 | ETIMEOUT | 172.67.198.57,104.21.44.89 | 104.21.44.89,172.67.198.57 | - |
| 36 | couldinstallup.com | c2 | 188.208.141.177,194.5.97.169 | 194.5.97.169,188.208.141.177 | ETIMEOUT | 188.208.141.177,194.5.97.169 | 188.208.141.177,194.5.97.169 | - |
| 37 | cpppemwjewjoiwejow.sale | c2 | 172.67.144.214,104.21.55.54 | 104.21.55.54,172.67.144.214 | 172.67.144.214,104.21.55.54 | 172.67.144.214,104.21.55.54 | ETIMEOUT | - |
| 38 | creativecommunityinfo.art | c2 | ENODATA | ENODATA | ETIMEOUT | ENODATA | ENODATA | - |
| 39 | crefisa.online | network_activity | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 40 | deep-harborio.com | c2 | 172.67.172.146,104.21.80.11 | 104.21.80.11,172.67.172.146 | 104.21.80.11,172.67.172.146 | 172.67.172.146,104.21.80.11 | 104.21.80.11,172.67.172.146 | - |
| 41 | deepdive.hypernas.com | phishing | 13.233.70.40 | ETIMEOUT | 13.233.70.40 | 13.233.70.40 | ETIMEOUT | - |
| 42 | defenceprodindia.site | phishing | 172.67.198.241,104.21.60.179 | 172.67.198.241,104.21.60.179 | ETIMEOUT | 172.67.198.241,104.21.60.179 | 104.21.60.179,172.67.198.241 | - |
| 43 | denika.se | phishing | 95.155.236.35 | 95.155.236.35 | ETIMEOUT | 95.155.236.35 | ETIMEOUT | - |
| 44 | digital-magicians.com | c2 | 213.136.93.164 | 213.136.93.164 | 213.136.93.164 | 213.136.93.164 | 213.136.93.164 | - |
| 45 | dodod.lat | c2 | 104.21.79.27,172.67.140.235 | ESERVFAIL | 172.67.140.235,104.21.79.27 | 104.21.79.27,172.67.140.235 | 104.21.79.27,172.67.140.235 | - |
| 46 | dronemaker.org | network_activity | 84.200.205.244 | 84.200.205.244 | ETIMEOUT | 84.200.205.244 | ETIMEOUT | - |
| 47 | elcat.kg | phishing | 212.42.102.197 | 212.42.102.197 | 212.42.102.197 | 212.42.102.197 | 212.42.102.197 | - |
| 48 | elev8souvenirs.com | c2 | 91.204.209.33 | 91.204.209.33 | 91.204.209.33 | 91.204.209.33 | 91.204.209.33 | - |
| 49 | enhanceblabber.cc | c2 | 104.21.56.49,172.67.177.145 | 172.67.177.145,104.21.56.49 | 104.21.56.49,172.67.177.145 | 104.21.56.49,172.67.177.145 | 104.21.56.49,172.67.177.145 | - |
| 50 | etaxtw.cn | phishing | 103.115.56.86 | 103.115.56.86 | 103.115.56.86 | 103.115.56.86 | 103.115.56.86 | - |
| 51 | ev2sirbd269o5j.org | c2 | 188.40.187.145 | 188.40.187.145 | 188.40.187.145 | 188.40.187.145 | 188.40.187.145 | - |
| 52 | fadoklismokley.com | c2 | 178.16.53.92 | 178.16.53.92 | 178.16.53.92 | 178.16.53.92 | 178.16.53.92 | - |
| 53 | fair-bath-fond.xyz | c2 | ESERVFAIL | ENOTFOUND | ETIMEOUT | ENOTFOUND | ENOTFOUND | - |
| 54 | fast.raidher.icu | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 55 | fiusyevr.live | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 56 | fuaytrwese.love | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | - |
| 57 | fvxcuvuyte.live | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | - |
| 58 | gasrobariokley.com | c2 | 178.16.53.93 | 178.16.53.93 | 178.16.53.93 | 178.16.53.93 | 178.16.53.93 | - |
| 59 | gatuso.duckdns.org | c2 | 162.35.97.149 | 162.35.97.149 | 162.35.97.149 | 162.35.97.149 | ETIMEOUT | - |
| 60 | glanz-gmbh.de | network_activity | 185.243.11.51 | 185.243.11.51 | 185.243.11.51 | 185.243.11.51 | 185.243.11.51 | - |
| 61 | global.webjine.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 62 | google.com.hospitalinstallation.com | c2 | 45.137.205.53 | 45.137.205.53 | 45.137.205.53 | 45.137.205.53 | 45.137.205.53 | - |
| 63 | hcgos.com | network_activity | ENODATA | ENODATA | ETIMEOUT | ENODATA | ETIMEOUT | - |
| 64 | helloxcherry.com | phishing | 2.25.69.49 | 2.25.69.49 | 2.25.69.49 | 2.25.69.49 | 2.25.69.49 | - |
| 65 | hospitalinstallation.com | c2 | ENODATA | ENODATA | ENODATA | ENODATA | ETIMEOUT | - |
| 66 | hsauyeet.live | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | - |
| 67 | hygienehistory.com | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 68 | ijt0l3i8brit6q.org | c2 | 34.209.195.255 | 34.209.195.255 | 34.209.195.255 | 34.209.195.255 | ETIMEOUT | - |
| 69 | investigation-launches-hearings-copying.trycloudflare.com | network_activity | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 70 | ip-scanner.org | c2 | ESERVFAIL | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 71 | iran.dashboard.1drvms.store | phishing | 45.12.109.78 | 45.12.109.78 | ETIMEOUT | 45.12.109.78 | 45.12.109.78 | - |
| 72 | iwsmailserver.com | phishing | 172.67.137.72,104.21.73.18 | 172.67.137.72,104.21.73.18 | 104.21.73.18,172.67.137.72 | 104.21.73.18,172.67.137.72 | 172.67.137.72,104.21.73.18 | - |
| 73 | jaiydteds.love | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | ETIMEOUT | - |
| 74 | johncon.my | c2 | 104.21.25.179,172.67.134.113 | 172.67.134.113,104.21.25.179 | 172.67.134.113,104.21.25.179 | 104.21.25.179,172.67.134.113 | 172.67.134.113,104.21.25.179 | - |
| 75 | jzluw.com | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 76 | kdsuyrse.live | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | - |
| 77 | lisiutegrm.live | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | - |
| 78 | lmaxjuyh.cn | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 79 | looksta.icu | c2 | 104.21.33.112,172.67.161.227 | 104.21.33.112,172.67.161.227 | ETIMEOUT | 172.67.161.227,104.21.33.112 | 172.67.161.227,104.21.33.112 | - |
| 80 | mail.iwsmailserver.com | phishing | 104.21.73.18,172.67.137.72 | ETIMEOUT | 172.67.137.72,104.21.73.18 | 104.21.73.18,172.67.137.72 | 172.67.137.72,104.21.73.18 | - |
| 81 | med.gov.sy | phishing | 177.29.245.136 | 177.29.245.136 | 177.29.245.136 | 177.29.245.136 | ETIMEOUT | - |
| 82 | memphiswawu.com | c2 | 124.198.132.55 | 124.198.132.55 | 124.198.132.55 | 124.198.132.55 | ETIMEOUT | - |
| 83 | microuptime.com | network_activity | 84.200.205.244 | 84.200.205.244 | 84.200.205.244 | 84.200.205.244 | 84.200.205.244 | - |
| 84 | mksfuuerwo.live | c2 | 103.23.172.117 | 103.23.172.117 | ETIMEOUT | 103.23.172.117 | 103.23.172.117 | - |
| 85 | mofa.gov.iq | phishing | 172.67.68.251,104.26.1.234,104.26.0.234 | 104.26.0.234,172.67.68.251,104.26.1.234 | 172.67.68.251,104.26.1.234,104.26.0.234 | 172.67.68.251,104.26.1.234,104.26.0.234 | 104.26.1.234,172.67.68.251,104.26.0.234 | - |
| 86 | mysimerp.net | network_activity | ESERVFAIL | ESERVFAIL | ESERVFAIL | ETIMEOUT | ESERVFAIL | - |
| 87 | naintn.com | c2 | 172.67.136.116,104.21.46.82 | 172.67.136.116,104.21.46.82 | 104.21.46.82,172.67.136.116 | 104.21.46.82,172.67.136.116 | 172.67.136.116,104.21.46.82 | - |
| 88 | ncduuyese.live | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | - |
| 89 | networklookout.com | network_activity | 172.67.207.143,104.21.22.229 | 172.67.207.143,104.21.22.229 | 104.21.22.229,172.67.207.143 | 104.21.22.229,172.67.207.143 | 172.67.207.143,104.21.22.229 | - |
| 90 | networkservice.cyou | c2 | ESERVFAIL | ESERVFAIL | ETIMEOUT | ESERVFAIL | ETIMEOUT | - |
| 91 | njhwuyklw.com | phishing | 103.115.56.86 | 103.115.56.86 | 103.115.56.86 | 103.115.56.86 | 103.115.56.86 | - |
| 92 | node449013.dwservice.net | c2 | 51.68.153.212 | 51.68.153.212 | 51.68.153.212 | 51.68.153.212 | ETIMEOUT | - |
| 93 | node828765.dwservice.net | c2 | 194.61.31.164 | 194.61.31.164 | 194.61.31.164 | 194.61.31.164 | 194.61.31.164 | - |
| 94 | node896147.dwservice.net | c2 | 46.250.233.27 | 46.250.233.27 | 46.250.233.27 | 46.250.233.27 | 46.250.233.27 | - |
| 95 | oakwusya.love | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | - |
| 96 | oauth.shacloud.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 97 | oobe.webjine.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 98 | opmanager.pro | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 99 | p.cloudlanecdn.com | c2 | ESERVFAIL | ETIMEOUT | ESERVFAIL | ESERVFAIL | ETIMEOUT | - |
| 100 | paiwudyea.love | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | - |
| 101 | pestrear-lamp.xyz | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT | - |
| 102 | playtogga.com | c2 | 172.67.212.199,104.21.61.184 | 172.67.212.199,104.21.61.184 | 104.21.61.184,172.67.212.199 | 104.21.61.184,172.67.212.199 | 104.21.61.184,172.67.212.199 | - |
| 103 | pois43.s3.eu-central-003.backblazeb2.com | c2 | 45.11.36.254,45.11.38.254,45.11.39.254,45.11.37.254 | 45.11.38.254,45.11.37.254,45.11.39.254,45.11.36.254 | 45.11.36.254,45.11.39.254,45.11.37.254,45.11.38.254 | 45.11.36.254,45.11.39.254,45.11.37.254,45.11.38.254 | 45.11.37.254,45.11.38.254,45.11.39.254 | - |
| 104 | prism-matrixs.com | c2 | 104.21.60.213,172.67.201.201 | 172.67.201.201,104.21.60.213 | ETIMEOUT | 172.67.201.201,104.21.60.213 | ETIMEOUT | - |
| 105 | prism-vertex.com | c2 | 104.21.13.107,172.67.199.214 | 172.67.199.214,104.21.13.107 | 172.67.199.214,104.21.13.107 | 104.21.13.107,172.67.199.214 | 104.21.13.107,172.67.199.214 | - |
| 106 | professionalhomebasedbusiness.com | network_activity | ETIMEOUT | ENOTFOUND | ETIMEOUT | ENOTFOUND | ENOTFOUND | - |
| 107 | projetosmecanicos.com.br | network_activity | 177.73.233.244 | 177.73.233.244 | 177.73.233.244 | 177.73.233.244 | 177.73.233.244 | - |
| 108 | proton-network.com | c2 | 172.67.198.116,104.21.68.204 | 172.67.198.116,104.21.68.204 | 104.21.68.204,172.67.198.116 | 104.21.68.204,172.67.198.116 | 172.67.198.116,104.21.68.204 | - |
| 109 | q.cloudlanecdn.com | c2 | ESERVFAIL | ETIMEOUT | ESERVFAIL | ESERVFAIL | ETIMEOUT | - |
| 110 | qeuasytua.love | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | - |
| 111 | rema200426.duckdns.org | network_activity | 186.169.76.60 | 186.169.76.60 | 186.169.76.60 | 186.169.76.60 | 186.169.76.60 | - |
| 112 | resumeacceptable.com | c2 | 185.117.72.215 | ETIMEOUT | 185.117.72.215 | 185.117.72.215 | ETIMEOUT | - |
| 113 | rule-bead-dust.xyz | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 114 | safefire.jo | network_activity | 173.212.234.74 | 173.212.234.74 | ETIMEOUT | 173.212.234.74 | 173.212.234.74 | - |
| 115 | sdfw2026024.tos-cn-shanghai.volces.com | phishing | 180.97.50.1,180.97.50.130 | 180.97.50.1,180.97.50.130 | 180.97.50.130,180.97.50.1 | 180.97.50.130,180.97.50.1 | 180.97.50.1,180.97.50.130 | - |
| 116 | security.amazonassist.xyz | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 117 | sentiwaw.s3.eu-central-003.backblazeb2.com | c2 | 45.11.38.254,45.11.39.254,45.11.37.254,45.11.36.254 | 45.11.36.254,45.11.38.254,45.11.37.254,45.11.39.254 | 45.11.39.254,45.11.37.254,45.11.38.254,45.11.36.254 | 45.11.38.254,45.11.39.254,45.11.37.254,45.11.36.254 | 45.11.38.254,45.11.39.254,45.11.36.254 | - |
| 118 | smallmartdirectintense.com | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 119 | socialbizsolutions.com | network_activity | 35.214.137.246 | 35.214.137.246 | 35.214.137.246 | 35.214.137.246 | 35.214.137.246 | - |
| 120 | sonra.eutialyson.com | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 121 | souls-entire-defined-routes.trycloudflare.com | network_activity | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND | - |
| 122 | statementstview.online | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 123 | stewise.top | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 124 | support.almersalstore.com | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 125 | svuatwea.love | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT | - |
| 126 | syfiaydytea.live | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | - |
| 127 | taukeny.com | phishing | 103.115.56.86 | 103.115.56.86 | 103.115.56.86 | 103.115.56.86 | 103.115.56.86 | - |
| 128 | taxfnat.tw | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 129 | taxhub.tw | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 130 | taxpro.tw | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 131 | telesupportgroup.com | network_activity | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 132 | tkooyvff.cn | phishing | 103.115.56.86 | 103.115.56.86 | 103.115.56.86 | 103.115.56.86 | ETIMEOUT | - |
| 133 | tmodloader.org | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 134 | tmodloader.pro | c2 | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND | ETIMEOUT | - |
| 135 | transfergocompany.com | phishing | 40.112.253.185 | 40.112.253.185 | 40.112.253.185 | 40.112.253.185 | 40.112.253.185 | - |
| 136 | turnkeyaiagents.com | network_activity | 75.98.162.139 | 75.98.162.139 | 75.98.162.139 | 75.98.162.139 | 75.98.162.139 | - |
| 137 | twmoi2002.tos-cn-shanghai.volces.com | phishing | 180.97.50.130,180.97.50.1 | 180.97.50.1,180.97.50.130 | 180.97.50.130,180.97.50.1 | 180.97.50.1,180.97.50.130 | 180.97.50.130,180.97.50.1 | - |
| 138 | twswsb.cn | phishing | 47.238.232.44 | 47.238.232.44 | ETIMEOUT | 47.238.232.44 | 47.238.232.44 | - |
| 139 | twtaxgo.cn | phishing | 47.238.232.44 | 47.238.232.44 | 47.238.232.44 | 47.238.232.44 | 47.238.232.44 | - |
| 140 | uglyshop-mare.xyz | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT | ENOTFOUND | - |
| 141 | unityprogressall.org | phishing | 72.60.90.32 | 72.60.90.32 | ETIMEOUT | 72.60.90.32 | 72.60.90.32 | - |
| 142 | ux.strainedeasily.icu | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 143 | vfsgloball.net | network_activity | 185.230.63.186,185.230.63.107,185.230.63.171 | 185.230.63.186,185.230.63.107,185.230.63.171 | 185.230.63.171,185.230.63.107,185.230.63.186 | 185.230.63.171,185.230.63.186,185.230.63.107 | 185.230.63.107,185.230.63.186,185.230.63.171 | - |
| 144 | vurul.click | c2 | 102.220.160.203 | 102.220.160.203 | 102.220.160.203 | 102.220.160.203 | ETIMEOUT | - |
| 145 | vusuydryt.love | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT | - |
| 146 | w456w5.s3.eu-central-003.backblazeb2.com | c2 | 45.11.39.254,45.11.38.254,45.11.36.254,45.11.37.254 | 45.11.37.254,45.11.39.254,45.11.38.254,45.11.36.254 | ETIMEOUT | 45.11.36.254,45.11.37.254,45.11.39.254,45.11.38.254 | ETIMEOUT | - |
| 147 | walter.filloco.icu | c2 | ESERVFAIL | ESERVFAIL | EREFUSED | ESERVFAIL | ESERVFAIL | - |
| 148 | walwood.be | network_activity | ESERVFAIL | 212.227.173.102 | 212.227.173.102 | 212.227.173.102 | 212.227.173.102 | - |
| 149 | war.analyse.ltd | phishing | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 150 | wawsenti.duckdns.org | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ETIMEOUT | - |
| 151 | windowsupdate-cdn.com | network_activity | 172.67.151.208,104.21.73.251 | 104.21.73.251,172.67.151.208 | 172.67.151.208,104.21.73.251 | 172.67.151.208,104.21.73.251 | 172.67.151.208,104.21.73.251 | - |
| 152 | woopresscdn.com | network_activity | 104.21.13.178,172.67.156.222 | 104.21.13.178,172.67.156.222 | 172.67.156.222,104.21.13.178 | 104.21.13.178,172.67.156.222 | 104.21.13.178,172.67.156.222 | - |
| 153 | www.ilskdeid.o-r.kr | c2 | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | ENOTFOUND | - |
| 154 | xnbscuya.love | c2 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | 103.23.172.117 | - |
| 155 | xuastyrdqk.love | c2 | 103.23.172.117 | 103.23.172.117 | ETIMEOUT | 103.23.172.117 | 103.23.172.117 | - |
| 156 | zbyq.cn | phishing | 43.228.242.34 | 43.228.242.34 | 43.228.242.34 | 43.228.242.34 | 43.228.242.34 | - |
| 157 | zealpraxis.com | c2 | 172.67.210.254,104.21.67.11 | 104.21.67.11,172.67.210.254 | 104.21.67.11,172.67.210.254 | 172.67.210.254,104.21.67.11 | 104.21.67.11,172.67.210.254 | - |

> 注: 除表内标注外, 其余域名 AAAA 记录均为正常公网IPv6。

## 7. IP 类型规则(102 条)

| 地址类型 | 数量 |
|---|---|
| 公网IP | 102 |

| # | IP | 类型 | 类别 | 严重度 |
|---|---|---|---|---|
| 1 | 103.23.172.117 | 公网IP | c2 | high |
| 2 | 103.23.172.117 | 公网IP | c2 | high |
| 3 | 103.23.172.117 | 公网IP | c2 | high |
| 4 | 103.23.172.117 | 公网IP | c2 | high |
| 5 | 103.23.172.117 | 公网IP | c2 | high |
| 6 | 103.23.172.117 | 公网IP | c2 | high |
| 7 | 103.23.172.117 | 公网IP | c2 | high |
| 8 | 103.23.172.117 | 公网IP | c2 | high |
| 9 | 103.23.172.117 | 公网IP | c2 | high |
| 10 | 103.23.172.117 | 公网IP | c2 | high |
| 11 | 103.23.172.117 | 公网IP | c2 | high |
| 12 | 103.23.172.117 | 公网IP | c2 | high |
| 13 | 103.23.172.117 | 公网IP | c2 | high |
| 14 | 103.23.172.117 | 公网IP | c2 | high |
| 15 | 104.21.13.107 | 公网IP | c2 | high |
| 16 | 104.21.25.179 | 公网IP | c2 | high |
| 17 | 104.21.33.112 | 公网IP | c2 | high |
| 18 | 104.21.44.89 | 公网IP | c2 | high |
| 19 | 104.21.55.54 | 公网IP | c2 | high |
| 20 | 104.21.56.49 | 公网IP | c2 | high |
| 21 | 104.21.57.117 | 公网IP | phishing | high |
| 22 | 104.21.60.213 | 公网IP | c2 | high |
| 23 | 104.21.61.3 | 公网IP | c2 | high |
| 24 | 104.21.67.11 | 公网IP | c2 | high |
| 25 | 104.21.68.204 | 公网IP | c2 | high |
| 26 | 104.21.73.251 | 公网IP | network_activity | high |
| 27 | 104.21.74.212 | 公网IP | network_activity | high |
| 28 | 104.21.79.27 | 公网IP | c2 | high |
| 29 | 104.21.80.11 | 公网IP | c2 | high |
| 30 | 104.251.55.114 | 公网IP | network_activity | high |
| 31 | 117.86.105.145 | 公网IP | botnet | medium |
| 32 | 117.86.13.143 | 公网IP | botnet | medium |
| 33 | 162.141.111.227 | 公网IP | network_activity | high |
| 34 | 162.241.2.30 | 公网IP | network_activity | high |
| 35 | 163.245.195.172 | 公网IP | c2 | high |
| 36 | 172.67.134.113 | 公网IP | c2 | high |
| 37 | 172.67.140.235 | 公网IP | c2 | high |
| 38 | 172.67.144.214 | 公网IP | c2 | high |
| 39 | 172.67.151.208 | 公网IP | network_activity | high |
| 40 | 172.67.161.227 | 公网IP | c2 | high |
| 41 | 172.67.172.146 | 公网IP | c2 | high |
| 42 | 172.67.177.145 | 公网IP | c2 | high |
| 43 | 172.67.190.89 | 公网IP | phishing | high |
| 44 | 172.67.198.116 | 公网IP | c2 | high |
| 45 | 172.67.198.57 | 公网IP | c2 | high |
| 46 | 172.67.199.214 | 公网IP | c2 | high |
| 47 | 172.67.201.201 | 公网IP | c2 | high |
| 48 | 172.67.204.80 | 公网IP | c2 | high |
| 49 | 172.67.206.120 | 公网IP | network_activity | high |
| 50 | 172.67.210.254 | 公网IP | c2 | high |
| 51 | 173.212.234.74 | 公网IP | network_activity | high |
| 52 | 176.32.34.135 | 公网IP | network_activity | high |
| 53 | 177.73.233.244 | 公网IP | network_activity | high |
| 54 | 178.16.52.80 | 公网IP | network_activity | high |
| 55 | 18.216.200.48 | 公网IP | c2 | high |
| 56 | 181.235.8.24 | 公网IP | network_activity | high |
| 57 | 185.117.72.215 | 公网IP | c2 | high |
| 58 | 185.141.216.194 | 公网IP | network_activity | high |
| 59 | 185.230.63.107 | 公网IP | network_activity | high |
| 60 | 185.230.63.171 | 公网IP | network_activity | high |
| 61 | 185.230.63.186 | 公网IP | network_activity | high |
| 62 | 185.243.11.51 | 公网IP | network_activity | high |
| 63 | 185.91.69.38 | 公网IP | botnet | medium |
| 64 | 186.169.63.174 | 公网IP | network_activity | high |
| 65 | 189.125.201.196 | 公网IP | network_activity | high |
| 66 | 192.185.86.177 | 公网IP | c2 | high |
| 67 | 194.61.31.164 | 公网IP | c2 | high |
| 68 | 2.25.69.49 | 公网IP | phishing | high |
| 69 | 213.111.158.200 | 公网IP | phishing | high |
| 70 | 213.111.158.201 | 公网IP | phishing | high |
| 71 | 213.111.158.216 | 公网IP | phishing | high |
| 72 | 213.136.93.164 | 公网IP | c2 | high |
| 73 | 31.58.136.207 | 公网IP | phishing | high |
| 74 | 35.214.137.246 | 公网IP | network_activity | high |
| 75 | 35.247.29.111 | 公网IP | botnet | medium |
| 76 | 45.11.36.254 | 公网IP | c2 | high |
| 77 | 45.11.36.254 | 公网IP | c2 | high |
| 78 | 45.11.36.254 | 公网IP | c2 | high |
| 79 | 45.11.37.254 | 公网IP | c2 | high |
| 80 | 45.11.37.254 | 公网IP | c2 | high |
| 81 | 45.11.37.254 | 公网IP | c2 | high |
| 82 | 45.11.38.254 | 公网IP | c2 | high |
| 83 | 45.11.38.254 | 公网IP | c2 | high |
| 84 | 45.11.38.254 | 公网IP | c2 | high |
| 85 | 45.11.39.254 | 公网IP | c2 | high |
| 86 | 45.11.39.254 | 公网IP | c2 | high |
| 87 | 45.11.39.254 | 公网IP | c2 | high |
| 88 | 45.131.66.106 | 公网IP | network_activity | high |
| 89 | 45.137.205.53 | 公网IP | c2 | high |
| 90 | 45.137.205.53 | 公网IP | c2 | high |
| 91 | 46.250.233.27 | 公网IP | c2 | high |
| 92 | 5.39.253.206 | 公网IP | network_activity | high |
| 93 | 51.68.153.212 | 公网IP | c2 | high |
| 94 | 63.118.85.249 | 公网IP | network_activity | high |
| 95 | 64.89.160.17 | 公网IP | network_activity | high |
| 96 | 65.109.197.222 | 公网IP | c2 | high |
| 97 | 69.10.50.165 | 公网IP | c2 | high |
| 98 | 75.98.162.139 | 公网IP | network_activity | high |
| 99 | 75.98.162.139 | 公网IP | network_activity | high |
| 100 | 85.137.53.71 | 公网IP | network_activity | high |
| 101 | 85.239.149.178 | 公网IP | c2 | high |
| 102 | 89.34.90.99 | 公网IP | c2 | high |

## 8. URL 类型规则(104 条)

| # | URL | 类别 | 主机解析(系统DNS) |
|---|---|---|---|
| 1 | http://140.206.161.227:443 | network_activity | 无记录 |
| 2 | http://192.159.99.83/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest | c2 | 192.159.99.83 |
| 3 | http://192.227.211.41:8040/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest | c2 | 无记录 |
| 4 | http://192.36.27.51/TechSupV18Fix3.zip | network_activity | 192.36.27.51 |
| 5 | http://43.160.202.246:8053 | network_activity | 无记录 |
| 6 | http://45.32.144.255/update/update.exe | network_activity | 45.32.144.255 |
| 7 | http://45.76.155.202/update/update.exe | network_activity | 45.76.155.202 |
| 8 | http://64.95.13.238/payload.php' | network_activity | 64.95.13.238 |
| 9 | http://77.110.122.58:23205/cons_1.0.1.msi | c2 | 无记录 |
| 10 | http://77.110.122.58:23205/lQhEQui9a4lZ.exe | c2 | 无记录 |
| 11 | http://77.110.122.58:23205/lQhEQui9a4lZ.exe' | c2 | 无记录 |
| 12 | http://77.110.122.58:44479/bjxxUmG8K3uy.ps1 | c2 | 无记录 |
| 13 | http://95.179.213.0/update/AutoUpdater.exe | network_activity | 95.179.213.0 |
| 14 | http://95.179.213.0/update/Upgrade.exe | network_activity | 95.179.213.0 |
| 15 | http://aerobickarlaurbanovas.top/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest= | c2 | ENOTFOUND |
| 16 | http://auth.samecloud.o-r.kr/index.php | c2 | ENOTFOUND |
| 17 | http://dodod.lat/darwin/i/_ | c2 | 104.21.79.27,172.67.140.235 |
| 18 | http://dodod.lat/linux/i/_ | c2 | 104.21.79.27,172.67.140.235 |
| 19 | http://dodod.lat/win32/i/_ | c2 | 104.21.79.27,172.67.140.235 |
| 20 | http://faeytrdeaw.gu.cc | c2 | 103.93.252.212 |
| 21 | http://figyuyrqwr.gu.cc | c2 | 103.93.252.212 |
| 22 | http://fiusyevr.live | c2 | ENOTFOUND |
| 23 | http://fuaytrwese.love | c2 | 103.23.172.117 |
| 24 | http://hfyuayustrv.gu.cc | c2 | 103.93.252.212 |
| 25 | http://hsahyteiows.gu.cc | c2 | 103.93.252.212 |
| 26 | http://jaiydteds.love | c2 | 103.23.172.117 |
| 27 | http://jsiruytrawey.gu.cc | c2 | 103.93.252.212 |
| 28 | http://jzluw.com/cdn-dynmedia-1.microsoft.com/is/n03ufh3k003jdhkg99fhhas/is/content/ | c2 | ENOTFOUND |
| 29 | http://kawosyetw.gu.cc | c2 | 103.93.252.212 |
| 30 | http://kawuuterta.gu.cc | c2 | 103.93.252.212 |
| 31 | http://laiwutrencr.gu.cc | c2 | 103.93.252.212 |
| 32 | http://lasiduutfe.gu.cc | c2 | 103.93.252.212 |
| 33 | http://lisiutegrm.live | c2 | 103.23.172.117 |
| 34 | http://maisytawe.gu.cc | c2 | 103.93.252.212 |
| 35 | http://memphiswawu.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest | c2 | 124.198.132.55 |
| 36 | http://mksfuuerwo.live | c2 | 103.23.172.117 |
| 37 | http://naintn.com/amazoncdn.com/oeiich37874cj30dkk43885j10vj38h38jd/nrs/opn/ca/ | c2 | 172.67.136.116,104.21.46.82 |
| 38 | http://ncduuyese.live | c2 | 103.23.172.117 |
| 39 | http://nciyeyrawoe.gu.cc | c2 | 103.93.252.212 |
| 40 | http://nviuawusye.gu.cc | c2 | 103.93.252.212 |
| 41 | http://nvsieyrrawe.gu.cc | c2 | 103.93.252.212 |
| 42 | http://paiwudyea.love | c2 | 103.23.172.117 |
| 43 | http://pmcjsuyraw.gu.cc | c2 | 103.93.252.212 |
| 44 | http://qeuasytua.love | c2 | 103.23.172.117 |
| 45 | http://smallmartdirectintense.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest= | c2 | ENOTFOUND |
| 46 | http://sonra.eutialyson.com/inst24.msi | c2 | ENOTFOUND |
| 47 | http://steamcommunity.com/profiles/76561198735736086 | network_activity | 199.96.63.53 |
| 48 | http://steamcommunity.com/profiles/76561198742377525 | network_activity | 199.96.63.53 |
| 49 | http://stewise.top/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest | c2 | ENOTFOUND |
| 50 | http://svuatwea.love | c2 | ENOTFOUND |
| 51 | http://syfiaydytea.live | c2 | 103.23.172.117 |
| 52 | http://taxfnat.tw/ | phishing | ENOTFOUND |
| 53 | http://telegram.me/dikkh0k | network_activity | 149.154.167.99 |
| 54 | http://telegram.me/pr55ii | network_activity | 149.154.167.99 |
| 55 | http://viuyeyrwqs.gu.cc | c2 | 103.93.252.212 |
| 56 | http://vusuydryt.love | c2 | ENOTFOUND |
| 57 | http://www.ilskdeid.o-r.kr:8000/ | c2 | 无记录 |
| 58 | http://xkcifgieusr.gu.cc | c2 | 103.93.252.212 |
| 59 | http://xnbscuya.love | c2 | 103.23.172.117 |
| 60 | http://xuastyrdqk.love | c2 | 103.23.172.117 |
| 61 | http://yicoweytcbtw.gu.cc | c2 | 103.93.252.212 |
| 62 | http://zbyq.cn/Set^up^64.e^x^e | phishing | 43.228.242.34 |
| 63 | https://adserviceupdate.com/cac.aspx | c2 | 65.109.197.222 |
| 64 | https://almacensantangel.com/wp-includes/assets/YourSSA_Documents_0000000676152_05_187_2026_Document_0000000676152.rar | c2 | 192.185.86.177 |
| 65 | https://amazonalert.xyz/download/code.txt | phishing | ENOTFOUND |
| 66 | https://amazonattention.com/verify | phishing | 172.67.190.89,104.21.57.117 |
| 67 | https://auth.samecloud.o-r.kr/index.php | c2 | ENOTFOUND |
| 68 | https://beta.padmin.com/mybenefits/Templates/cd.zip | network_activity | 4.174.244.151 |
| 69 | https://cl.distritovagas.com/hte.hta | c2 | ENOTFOUND |
| 70 | https://commit.hanbiro.o-r.kr/index.php | c2 | ENOTFOUND |
| 71 | https://computer.kplus.com/cd.zip | network_activity | 104.21.74.212,172.67.206.120 |
| 72 | https://deepdive.hypernas.com/hypernas/api/page.php?uid= | phishing | 13.233.70.40 |
| 73 | https://defenceprodindia.site/server.php?file=Reader_en_install | phishing | 172.67.198.241,104.21.60.179 |
| 74 | https://digital-magicians.com/photo295825092412.zip?_r=ea623202 | c2 | 213.136.93.164 |
| 75 | https://dodod.lat/ | c2 | 104.21.79.27,172.67.140.235 |
| 76 | https://dodod.lat/darwin/i/_ | c2 | 104.21.79.27,172.67.140.235 |
| 77 | https://dodod.lat/linux/i/_ | c2 | 104.21.79.27,172.67.140.235 |
| 78 | https://dodod.lat/win32/i/_ | c2 | 104.21.79.27,172.67.140.235 |
| 79 | https://fadoklismokley.com/work/ | c2 | 178.16.53.92 |
| 80 | https://fadoklismokley.com/work/?counter=0&type=1&guid=3B7FFFF7F331576B6FA3479BDF43&os=6&arch=1&username=JohnDoe&group=2201209746&ver=2.3&up=7&direction=fadoklismokley.com | c2 | 178.16.53.92 |
| 81 | https://fvxcuvuyte.live | c2 | 103.23.172.117 |
| 82 | https://gasrobariokley.com/work/ | c2 | 178.16.53.93 |
| 83 | https://gasrobariokley.com/work/?counter=0&type=1&guid=3B7FFFF7F331576B6FA3479BDF43&os=6&arch=1&username=JohnDoe&group=2201209746&ver=2.3&up=7&direction=gasrobariokley.com | c2 | 178.16.53.93 |
| 84 | https://global.webjine.o-r.kr/index.php | c2 | ENOTFOUND |
| 85 | https://helloxcherry.com/cdn/static/c3587edc48c37656b29bcd3da9458eea/update | phishing | 2.25.69.49 |
| 86 | https://hsauyeet.live | c2 | 103.23.172.117 |
| 87 | https://hygienehistory.com/cac.aspx | c2 | ENOTFOUND |
| 88 | https://iran.dashboard.1drvms.store/errors/sessionerrors/expire?client= | phishing | 45.12.109.78 |
| 89 | https://iran.dashboard.1drvms.store/errors/sessionerrors/expire?client=[redacted] | phishing | 45.12.109.78 |
| 90 | https://kdsuyrse.live | c2 | 103.23.172.117 |
| 91 | https://mail.iwsmailserver.com/owa/auth/logon.aspx?uid= | phishing | 104.21.73.18,172.67.137.72 |
| 92 | https://njhwuyklw.com/ | phishing | 103.115.56.86 |
| 93 | https://oakwusya.love | c2 | 103.23.172.117 |
| 94 | https://oauth.shacloud.o-r.kr:8443 | c2 | 无记录 |
| 95 | https://oobe.webjine.o-r.kr/index.php | c2 | ENOTFOUND |
| 96 | https://pivigames.blog/adbuho | c2 | 104.21.17.80,172.67.175.78 |
| 97 | https://resumeacceptable.com | c2 | 185.117.72.215 |
| 98 | https://sdfw2026024.tos-cn-shanghai.volces.com/E-Invoice.rar | phishing | 180.97.50.1,180.97.50.130 |
| 99 | https://sdfw2026024.tos-cn-shanghai.volces.com/E-Invoice.rar. | phishing | 180.97.50.1,180.97.50.130 |
| 100 | https://twmoi2002.tos-cn-shanghai.volces.com/E-Invoice.rar | phishing | 180.97.50.130,180.97.50.1 |
| 101 | https://twtaxgo.cn/uploads/20260129/taxIs_RX3001.7z | phishing | 47.238.232.44 |
| 102 | https://twtaxgo.cn/uploads/20260129/taxIs_RX3001.7z. | phishing | 47.238.232.44 |
| 103 | https://unityprogressall.org/imagecontent/getimgcontent.php?id= | phishing | 72.60.90.32 |
| 104 | https://www.dwservice.net/ | c2 | 94.72.121.132,116.203.208.186,74.208.130.208 |

### 8.1 URL 中直接使用 IP 字面量的条目

| URL | IP | 类别 |
|---|---|---|
| http://95.179.213.0/update/Upgrade.exe | 95.179.213.0 | network_activity |
| http://95.179.213.0/update/AutoUpdater.exe | 95.179.213.0 | network_activity |
| http://45.76.155.202/update/update.exe | 45.76.155.202 | network_activity |
| http://45.32.144.255/update/update.exe | 45.32.144.255 | network_activity |
| http://192.159.99.83/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest | 192.159.99.83 | c2 |
| http://192.36.27.51/TechSupV18Fix3.zip | 192.36.27.51 | network_activity |
| http://64.95.13.238/payload.php' | 64.95.13.238 | network_activity |

## 9. 威胁标签 TOP20

| 标签 | 数量 |
|---|---|
| clickfix | 88 |
| adaptixc2 | 83 |
| defense-evasion | 76 |
| darkcloud stealer | 76 |
| malware-as-a-service | 76 |
| formbook | 76 |
| winos4.0 | 76 |
| crypter-service | 76 |
| xworm | 76 |
| blockchain c2 | 50 |
| phishing | 46 |
| fake captcha | 38 |
| byovd | 38 |
| ransomware | 34 |
| dll sideloading | 34 |
| webdav | 34 |
| steganography | 34 |
| amatera stealer | 34 |
| acr stealer | 34 |
| cobalt strike | 30 |

## 10. 域名权威NS服务商分布

| NS | 域名数 |
|---|---|
| a.share-dns.com | 15 |
| b.share-dns.net | 15 |
| goat.dnspod.net | 5 |
| harmony.dnspod.net | 5 |
| clyde.ns.cloudflare.com | 5 |
| connie.ns.cloudflare.com | 5 |
| junade.ns.cloudflare.com | 2 |
| nick.ns.cloudflare.com | 2 |
| sandra.ns.cloudflare.com | 2 |
| ns7.alidns.com | 2 |
| ns8.alidns.com | 2 |
| ns1.contabo.net | 2 |
| ns2.contabo.net | 2 |
| ns3.contabo.net | 2 |
| dns1.registrar-servers.com | 1 |
| dns2.registrar-servers.com | 1 |
| ns1.sinkhole.caad.fkie.fraunhofer.de | 1 |
| ns2.sinkhole.caad.fkie.fraunhofer.de | 1 |
| ns3.sinkhole.caad.fkie.fraunhofer.de | 1 |
| ns1.csof.net | 1 |
| ns2.csof.net | 1 |
| ns3.csof.net | 1 |
| ns4.csof.net | 1 |
| ns1.ultahost.com | 1 |
| ns2.ultahost.com | 1 |
| ns3.ultahost.com | 1 |
| ns4.ultahost.com | 1 |
| ns1.dnsowl.com | 1 |
| ns2.dnsowl.com | 1 |
| ns3.dnsowl.com | 1 |
| hera.ns.cloudflare.com | 1 |
| tony.ns.cloudflare.com | 1 |
| ns1.loopia.se | 1 |
| ns2.loopia.se | 1 |
| elmo.ns.cloudflare.com | 1 |
| ines.ns.cloudflare.com | 1 |
| ns3.tld.sy | 1 |
| ns4.tld.sy | 1 |
| ns001.microsoftinternetsafety.net | 1 |
| ns002.microsoftinternetsafety.net | 1 |
| casey.ns.cloudflare.com | 1 |
| davina.ns.cloudflare.com | 1 |
| romina.ns.cloudflare.com | 1 |
| kyle.ns.cloudflare.com | 1 |
| nola.ns.cloudflare.com | 1 |
| 1-you.njalla.no | 1 |
| 2-can.njalla.in | 1 |
| 3-get.njalla.fo | 1 |
| amos.ns.cloudflare.com | 1 |
| naya.ns.cloudflare.com | 1 |
| ns1.elcat.kg | 1 |
| ns2.elcat.kg | 1 |
| ns3.elcat.kg | 1 |
| camilo.ns.cloudflare.com | 1 |
| nelly.ns.cloudflare.com | 1 |
| elma.ns.cloudflare.com | 1 |
| wesley.ns.cloudflare.com | 1 |
| ns1.maehdros.be | 1 |
| ns2.maehdros.be | 1 |
| grannbo.ns.cloudflare.com | 1 |
| rick.ns.cloudflare.com | 1 |
| augustus.ns.cloudflare.com | 1 |
| laura.ns.cloudflare.com | 1 |
| brenna.ns.cloudflare.com | 1 |
| tadeo.ns.cloudflare.com | 1 |
| ns1.absoluteict.co.uk | 1 |
| ns2.absoluteict.co.uk | 1 |
| brynne.ns.cloudflare.com | 1 |
| ns1.ename.net | 1 |
| ns2.ename.net | 1 |
| ns1.dyna-ns.net | 1 |
| ns2.dyna-ns.net | 1 |
| ariadne.ns.cloudflare.com | 1 |
| tosana.ns.cloudflare.com | 1 |
| ashton.ns.cloudflare.com | 1 |
| kimora.ns.cloudflare.com | 1 |
| thcservers.earth.orderbox-dns.com | 1 |
| thcservers.mars.orderbox-dns.com | 1 |
| thcservers.mercury.orderbox-dns.com | 1 |
| thcservers.venus.orderbox-dns.com | 1 |
| docks07.rzone.de | 1 |
| shades09.rzone.de | 1 |
| ns1.projetosmecanicos.com.br | 1 |
| ns2.projetosmecanicos.com.br | 1 |
| ns1.siteground.net | 1 |
| ns2.siteground.net | 1 |
| ns1909215924.a2dns.com | 1 |
| ns7598162139.a2dns.com | 1 |
| ns1.1domainregistry.com | 1 |
| ns2.1domainregistry.com | 1 |
| ns3.1domainregistry.com | 1 |
| ns4.1domainregistry.com | 1 |
| katja.ns.cloudflare.com | 1 |
| rodney.ns.cloudflare.com | 1 |
| hunts.ns.cloudflare.com | 1 |
| kami.ns.cloudflare.com | 1 |
| eve.ns.cloudflare.com | 1 |
| plato.ns.cloudflare.com | 1 |
| clark.ns.cloudflare.com | 1 |
| sreeni.ns.cloudflare.com | 1 |
| benedict.ns.cloudflare.com | 1 |
| mina.ns.cloudflare.com | 1 |
| cash.ns.cloudflare.com | 1 |
| mira.ns.cloudflare.com | 1 |
| lilyana.ns.cloudflare.com | 1 |
| phil.ns.cloudflare.com | 1 |
| arturo.ns.cloudflare.com | 1 |
| penny.ns.cloudflare.com | 1 |
| 1-ceci.njalla.do | 1 |
| 2-nest.pipe.ma | 1 |
| 3-pas.njalla.in | 1 |
| 10.1.16.4 | 1 |
| 10.1.16.5 | 1 |
| ns01.cartaobrb.com.br | 1 |
| ns02.cartaobrb.com.br | 1 |
| srvvmz02 | 1 |
| ns4.wixdns.net | 1 |
| ns5.wixdns.net | 1 |
| ns25.websitewelcome.com | 1 |
| ns26.websitewelcome.com | 1 |
| addilyn.ns.cloudflare.com | 1 |
| jacob.ns.cloudflare.com | 1 |

## 11. 结论与建议

1. **内网/特殊地址异常(3个域名)**:
   - `walter.filloco.icu`: 首轮系统解析返回 `127.0.0.1`(回环),后续查询 ESERVFAIL,权威侧轮换返回回环地址,典型反检测/投毒行为;
   - `ashx.lhlsjcb.com`: AAAA 返回 `::1`(系统/阿里DNS),A 记录在不同解析器间不一致(221.228.32.13 vs 104.251.55.114);
   - `2-api.mooo.com`: AAAA 在所有解析器一致返回 `2001::1`(Teredo特殊用途地址),A 记录 fast-flux(188.5.4.96 / 54.76.135.1 / 77.4.7.92)。
2. **公共DNS服务器IP**: 本轮 5 个解析器均未发现任何域名解析到已知公共DNS服务器IP(8.8.8.8 / 114.114.114.114 / 223.5.5.5 等);若在业务环境曾观察到该现象,大概率是本地递归DNS/安全设备对黑名单域名的投毒或sinkhole应答,建议在节点上复测。
3. **失效域名**: 64 个域名在全部解析器上无解析(多为 NXDOMAIN),可考虑清理或降级;
4. **fast-flux**: 2-api.mooo.com、ashx.lhlsjcb.com 等解析随解析器变化,拦截需依赖实时DNS而非静态IP;
5. **IP 规则 102 条全部为公网IP**,无内网/保留地址;但存在重复规则: 103.23.172.117×14、45.11.36~39.254 各×3、45.137.205.53×2、75.98.162.139×2,可去重;
6. **TLP 全部为 WHITE**(4条未标注),与公开情报来源(OTX)一致;
7. **NS 观察**: 15 个域名挂在免费动态DNS share-dns.com(a.share-dns.com / b.share-dns.net)上,典型的恶意DDNS托管;ev2sirbd269o5j.org 的 NS 已被 FKIE sinkhole 接管(可能是已失效样本域名)。