#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, ipaddress, collections, re, time, os, yaml
from urllib.parse import urlsplit

items = json.load(open('.analysis/items.json', encoding='utf-8'))
multi = json.load(open('.analysis/dns_multi.json', encoding='utf-8'))
ptr_ips = json.load(open('.analysis/ptr_ips.json', encoding='utf-8'))

NOW = int(time.time())
EXP_LIVE = NOW + 90*86400
EXP_DEAD = NOW + 30*86400

RES_NAMES = ['sys','alidns','google','dnspod','cn114']
def A(rec, rn):
    r = rec.get(rn)
    if not r: return None
    a = r.get('A')
    return a if isinstance(a, list) else None

# ---------- shared CDN / cloud ranges (monitor-only) ----------
MONITOR_NETS = [
    ipaddress.ip_network('104.16.0.0/13'),   # Cloudflare
    ipaddress.ip_network('172.64.0.0/13'),   # Cloudflare
    ipaddress.ip_network('45.11.36.0/22'),   # Backblaze B2 EU-central
    ipaddress.ip_network('185.230.63.0/24'), # Wix
]
MONITOR_PTR_SUFFIX = ('unifiedlayer.com','webhosting.systems','hstgr.cloud','invisihost.net')

def ip_monitor(ipstr):
    ip = ipaddress.ip_address(ipstr)
    for net in MONITOR_NETS:
        if ip in net: return True
    ptrs = ptr_ips.get(ipstr, ['<no-ptr>'])
    for p in ptrs:
        if p != '<no-ptr>' and p.endswith(MONITOR_PTR_SUFFIX): return True
    return False

# ---------- dedupe ip rules ----------
byval = collections.defaultdict(list)
for i in items:
    if i['type'] == 'ip': byval[i['value']].append(i)

def pick_best(lst):
    def score(x):
        s = len(x.get('description','')) + 10*len(x.get('tags') or []) + 5*len((x.get('evidence') or {}).get('threat_labels') or [])
        if x.get('source') == 'ThreatBook': s += 20
        return s
    return max(lst, key=score)

active, monitor, removed = [], [], []
def rm(it, reason):
    it = dict(it)
    it['description'] = '【清洗移除】原因: %s | %s' % (reason, it.get('description',''))
    it['expire_at'] = EXP_DEAD
    removed.append(it)

for v, lst in byval.items():
    best = pick_best(lst)
    best = dict(best)
    if len(lst) > 1:
        for extra in lst:
            if extra['id'] != best['id']:
                rm(extra, '重复IP规则, 与 id=%s 相同, 保留信息最全条目' % best['id'])
    if ip_monitor(v):
        best['enabled'] = False
        best['expire_at'] = EXP_DEAD
        monitor.append(best)
    else:
        best['expire_at'] = EXP_LIVE
        active.append(best)

# ---------- domains ----------
dead_domains = set()
for h, rec in multi.items():
    if all(not A(rec, rn) for rn in RES_NAMES):
        dead_domains.add(h)

for i in items:
    if i['type'] != 'domain': continue
    it = dict(i)
    v = it['value'].strip().rstrip('.').lower()
    it['value'] = v
    it['expire_at'] = EXP_DEAD if v in dead_domains else EXP_LIVE
    active.append(it)

# ---------- urls ----------
for i in items:
    if i['type'] != 'url': continue
    it = dict(i)
    v = it['value'].strip()
    it['value'] = v
    host = ''
    try:
        host = (urlsplit(v).hostname or '').lower()
    except Exception:
        host = ''
    if host and host in dead_domains:
        rm(it, 'URL主机已失效(所有解析器无解析): %s' % host)
        continue
    it['expire_at'] = EXP_LIVE
    active.append(it)

# ---------- normalize ----------
for it in active:
    if it['type'] == 'domain':
        it['value'] = it['value'].strip().rstrip('.').lower()
    if it['type'] == 'url':
        it['value'] = it['value'].strip()
for it in monitor:
    it['expire_at'] = EXP_DEAD

def sort_key(it): return (it['type'], it['value'].lower())
active.sort(key=sort_key)
monitor.sort(key=sort_key)
removed.sort(key=sort_key)

print('active:', len(active), '| monitor:', len(monitor), '| removed:', len(removed))
print('active by type:', dict(collections.Counter(i['type'] for i in active)))
print('monitor by type:', dict(collections.Counter(i['type'] for i in monitor)))
print('removed by type:', dict(collections.Counter(i['type'] for i in removed)))

# ---------- write YAML ----------
def dump(path, lst):
    with open(path, 'w', encoding='utf-8') as f:
        yaml.safe_dump({'items': lst}, f, allow_unicode=True, sort_keys=False,
                       default_flow_style=False, indent=2, width=4096)
dump('docs/intel-clean.yaml', active)
dump('docs/intel-monitor.yaml', monitor)
dump('docs/intel-removed.yaml', removed)

# ---------- plain lists ----------
os.makedirs('docs/rules', exist_ok=True)
domains = sorted(set(i['value'] for i in active if i['type']=='domain'))
ips_blk = sorted(set(i['value'] for i in active if i['type']=='ip'), key=lambda x: ipaddress.ip_address(x))
ips_mon = sorted(set(i['value'] for i in monitor if i['type']=='ip'), key=lambda x: ipaddress.ip_address(x))
urls    = sorted(set(i['value'] for i in active if i['type']=='url'))

open('docs/rules/domains.txt','w').write(chr(10).join(domains) + chr(10))
open('docs/rules/ips-block.txt','w').write(chr(10).join(ips_blk) + chr(10))
open('docs/rules/ips-monitor-only.txt','w').write(chr(10).join(ips_mon) + chr(10))
open('docs/rules/urls.txt','w').write(chr(10).join(urls) + chr(10))

with open('docs/rules/dnsmasq-block.conf','w') as f:
    f.write('# ta_node intel sinkhole - %d domains - generated %s' % (len(domains), time.strftime('%Y-%m-%d %H:%M')) + chr(10))
    for d in domains:
        f.write('address=/%s/0.0.0.0' % d + chr(10))
        f.write('address=/%s/::' % d + chr(10))
with open('docs/rules/hosts-block.txt','w') as f:
    f.write('# ta_node intel sinkhole hosts format - %d domains' % len(domains) + chr(10))
    for d in domains:
        f.write('0.0.0.0 %s' % d + chr(10))
        f.write(':: %s' % d + chr(10))
with open('docs/rules/suricata-dns.rules','w') as f:
    for n, d in enumerate(domains, 1):
        f.write('alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"TA-INTEL malicious domain %s"; dns.query; content:"%s"; nocase; endswith; classtype:trojan-activity; metadata:category ta-intel; priority:1; sid:%d; rev:1;)' % (d, d, 3000000+n) + chr(10))

# ---------- domain status csv ----------
with open('docs/rules/domain-status.csv','w',encoding='utf-8-sig') as f:
    f.write('域名,状态,系统DNS,阿里DNS,谷歌DNS,DNSPod,114DNS' + chr(10))
    for d in domains:
        rec = multi.get(d, {})
        cols = []
        for rn in RES_NAMES:
            a = A(rec, rn)
            if a: cols.append(';'.join(a))
            else: cols.append(rec[rn]['A'].get('err','?') if rec.get(rn) else '-')
        st = '已失效' if d in dead_domains else '正常'
        f.write('%s,%s,%s' % (d, st, ','.join(cols)) + chr(10))

# ---------- report ----------
R = []
R.append('# intel.yaml 清洗报告(实战规则包)' + chr(10))
R.append('> 生成: %s | 输入 docs/intel.yaml (363条) -> 清洗后 %d 条启用规则' % (time.strftime('%Y-%m-%d %H:%M'), len(active)) + chr(10))
R.append('')
R.append('## 清洗动作' + chr(10))
R.append('| 动作 | 数量 | 说明 |')
R.append('|---|---|---|')
R.append('| 重复IP去重 | %d 条移除 | 103.23.172.117×14→1、45.11.36~39.254 各×3→1、45.137.205.53×2→1、75.98.162.139×2→1; ip 规则 102→79 唯一, 移除件归档于 intel-removed.yaml |' % sum(1 for i in removed if i['type']=='ip'))
R.append('| 共享CDN/云IP降级 | %d 条 | Cloudflare 30条 / Backblaze B2 4个 / Wix 3条 / 共享主机 5条; IP级阻断误伤大, 移至 monitor(enabled=false), 相关威胁由域名规则覆盖 |' % len(monitor))
R.append('| URL主机失效移除 | %d 条 | 主机无解析则URL规则永不命中 |' % sum(1 for i in removed if i['type']=='url'))
R.append('| 失效域名保留 | %d 个 | ta_node 匹配 DNS 查询, 失效C2/钓鱼域名仍可检出失陷主机信标; expire_at=30天, 正常域名90天 |' % len([d for d in domains if d in dead_domains]))
R.append('')
R.append('## 产物' + chr(10))
R.append('| 文件 | 用途 | 数量 |')
R.append('|---|---|---|')
R.append('| docs/intel-clean.yaml | ta_node --intel-file 直接替换 | %d 条 (domain %d / ip %d / url %d) |' % (len(active), sum(1 for i in active if i['type']=='domain'), sum(1 for i in active if i['type']=='ip'), sum(1 for i in active if i['type']=='url')))
R.append('| docs/intel-monitor.yaml | 共享CDN/云IP, enabled=false, 仅审计参考 | %d 条 |' % len(monitor))
R.append('| docs/intel-removed.yaml | 清洗归档(重复/失效URL), 可回溯 | %d 条 |' % len(removed))
R.append('| docs/rules/domains.txt | 域名黑名单(每行1个) | %d |' % len(domains))
R.append('| docs/rules/ips-block.txt | IP阻断清单(已去重, 剔除CDN/云) | %d |' % len(ips_blk))
R.append('| docs/rules/ips-monitor-only.txt | 高风险误伤IP(建议只监控不阻断) | %d |' % len(ips_mon))
R.append('| docs/rules/urls.txt | URL黑名单 | %d |' % len(urls))
R.append('| docs/rules/dnsmasq-block.conf | dnsmasq/AdGuardHome sinkhole 配置 | %d×2 行 |' % len(domains))
R.append('| docs/rules/hosts-block.txt | hosts 文件格式 | %d×2 行 |' % len(domains))
R.append('| docs/rules/suricata-dns.rules | Suricata DNS 查询告警规则 | %d 条 |' % len(domains))
R.append('| docs/rules/domain-status.csv | 域名解析状态明细(5解析器) | %d 行 |' % len(domains))
R.append('')
R.append('## 关键处置说明' + chr(10))
R.append('1. **保留解析异常域名规则**: walter.filloco.icu(轮换返回127.0.0.1)、ashx.lhlsjcb.com(AAAA=::1)、2-api.mooo.com(AAAA=2001::1, fast-flux) —— 三者均保留域名规则: ta_node 对 DNS 查询做匹配, 域名级检测不受其IP异常影响; 这些IP未进入IP阻断清单, 不会误伤本机/内网。' + chr(10))
R.append('2. **不阻断公共DNS/IP**: 全量数据中不存在指向公共DNS服务器IP或内网IP的 ip 规则; 若发现内网设备解析出 127.0.0.1/::1, 属于上述域名自身投毒行为, 用域名规则即可覆盖。' + chr(10))
R.append('3. **Cloudflare/Backblaze/Wix 等共享IP不阻断**: 30 条 Cloudflare、12 条 Backblaze B2(去重后4个IP)、3 条 Wix 等IP规则移入 monitor, 相关威胁已由域名规则覆盖(如 *.s3.eu-central-003.backblazeb2.com 桶域名)。' + chr(10))
R.append('4. **过期机制**: 全部规则带 expire_at(正常90天/失效域名与monitor 30天), ta_node store 的 PruneExpired 可自动清理。' + chr(10))
R.append('5. **用法**: ta_node: `--intel-file ./docs/intel-clean.yaml`; dnsmasq: `conf-file=/path/dnsmasq-block.conf`; Suricata: 复制 rules 至 suricata.rules 目录并 reload。' + chr(10))
open('docs/intel-clean-report.md','w',encoding='utf-8').write(chr(10).join(R))
print('files written')