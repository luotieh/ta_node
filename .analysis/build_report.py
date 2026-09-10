#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, ipaddress, collections, re, datetime

items = json.load(open('.analysis/items.json', encoding='utf-8'))
sysres = json.load(open('.analysis/dns_results.json', encoding='utf-8'))
pubres = json.load(open('.analysis/dns_public.json', encoding='utf-8'))
ptr = json.load(open('.analysis/ptr.json', encoding='utf-8'))

PUBLIC_DNS = {ipaddress.ip_address(x) for x in [
 '8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1','9.9.9.9','149.112.112.112',
 '208.67.222.222','208.67.220.220','4.2.2.1','4.2.2.2','4.2.2.3','4.2.2.4','4.2.2.5','4.2.2.6',
 '114.114.114.114','114.114.115.115','223.5.5.5','223.6.6.6','119.29.29.29','182.254.116.116',
 '180.76.76.76','1.2.4.8','210.2.4.8','64.6.64.6','64.6.65.6','199.85.126.10','199.85.127.10',
 '8.26.56.26','8.20.247.20','185.228.168.9','185.228.168.10','185.228.169.9','185.228.169.168',
 '94.140.14.14','94.140.15.15','156.154.70.1','156.154.71.1','77.88.8.8','77.88.8.1',
 '202.96.128.86','202.96.134.33','202.102.128.68','202.102.134.68','218.102.23.228',
 '101.226.4.6','218.30.19.40','123.125.81.6','61.134.1.4','116.228.111.118']}

def classify(ipstr):
    ip = ipaddress.ip_address(ipstr)
    if ip in PUBLIC_DNS: return '公共DNS服务器'
    if ip.version == 4:
        if ip.is_loopback: return '回环地址'
        if ip.is_link_local: return '链路本地'
        if ip.is_multicast: return '组播'
        if ip.is_reserved: return '保留地址'
        if ip in ipaddress.ip_network('100.64.0.0/10'): return 'CGNAT'
        if ip in ipaddress.ip_network('198.18.0.0/15'): return '基准测试'
        if ip.is_private: return '内网地址'
        return '公网IP'
    if ip.is_loopback: return '回环地址v6'
    if ip.is_link_local: return '链路本地v6'
    if ip.is_multicast: return '组播v6'
    if ip.is_reserved: return '保留地址v6'
    if ip.is_private: return '内网地址v6'
    return '公网IPv6'

DNSISH = re.compile(r'(^|\.)(ns\d*|dns\d*|resolver|rdns|doh|dot)(\d*)(\.|$)', re.I)
def ptr_dnsish(ip):
    names = ptr.get(ip, ['<no-ptr>'])
    return [n for n in names if n != '<no-ptr>' and DNSISH.search(n)]

def tstr(ts):
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')

def esc(s): return str(s).replace('|','\|').replace('\n',' ')

L = []
L.append('# intel.yaml 规则数据分析报告\n')
L.append('> 生成时间: %s | 数据文件: docs/intel.yaml | 规则总数: %d\n' % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M'), len(items)))
L.append('> 解析环境: 系统解析器 10.255.255.254 (WSL内网DNS) 与公共DNS 223.5.5.5 (阿里) 对比\n')

# ---- 1 总览 ----
L.append('## 1. 规则总览\n')
L.append('| 维度 | 分布 |')
L.append('|---|---|')
for t in ['domain','url','ip']:
    n = sum(1 for i in items if i['type']==t)
    L.append('| 类型 %s | %d 条 |' % (t, n))
cat = collections.Counter(i['category'] for i in items)
L.append('| 类别 | ' + ' / '.join('%s=%d' % (k,v) for k,v in cat.most_common()) + ' |')
sev = collections.Counter(i['severity'] for i in items)
L.append('| 严重度 | ' + ' / '.join('%s=%d' % (k,v) for k,v in sev.most_common()) + ' |')
src = collections.Counter(i['source'] for i in items)
L.append('| 来源 | ' + ' / '.join('%s=%d' % (k,v) for k,v in src.most_common()) + ' |')
tlp = collections.Counter()
for i in items:
    m = re.search(r'TLP\s*[:：]\s*(\w+)', i.get('description',''))
    tlp[m.group(1) if m else '(none)'] += 1
L.append('| TLP | ' + ' / '.join('%s=%d' % (k,v) for k,v in tlp.most_common()) + ' |')
L.append('| enabled | %d 条全部为 true |' % sum(1 for i in items if i.get('enabled') is True))
ra = collections.Counter(i.get('recommended_action') for i in items)
L.append('| 处置建议 | ' + ' / '.join('%s=%d' % (k,v) for k,v in ra.most_common()) + ' |')
cr = [i['created_at'] for i in items]; ur = [i['updated_at'] for i in items]
L.append('| 创建时间范围 | %s ~ %s |' % (tstr(min(cr)), tstr(max(cr))))
L.append('| 更新时间范围 | %s ~ %s |' % (tstr(min(ur)), tstr(max(ur))))
# dup ids / dup values
ids = [i['id'] for i in items]
L.append('| 重复 id | %d 个 |' % (len(ids)-len(set(ids))))
vc = collections.Counter(i['value'] for i in items)
L.append('| 重复 value | %d 个 |' % sum(1 for v in vc.values() if v>1))
L.append('')

# ---- 2 域名解析概况 ----
doms = [i for i in items if i['type']=='domain']
L.append('## 2. 域名解析概况 (157 条 domain 规则)\n')
n_ok = n_nx = n_err = 0
sys_cls = collections.Counter(); pub_cls = collections.Counter()
rows = []
anomalies = []
for it in doms:
    h = it['value'].strip()
    s = sysres.get(h, {})
    p = pubres.get(h, {})
    sips = (s.get('ipv4') or []) + (s.get('ipv6') or [])
    pips = (p.get('pub_ipv4') or []) + (p.get('pub_ipv6') or [])
    scls = [classify(x) for x in sips]
    pcls = [classify(x) for x in pips]
    for c in scls: sys_cls[c]+=1
    for c in pcls: pub_cls[c]+=1
    if sips: n_ok += 1
    else:
        if s.get('errorCode') == 'ENOTFOUND': n_nx += 1
        else: n_err += 1
    status = []
    if not sips: status.append('系统DNS无解析(%s)' % s.get('errorCode','?'))
    if not pips: status.append('公共DNS无解析(%s)' % p.get('pub_err','?'))
    if sips and pips:
        if set(sips) == set(pips): status.append('内外一致')
        else: status.append('内外不一致')
    for x in scls:
        if x not in ('公网IP','公网IPv6'): anomalies.append((h, '系统DNS解析为'+x, ','.join(sips), it['category'], it['severity']))
    for x in pcls:
        if x not in ('公网IP','公网IPv6'): anomalies.append((h, '公共DNS解析为'+x, ','.join(pips), it['category'], it['severity']))
    rows.append((h, it['category'], ','.join(sips) or '-', s.get('errorCode') or '-', ','.join(pips) or '-', p.get('pub_err') or '-', ','.join(p.get('ns') or []) or '-', ' / '.join(status)))
L.append('- 系统DNS: %d 个可解析, %d 个 NXDOMAIN, %d 个其他错误 | 公共DNS: %d 个可解析, %d 个无解析\n' % (n_ok, n_nx, n_err, sum(1 for r in rows if r[4] != '-'), sum(1 for r in rows if r[4] == '-')))
L.append('- 系统DNS解析结果类型分布: %s' % ' / '.join('%s=%d' % (k,v) for k,v in sys_cls.most_common()))
L.append('- 公共DNS解析结果类型分布: %s' % ' / '.join('%s=%d' % (k,v) for k,v in pub_cls.most_common()))
L.append('')

# ---- 3 异常域名 ----
L.append('## 3. 异常域名(解析到公共DNS服务器 / 内网及特殊地址)\n')
if anomalies:
    L.append('| # | 域名 | 异常 | 解析IP | 类别 | 严重度 |')
    L.append('|---|---|---|---|---|---|')
    for n,(h,a,ips,c,s) in enumerate(sorted(set(anomalies)),1):
        L.append('| %d | %s | %s | %s | %s | %s |' % (n, h, a, ips, c, s))
else:
    L.append('无。')
# ptr dnsish flags
L.append('')
L.append('### 3.1 PTR 反向解析提示 DNS 服务的公网IP(疑似公共DNS被域名引用)\n')
found = []
for h in sorted(set(r[0] for r in rows)):
    pass
ptrflags = collections.defaultdict(list)
for r in rows:
    for ip in r[2].split(','):
        if ip and ip not in ('-',) and ':' not in ip:
            d = ptr_dnsish(ip)
            if d: ptrflags[r[0]].append((ip, d))
    for ip in r[4].split(','):
        if ip and ip not in ('-',) and ':' not in ip:
            d = ptr_dnsish(ip)
            if d: ptrflags[r[0]].append((ip, d))
if ptrflags:
    L.append('| 域名 | IP | PTR |')
    L.append('|---|---|---|')
    for h, lst in sorted(ptrflags.items()):
        for ip, names in lst:
            L.append('| %s | %s | %s |' % (h, ip, ', '.join(names)))
else:
    L.append('无。')
L.append('')

# ---- 4 内外解析不一致 ----
L.append('## 4. 系统DNS 与 公共DNS 解析不一致的域名\n')
diff = [r for r in rows if r[2] not in ('-',) and r[4] not in ('-',) and set(r[2].split(',')) != set(r[4].split(','))]
if diff:
    L.append('| 域名 | 系统DNS | 公共DNS | 类别 |')
    L.append('|---|---|---|---|')
    for r in sorted(diff):
        L.append('| %s | %s | %s | %s |' % (r[0], r[2], r[4], r[1]))
else:
    L.append('无。')
L.append('')

# ---- 5 无解析域名 ----
L.append('## 5. 无法解析的域名 (系统DNS)\n')
dead = [r for r in rows if r[2] == '-']
L.append('| 域名 | 系统错误 | 公共DNS | 类别 |')
L.append('|---|---|---|---|')
for r in sorted(dead):
    L.append('| %s | %s | %s | %s |' % (r[0], r[3], r[4], r[1]))
L.append('')

# ---- 6 全部域名明细 ----
L.append('## 6. 全部域名解析明细 (157 条)\n')
L.append('| # | 域名 | 类别 | 系统DNS解析 | 系统错误 | 公共DNS解析 | 公共错误 | NS | 状态 |')
L.append('|---|---|---|---|---|---|---|---|---|')
for n, r in enumerate(sorted(rows), 1):
    L.append('| %d | %s | %s | %s | %s | %s | %s | %s | %s |' % (n, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]))
L.append('')

# ---- 7 IP 规则 ----
L.append('## 7. IP 类型规则 (102 条)\n')
ipc = collections.Counter()
iprows = []
for it in [i for i in items if i['type']=='ip']:
    c = classify(it['value'])
    ipc[c]+=1
    iprows.append((it['value'], c, it['category'], it['severity']))
L.append('类型分布: ' + ' / '.join('%s=%d' % (k,v) for k,v in ipc.most_common()))
L.append('')
L.append('| # | IP | 类型 | 类别 | 严重度 |')
L.append('|---|---|---|---|---|')
for n,(v,c,cat,s) in enumerate(sorted(iprows),1):
    L.append('| %d | %s | %s | %s | %s |' % (n, v, c, cat, s))
L.append('')

# ---- 8 URL 规则 ----
L.append('## 8. URL 类型规则 (104 条)\n')
urls = [i for i in items if i['type']=='url']
uhost = collections.Counter()
for u in urls:
    try: uh = u['value'].split('/')[2]
    except Exception: uh = '-'
    uhost[uh]+=1
L.append('| 主机 | 规则数 | 解析状态 |')
L.append('|---|---|---|')
for uh, n in sorted(uhost.items(), key=lambda x:-x[1]):
    s = sysres.get(uh)
    st = ','.join((s or {}).get('ipv4',[]) or ['未解析']) if s else '-'
    L.append('| %s | %d | %s |' % (uh, n, st))
L.append('')

# ---- 9 威胁标签 ----
L.append('## 9. 威胁标签 TOP20\n')
tl = collections.Counter()
for it in items:
    for lab in (it.get('evidence',{}) or {}).get('threat_labels',[]) or []:
        tl[lab]+=1
L.append('| 标签 | 数量 |')
L.append('|---|---|')
for k,v in tl.most_common(20):
    L.append('| %s | %d |' % (k, v))
L.append('')

# ---- 10 NS 供应商 ----
L.append('## 10. 域名 NS 服务商分布 (权威DNS)\n')
nsc = collections.Counter()
for r in rows:
    if r[6] != '-':
        for ns in r[6].split(','):
            nsc[ns.strip().lower()]+=1
L.append('| NS | 域名数 |')
L.append('|---|---|')
for k,v in nsc.most_common():
    L.append('| %s | %d |' % (k, v))

open('docs/intel-analysis-report.md','w',encoding='utf-8').write('\n'.join(L))
print('report written, lines:', len(L))
print('anomalies:', len(set(anomalies)))
print('diff:', len(diff))
print('dead:', len(dead))
print('ptrflags:', dict(ptrflags))
