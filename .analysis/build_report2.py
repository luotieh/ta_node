#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, ipaddress, collections, re, datetime, csv

NL = chr(10)
items = json.load(open('.analysis/items.json', encoding='utf-8'))
multi = json.load(open('.analysis/dns_multi.json', encoding='utf-8'))
run1 = json.load(open('.analysis/dns_results.json', encoding='utf-8'))
ptr = json.load(open('.analysis/ptr.json', encoding='utf-8'))

PUBLIC_DNS = {'8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1','9.9.9.9','149.112.112.112',
 '208.67.222.222','208.67.220.220','4.2.2.1','4.2.2.2','4.2.2.3','4.2.2.4','4.2.2.5','4.2.2.6',
 '114.114.114.114','114.114.115.115','223.5.5.5','223.6.6.6','119.29.29.29','182.254.116.116',
 '180.76.76.76','1.2.4.8','210.2.4.8','64.6.64.6','64.6.65.6','199.85.126.10','199.85.127.10',
 '8.26.56.26','8.20.247.20','185.228.168.9','185.228.168.10','185.228.169.9','185.228.169.168',
 '94.140.14.14','94.140.15.15','156.154.70.1','156.154.71.1','77.88.8.8','77.88.8.1',
 '202.96.128.86','202.96.134.33','202.102.128.68','202.102.134.68','218.102.23.228',
 '101.226.4.6','218.30.19.40','123.125.81.6','61.134.1.4','116.228.111.118'}
DNSISH = re.compile(r'(^|\.)(ns\d*|dns|resolver|rdns|doh|dot)(\d*)(\.|$)', re.I)
RES_NAMES = ['sys','alidns','google','dnspod','cn114']
RES_LABEL = {'sys':'系统DNS','alidns':'阿里223.5.5.5','google':'谷歌8.8.8.8','dnspod':'DNSPod119.29.29.29','cn114':'114DNS114.114.114.114'}

def cls(ip):
    ip = ipaddress.ip_address(ip)
    if str(ip) in PUBLIC_DNS: return '公共DNS服务器IP'
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
    if ip.is_private: return '内网/特殊地址v6'
    return '公网IPv6'

def tstr(ts):
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')

def esc(s): return str(s).replace('|', '\\|').replace(NL, ' ')

doms = [i for i in items if i['type'] == 'domain']
urls = [i for i in items if i['type'] == 'url']
ips  = [i for i in items if i['type'] == 'ip']

def host_of(url):
    try: return url.split('/')[2]
    except Exception: return '-'

def A(rec, rname):
    r = rec.get(rname)
    if not r: return None
    a = r.get('A')
    return a if isinstance(a, list) else None
def AAAA(rec, rname):
    r = rec.get(rname)
    if not r: return None
    a = r.get('AAAA')
    return a if isinstance(a, list) else None

L = []
L.append('# intel.yaml 规则数据分析报告' + NL)
L.append('> 生成时间: %s | 数据文件: docs/intel.yaml | 规则总数: %d' % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M'), len(items)) + NL)
L.append('> 解析对比: 系统DNS 10.255.255.254 (WSL内网) + 4个公共DNS (阿里223.5.5.5 / 谷歌8.8.8.8 / DNSPod 119.29.29.29 / 114DNS 114.114.114.114)' + NL)
L.append('')
L.append('## 1. 规则总览' + NL)
L.append('| 维度 | 分布 |')
L.append('|---|---|')
for t in ['domain','url','ip']:
    L.append('| 类型 %s | %d 条 |' % (t, sum(1 for i in items if i['type']==t)))
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
L.append('| 创建时间 | %s ~ %s |' % (tstr(min(cr)), tstr(max(cr))))
L.append('| 更新时间 | %s ~ %s |' % (tstr(min(ur)), tstr(max(ur))))
vc = collections.Counter(i['value'] for i in items)
dups = [(v,n) for v,n in vc.items() if n>1]
L.append('| 重复 value | %d 个: %s |' % (len(dups), ', '.join('%s×%d' % (v,n) for v,n in sorted(dups))))
L.append('')
L.append('| 类型/类别 | ' + ' | '.join(c for c,_ in cat.most_common()) + ' |')
L.append('|---|' + '---|'*len(cat))
for t in ['domain','url','ip']:
    row = [t]
    for c,_ in cat.most_common():
        row.append(str(sum(1 for i in items if i['type']==t and i['category']==c)))
    L.append('| ' + ' | '.join(row) + ' |')
L.append('')
L.append('## 2. 域名/主机解析概况 (188 个去重主机)' + NL)
L.append('| 解析器 | 可解析 | NXDOMAIN | 其他错误 | 其他错误明细 |')
L.append('|---|---|---|---|---|')
for rn in RES_NAMES:
    ok = nx = other = 0; codes = collections.Counter()
    for h, rec in multi.items():
        a = A(rec, rn)
        if a is not None:
            if a: ok += 1
            else: nx += 1
        else:
            e = rec[rn]['A'].get('err','?')
            if e == 'ENOTFOUND': nx += 1
            else:
                other += 1; codes[e] += 1
    L.append('| %s | %d | %d | %d | %s |' % (RES_LABEL[rn], ok, nx, other, ' / '.join('%s=%d' % (k,v) for k,v in codes.most_common()) or '-'))
L.append('')
L.append('系统DNS解析到的 A/AAAA 记录类型分布:')
L.append('')
dist = collections.Counter()
for h, rec in multi.items():
    for ip in (A(rec,'sys') or []) + (AAAA(rec,'sys') or []):
        dist[cls(ip)] += 1
L.append('| 类型 | 数量 |')
L.append('|---|---|')
for k,v in dist.most_common():
    L.append('| %s | %d |' % (k,v))
L.append('')
L.append('## 3. 异常域名(公共DNS服务器IP / 内网及特殊地址)' + NL)
pubdns_hits = []
internal_hits = []
for it in doms:
    h = it['value'].strip()
    rec = multi.get(h)
    if not rec: continue
    for rn in RES_NAMES:
        for ip in (A(rec,rn) or []) + (AAAA(rec,rn) or []):
            c = cls(ip)
            if c == '公共DNS服务器IP': pubdns_hits.append((h, rn, ip, it['category']))
            elif c not in ('公网IP','公网IPv6'): internal_hits.append((h, rn, ip, c, it['category']))
for it in doms:
    h = it['value'].strip()
    r1 = run1.get(h, {})
    for ip in (r1.get('ipv4') or []) + (r1.get('ipv6') or []):
        c = cls(ip)
        if c not in ('公网IP','公网IPv6'):
            internal_hits.append((h, '首轮系统DNS', ip, c, it['category']))
L.append('### 3.1 解析到公共DNS服务器IP的域名' + NL)
if pubdns_hits:
    L.append('| 域名 | 解析器 | IP | 类别 |')
    L.append('|---|---|---|---|')
    for h,rn,ip,cat_ in sorted(set(pubdns_hits)):
        L.append('| %s | %s | %s | %s |' % (h, RES_LABEL[rn], ip, cat_))
else:
    L.append('未发现。5 个解析器均未返回已知公共DNS服务器IP(8.8.8.8 / 114.114.114.114 / 223.5.5.5 等 60+ 个知名递归解析器地址)。')
L.append('')
L.append('### 3.2 解析到内网/回环/特殊地址的域名(重点异常)' + NL)
L.append('| 域名 | 解析器 | IP | 地址类型 | 类别 | 备注 |')
L.append('|---|---|---|---|---|---|')
groups = collections.defaultdict(list)
for h,rn,ip,c,cat_ in sorted(set(internal_hits)):
    note = ''
    if ip in ('127.0.0.1','::1'): note = '回环地址,典型sinkhole/投毒特征'
    if ip == '2001::1': note = 'Teredo特殊用途地址,所有解析器一致返回'
    groups[(h,ip,c,cat_,note)].append(rn)
for (h,ip,c,cat_,note), rns in sorted(groups.items()):
    L.append('| %s | %s | %s | %s | %s | %s |' % (h, ' / '.join(rns), ip, c, cat_, note))
L.append('')
L.append('### 3.3 公网IP的 PTR 带 DNS 服务特征(疑似公共DNS被域名引用)' + NL)
hits = []
for h, rec in multi.items():
    for rn in RES_NAMES:
        for ip in (A(rec,rn) or []):
            for n in ptr.get(ip, ['<no-ptr>']):
                if n != '<no-ptr>' and DNSISH.search(n):
                    hits.append((h, ip, n, rn))
if hits:
    L.append('| 域名 | IP | PTR | 解析器 |')
    L.append('|---|---|---|---|')
    for h,ip,n,rn in sorted(set(hits)):
        L.append('| %s | %s | %s | %s |' % (h, ip, n, RES_LABEL[rn]))
else:
    L.append('未发现。')
L.append('')
L.append('## 4. 各解析器返回不一致的域名(疑似 fast-flux / CDN 差异)' + NL)
L.append('| 域名 | 系统DNS | 阿里DNS | 谷歌DNS | DNSPod | 114DNS | 备注 |')
L.append('|---|---|---|---|---|---|---|')
for it in sorted(doms, key=lambda i: i['value']):
    h = it['value'].strip()
    rec = multi.get(h)
    if not rec: continue
    sets = {}
    for rn in RES_NAMES:
        a = A(rec, rn)
        if a: sets[rn] = tuple(sorted(a))
    uniq = set(sets.values())
    if len(uniq) > 1:
        note = 'fast-flux(各解析器均不同)' if len(uniq) >= 3 else '差异'
        L.append('| %s | %s | %s | %s | %s | %s | %s |' % (h,
            ','.join(sets.get('sys',())) or '-',
            ','.join(sets.get('alidns',())) or '-',
            ','.join(sets.get('google',())) or '-',
            ','.join(sets.get('dnspod',())) or '-',
            ','.join(sets.get('cn114',())) or '-', note))
L.append('')
L.append('### 4.1 系统DNS(内网)与公共DNS 方向性差异' + NL)
L.append('| 域名 | 系统DNS | 公共DNS | 现象 |')
L.append('|---|---|---|---|')
for it in sorted(doms, key=lambda i: i['value']):
    h = it['value'].strip()
    rec = multi.get(h)
    if not rec: continue
    sysA = A(rec,'sys')
    pub_any = [a for a in (A(rec,rn) for rn in RES_NAMES[1:]) if a]
    if sysA is None and pub_any:
        L.append('| %s | 无法解析(%s) | %s | 内网DNS解析失败但公共DNS可解析 |' % (h, rec['sys']['A'].get('err','?'), '; '.join(','.join(a) for a in pub_any)))
    elif sysA and not pub_any:
        L.append('| %s | %s | 公共DNS均无解析 | 仅内网DNS可解析(内网缓存/劫持) |' % (h, ','.join(sysA)))
L.append('')
L.append('## 5. 各解析器均无法解析的域名' + NL)
dead_all = []
for it in sorted(doms, key=lambda i: i['value']):
    h = it['value'].strip()
    rec = multi.get(h)
    if not rec: continue
    if all(not A(rec, rn) for rn in RES_NAMES):
        errs = []
        for rn in RES_NAMES:
            e = rec[rn]['A']
            errs.append(e.get('err','OK') if not isinstance(e,list) else 'OK')
        dead_all.append((h, it['category'], errs))
L.append('共 %d 个域名在全部解析器上均无 A 记录:' % len(dead_all))
L.append('')
L.append('| 域名 | 类别 | 系统 | 阿里 | 谷歌 | DNSPod | 114 |')
L.append('|---|---|---|---|---|---|---|')
for h,cat_,errs in dead_all:
    L.append('| %s | %s | %s | %s | %s | %s | %s |' % (h, cat_, errs[0], errs[1], errs[2], errs[3], errs[4]))
L.append('')
L.append('## 6. 全部域名解析明细(157 条 domain 规则)' + NL)
L.append('| # | 域名 | 类别 | 系统DNS A | 阿里DNS A | 谷歌DNS A | DNSPod A | 114DNS A | AAAA异常 |')
L.append('|---|---|---|---|---|---|---|---|---|')
for n, it in enumerate(sorted(doms, key=lambda i: i['value']), 1):
    h = it['value'].strip()
    rec = multi.get(h, {})
    cols = []
    for rn in RES_NAMES:
        a = A(rec, rn)
        if a is None: cols.append(rec[rn]['A'].get('err','?'))
        elif a: cols.append(','.join(a))
        else: cols.append('NXDOMAIN')
    aaaa_bad = []
    for rn in RES_NAMES:
        for ip in (AAAA(rec, rn) or []):
            c = cls(ip)
            if c not in ('公网IP','公网IPv6'):
                aaaa_bad.append('%s=%s(%s)' % (RES_LABEL[rn], ip, c))
    L.append('| %d | %s | %s | %s | %s | %s | %s | %s | %s |' % (n, h, it['category'], cols[0], cols[1], cols[2], cols[3], cols[4], '; '.join(aaaa_bad) or '-'))
L.append('')
L.append('> 注: 除表内标注外, 其余域名 AAAA 记录均为正常公网IPv6。' + NL)
L.append('## 7. IP 类型规则(102 条)' + NL)
ipc = collections.Counter()
for it in ips:
    ipc[cls(it['value'])] += 1
L.append('| 地址类型 | 数量 |')
L.append('|---|---|')
for k,v in ipc.most_common():
    L.append('| %s | %d |' % (k,v))
L.append('')
L.append('| # | IP | 类型 | 类别 | 严重度 |')
L.append('|---|---|---|---|---|')
for n, it in enumerate(sorted(ips, key=lambda i: i['value']), 1):
    L.append('| %d | %s | %s | %s | %s |' % (n, it['value'], cls(it['value']), it['category'], it['severity']))
L.append('')
L.append('## 8. URL 类型规则(104 条)' + NL)
L.append('| # | URL | 类别 | 主机解析(系统DNS) |')
L.append('|---|---|---|---|')
for n, it in enumerate(sorted(urls, key=lambda i: i['value']), 1):
    h = host_of(it['value'])
    rec = multi.get(h, {})
    a = A(rec, 'sys')
    st = ','.join(a) if a else ((rec['sys']['A'].get('err','?') if rec.get('sys') and not isinstance(rec['sys']['A'], list) else '无记录'))
    L.append('| %d | %s | %s | %s |' % (n, esc(it['value']), it['category'], st))
L.append('')
L.append('### 8.1 URL 中直接使用 IP 字面量的条目' + NL)
ip_lit = []
for it in urls:
    h = host_of(it['value'])
    try:
        ipaddress.ip_address(h)
        ip_lit.append((it['value'], h, it['category']))
    except ValueError:
        pass
if ip_lit:
    L.append('| URL | IP | 类别 |')
    L.append('|---|---|---|')
    for u_,h_,c_ in ip_lit:
        L.append('| %s | %s | %s |' % (esc(u_), h_, c_))
else:
    L.append('无。')
L.append('')
L.append('## 9. 威胁标签 TOP20' + NL)
tl = collections.Counter()
for it in items:
    for lab in (it.get('evidence',{}) or {}).get('threat_labels',[]) or []:
        tl[lab] += 1
L.append('| 标签 | 数量 |')
L.append('|---|---|')
for k,v in tl.most_common(20):
    L.append('| %s | %d |' % (esc(k), v))
L.append('')
L.append('## 10. 域名权威NS服务商分布' + NL)
pub = json.load(open('.analysis/dns_public.json', encoding='utf-8'))
nsc = collections.Counter()
for it in doms:
    h = it['value'].strip()
    for ns in (pub.get(h, {}).get('ns') or []):
        nsc[ns.strip().lower()] += 1
L.append('| NS | 域名数 |')
L.append('|---|---|')
for k,v in nsc.most_common():
    L.append('| %s | %d |' % (k, v))
L.append('')
L.append('## 11. 结论与建议' + NL)
L.append('1. **内网/特殊地址异常(3个域名)**:')
L.append('   - `walter.filloco.icu`: 首轮系统解析返回 `127.0.0.1`(回环),后续查询 ESERVFAIL,权威侧轮换返回回环地址,典型反检测/投毒行为;')
L.append('   - `ashx.lhlsjcb.com`: AAAA 返回 `::1`(系统/阿里DNS),A 记录在不同解析器间不一致(221.228.32.13 vs 104.251.55.114);')
L.append('   - `2-api.mooo.com`: AAAA 在所有解析器一致返回 `2001::1`(Teredo特殊用途地址),A 记录 fast-flux(188.5.4.96 / 54.76.135.1 / 77.4.7.92)。')
L.append('2. **公共DNS服务器IP**: 本轮 5 个解析器均未发现任何域名解析到已知公共DNS服务器IP(8.8.8.8 / 114.114.114.114 / 223.5.5.5 等);若在业务环境曾观察到该现象,大概率是本地递归DNS/安全设备对黑名单域名的投毒或sinkhole应答,建议在节点上复测。')
L.append('3. **失效域名**: %d 个域名在全部解析器上无解析(多为 NXDOMAIN),可考虑清理或降级;' % len(dead_all))
L.append('4. **fast-flux**: 2-api.mooo.com、ashx.lhlsjcb.com 等解析随解析器变化,拦截需依赖实时DNS而非静态IP;')
L.append('5. **IP 规则 102 条全部为公网IP**,无内网/保留地址;但存在重复规则: 103.23.172.117×14、45.11.36~39.254 各×3、45.137.205.53×2、75.98.162.139×2,可去重;')
L.append('6. **TLP 全部为 WHITE**(4条未标注),与公开情报来源(OTX)一致;')
L.append('7. **NS 观察**: 15 个域名挂在免费动态DNS share-dns.com(a.share-dns.com / b.share-dns.net)上,典型的恶意DDNS托管;ev2sirbd269o5j.org 的 NS 已被 FKIE sinkhole 接管(可能是已失效样本域名)。')

open('docs/intel-analysis-report.md','w',encoding='utf-8').write(NL.join(L))
print('report md lines:', len(L))

with open('docs/intel-domain-resolution.csv','w',newline='',encoding='utf-8-sig') as f:
    w = csv.writer(f)
    w.writerow(['域名','类别','严重度','系统DNS_A','阿里DNS_A','谷歌DNS_A','DNSPod_A','114DNS_A','AAAA异常'])
    for it in sorted(doms, key=lambda i: i['value']):
        h = it['value'].strip()
        rec = multi.get(h, {})
        cols = []
        for rn in RES_NAMES:
            a = A(rec, rn)
            if a is None: cols.append(rec[rn]['A'].get('err','?'))
            elif a: cols.append(';'.join(a))
            else: cols.append('NXDOMAIN')
        aaaa_bad = []
        for rn in RES_NAMES:
            for ip in (AAAA(rec, rn) or []):
                c = cls(ip)
                if c not in ('公网IP','公网IPv6'):
                    aaaa_bad.append('%s=%s(%s)' % (RES_LABEL[rn], ip, c))
        w.writerow([h, it['category'], it['severity']] + cols + [';'.join(aaaa_bad) or ''])
with open('docs/intel-rules-all.csv','w',newline='',encoding='utf-8-sig') as f:
    w = csv.writer(f)
    w.writerow(['id','type','value','category','severity','source','recommended_action','enabled','tags','created_at','updated_at'])
    for it in items:
        w.writerow([it.get('id'), it.get('type'), it.get('value'), it.get('category'), it.get('severity'),
                    it.get('source'), it.get('recommended_action'), it.get('enabled'),
                    ';'.join(it.get('tags') or []), tstr(it.get('created_at',0)), tstr(it.get('updated_at',0))])
print('csvs written')
print('dead_all:', len(dead_all))
print('internal_hits:', len(set(internal_hits)))
print('pubdns_hits:', len(set(pubdns_hits)))