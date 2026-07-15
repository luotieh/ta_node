#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
构造 N 条安全事件并推送到管理端 / 节点 ingest 接口。

事件语义：docs/ip.xlsx 中的内网 IP 访问 intel.yaml 中的恶意域名（intel 命中，
threat_source=intel_domain）。字段对齐 internal/event/event.go 的 ThreatEvent 与
docs/event-schema-1.3.md，并带管理端读取的 protocol/occurrence_time 别名。

纯标准库实现：不依赖 openpyxl / requests / PyYAML。
在部署机上直接：
    python3 scripts/gen_events.py --dry-run          # 先看要发什么
    python3 scripts/gen_events.py \
        --url http://<host>:<port>/api/internal/event/push \
        --api-key <node.api_key>

不传 --url/--api-key 时，脚本会尝试从 --config 指定的节点 yaml 里读取
node.management_url / node.api_key / node.device_id（默认 configs/ta_node.yaml）。
"""
import argparse
import json
import os
import re
import sys
import time
import uuid
import zipfile
import xml.etree.ElementTree as ET
import urllib.request
import urllib.error

MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


# ----------------------------- xlsx (IP) -----------------------------
def read_ips_from_xlsx(path, ip_col_letter="B", sheet="xl/worksheets/sheet1.xml"):
    """读取 xlsx 指定列的 IP，跳过表头，去重保序。纯 zip+xml 解析。"""
    ns = {"a": MAIN_NS}
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall("a:si", ns):
                shared.append("".join(t.text or "" for t in si.iter(f"{{{MAIN_NS}}}t")))
        if sheet not in z.namelist():
            sheet = next(n for n in z.namelist()
                         if n.startswith("xl/worksheets/") and n.endswith(".xml"))
        sh = ET.fromstring(z.read(sheet))

    def cell_val(c):
        v = c.find("a:v", ns)
        if v is None or v.text is None:
            return ""
        return shared[int(v.text)] if c.get("t") == "s" else v.text

    def col_letters(ref):
        return "".join(ch for ch in (ref or "") if ch.isalpha())

    ip_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    ips, seen = [], set()
    for row in sh.findall(".//a:row", ns):
        for c in row.findall("a:c", ns):
            if col_letters(c.get("r")) != ip_col_letter:
                continue
            val = cell_val(c).strip()
            if ip_re.match(val) and val not in seen:
                seen.add(val)
                ips.append(val)
    return ips


# --------------------------- intel.yaml (domain) ---------------------------
def read_domains_from_intel(path):
    """
    从 intel.yaml 提取 type: domain 的条目。优先用 PyYAML；没有则退回逐块解析。
    返回 dict 列表：value / id / category / severity / source / description /
    recommended_action / evidence(可空)。
    """
    try:
        import yaml  # 可选
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        out = []
        for it in (doc.get("items") or []):
            if str(it.get("type", "")).strip().lower() != "domain":
                continue
            if it.get("enabled") is False:
                continue
            out.append({
                "value": it.get("value", ""),
                "id": it.get("id", ""),
                "category": it.get("category", "malware"),
                "severity": it.get("severity", "high"),
                "source": it.get("source", "local"),
                "description": it.get("description", ""),
                "recommended_action": it.get("recommended_action", ""),
                "evidence": it.get("evidence") or None,
            })
        if out:
            return out
    except Exception:
        pass
    return _read_domains_fallback(path)


def _read_domains_fallback(path):
    """无 PyYAML 时的极简解析：按 `- id:` 切块，取 domain 类型的标量字段（不含 evidence）。"""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    blocks = re.split(r"(?m)^\s*-\s+id\s*:", text)
    out = []

    def scalar(block, key):
        m = re.search(r"(?m)^\s+%s\s*:\s*(.+?)\s*$" % re.escape(key), block)
        if not m:
            return ""
        v = m.group(1).strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        return v

    for blk in blocks[1:]:
        blk = "id:" + blk
        if scalar(blk, "type").lower() != "domain":
            continue
        out.append({
            "value": scalar(blk, "value"),
            "id": scalar(blk, "id"),
            "category": scalar(blk, "category") or "malware",
            "severity": scalar(blk, "severity") or "high",
            "source": scalar(blk, "source") or "local",
            "description": scalar(blk, "description"),
            "recommended_action": scalar(blk, "recommended_action"),
            "evidence": None,
        })
    return out


# --------------------------- node config (defaults) ---------------------------
def read_node_config(path):
    """从节点 yaml 抓 node.management_url / api_key / device_id（简单缩进解析，够用）。"""
    cfg = {}
    if not path or not os.path.exists(path):
        return cfg
    in_node = False
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if re.match(r"^\S", line):
                in_node = line.strip().startswith("node:")
                continue
            if not in_node:
                continue
            m = re.match(r"^\s+(management_url|api_key|device_id)\s*:\s*(.*)$", line)
            if m:
                v = m.group(2).strip().strip('"').strip("'")
                cfg[m.group(1)] = v
    return cfg


# ------------------------------ event build ------------------------------
CATEGORY_TO_TYPE = {
    "c2": "c2", "malware": "malware", "phishing": "phishing",
    "scanner": "scan", "webshell": "webshell", "botnet": "botnet",
}


def build_event(idx, ip, dom, device_id, sensor_version, now_ns):
    cat = (dom.get("category") or "malware").lower()
    event_type = CATEGORY_TO_TYPE.get(cat, "intel_hit")
    domain = dom["value"]
    src_port = 30000 + (idx * 7) % 20000
    ev = {
        "event_id": str(uuid.uuid4()),
        "device_id": device_id,
        "event_time": now_ns,
        "event_type": event_type,
        "event_name": domain,
        "severity": dom.get("severity") or "high",
        "model": "threat_intel",
        "src_ip": ip,
        "src_port": src_port,
        "dst_ip": "",             # 域名命中：目的 IP 未解析，置空由管理端按域名归并
        "dst_port": 443,
        "proto": "tcp",
        "direction": "outbound",
        "threat_source": "intel_domain",
        "ioc_type": "domain",
        "ioc_value": domain,
        "ioc_category": cat,
        "ioc_id": dom.get("id") or "",
        "ioc_source": dom.get("source") or "local",
        "ioc_tags": ["source:%s" % (dom.get("source") or "local")],
        "flows": 1,
        "packets": 12 + idx,
        "bytes": 1024 + idx * 128,
        "app": {
            "http_host": domain,
            "http_method": "GET",
            "http_url": "https://%s/" % domain,
            "user_agent": "Mozilla/5.0 (compatible; ta-node-sim/1.0)",
            "dns_query": domain,
        },
        "schema_version": "1.3",
        "sensor_version": sensor_version,
        # 管理端 ingest 读取的别名
        "protocol": "tcp",
        "occurrence_time": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                         time.gmtime(now_ns / 1e9)),
    }
    if dom.get("description"):
        ev["ioc_description"] = dom["description"]
    if dom.get("recommended_action"):
        ev["recommended_action"] = dom["recommended_action"]
    if dom.get("evidence"):
        ev["ioc_evidence"] = dom["evidence"]
    return ev


def push_event(url, api_key, ev, timeout):
    data = json.dumps(ev, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("X-API-Key", api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(512).decode("utf-8", "replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read(512).decode("utf-8", "replace")
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    ap = argparse.ArgumentParser(description="构造并推送 N 条 intel 命中安全事件")
    ap.add_argument("--url", default=os.environ.get("PUSH_URL", ""),
                    help="推送地址，如 http://<host>:<port>/api/internal/event/push")
    ap.add_argument("--api-key", default=os.environ.get("PUSH_API_KEY", ""),
                    help="X-API-Key（管理端设了 internal_api_key 时必填）")
    ap.add_argument("--count", type=int, default=10, help="事件条数（默认 10）")
    ap.add_argument("--ip-xlsx", default=os.path.join(root, "docs", "ip.xlsx"))
    ap.add_argument("--intel", default=os.path.join(root, "docs", "intel.yaml"))
    ap.add_argument("--config", default=os.path.join(root, "configs", "ta_node.yaml"),
                    help="从中读取 node.management_url/api_key/device_id 作默认值")
    ap.add_argument("--device-id", default="")
    ap.add_argument("--sensor-version", default="sim-1.3")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--dry-run", action="store_true", help="只打印事件，不发送")
    args = ap.parse_args()

    cfg = read_node_config(args.config)
    url = args.url or cfg.get("management_url", "")
    api_key = args.api_key or cfg.get("api_key", "")
    device_id = args.device_id or cfg.get("device_id", "") or "sim-node-001"

    ips = read_ips_from_xlsx(args.ip_xlsx)
    domains = read_domains_from_intel(args.intel)
    if not ips:
        sys.exit("未从 %s 读到 IP" % args.ip_xlsx)
    if not domains:
        sys.exit("未从 %s 读到 type=domain 的恶意域名" % args.intel)
    print("载入 %d 个内网 IP、%d 个恶意域名" % (len(ips), len(domains)), file=sys.stderr)

    if not args.dry_run and not url:
        sys.exit("缺少 --url（也未从 %s 读到 node.management_url）" % args.config)

    now_ns = int(time.time() * 1e9)
    events = [
        build_event(i, ips[i % len(ips)], domains[i % len(domains)],
                    device_id, args.sensor_version, now_ns + i * 1_000_000)
        for i in range(args.count)
    ]

    if args.dry_run:
        for ev in events:
            print(json.dumps(ev, ensure_ascii=False, indent=2))
        print("\n[dry-run] 共 %d 条，未发送。" % len(events), file=sys.stderr)
        return

    print("推送到 %s （device_id=%s, api_key=%s）"
          % (url, device_id, "已设置" if api_key else "空"), file=sys.stderr)
    ok = 0
    for i, ev in enumerate(events, 1):
        status, body = push_event(url, api_key, ev, args.timeout)
        good = status is not None and 200 <= status < 300
        ok += good
        print("[%2d/%d] %s -> %s  %s  %s" % (
            i, len(events), ev["src_ip"], ev["ioc_value"],
            "OK" if good else "FAIL", "" if good else "(%s) %s" % (status, body[:200])))
    print("\n完成：%d/%d 成功。" % (ok, len(events)), file=sys.stderr)
    sys.exit(0 if ok == len(events) else 1)


if __name__ == "__main__":
    main()
