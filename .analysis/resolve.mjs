import dns from 'node:dns/promises';
import fs from 'node:fs';

const items = JSON.parse(fs.readFileSync('.analysis/items.json','utf-8'));
const domains = items.filter(i=>i.type==='domain').map(i=>i.value.trim());
const urlHosts = [];
for (const it of items.filter(i=>i.type==='url')) {
  try { urlHosts.push(new URL(it.value).hostname); } catch { urlHosts.push(it.value.trim()); }
}
const hosts = [...new Set([...domains, ...urlHosts])];
console.log('total hosts to resolve:', hosts.length);

const CONC = 40, TIMEOUT = 4000;
const results = {};
let idx = 0;
async function worker() {
  while (true) {
    const i = idx++;
    if (i >= hosts.length) return;
    const h = hosts[i];
    const rec = { host: h, ipv4: [], ipv6: [], error: null, errorCode: null };
    const r = new dns.Resolver();
    r.setTimeout ? null : null;
    const resolver = new dns.Resolver({ timeout: TIMEOUT, tries: 1 });
    try {
      const a = await resolver.resolve4(h);
      rec.ipv4 = [...new Set(a)];
    } catch (e) { rec.error = rec.error || e.message; rec.errorCode = rec.errorCode || e.code; }
    try {
      const aaaa = await resolver.resolve6(h);
      rec.ipv6 = [...new Set(aaaa)];
    } catch (e) { if (!rec.error) { rec.error = e.message; rec.errorCode = e.code; } }
    results[h] = rec;
    process.stdout.write('.');
  }
}
const t0 = Date.now();
await Promise.all(Array.from({length: CONC}, worker));
console.log('\nresolved in', ((Date.now()-t0)/1000).toFixed(1), 's');
fs.writeFileSync('.analysis/dns_results.json', JSON.stringify(results, null, 0));
console.log('saved .analysis/dns_results.json');
