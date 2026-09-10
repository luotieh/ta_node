import dns from 'node:dns/promises';
import fs from 'node:fs';

const hosts = [...new Set(JSON.parse(fs.readFileSync('.analysis/items.json','utf-8'))
  .filter(i=>i.type==='domain').map(i=>i.value.trim())
  .concat(JSON.parse(fs.readFileSync('.analysis/items.json','utf-8'))
  .filter(i=>i.type==='url').map(i=>{ try { return new URL(i.value).hostname; } catch { return i.value.trim(); } })))];

// probe public resolvers
for (const srv of ['223.5.5.5','8.8.8.8','119.29.29.29','114.114.114.114']) {
  const r = new dns.Resolver(); r.setServers([srv]);
  try { const t0=Date.now(); await r.resolve4('www.baidu.com', {timeout: 2500}); console.log(srv, 'REACHABLE', Date.now()-t0+'ms'); }
  catch(e){ console.log(srv, 'UNREACHABLE', e.code||e.message); }
}

const PUB = process.env.PUB || '223.5.5.5';
const out = {};
const CONC = 30;
let idx = 0;
async function worker() {
  while (true) {
    const i = idx++; if (i >= hosts.length) return;
    const h = hosts[i];
    const pub = new dns.Resolver(); pub.setServers([PUB]);
    const rec = { host: h, pub_ipv4: [], pub_ipv6: [], pub_err: null, ns: [], ns_err: null };
    try { rec.pub_ipv4 = [...new Set(await pub.resolve4(h))]; } catch(e){ rec.pub_err = e.code || e.message; }
    try { const aaaa = await pub.resolve6(h); rec.pub_ipv6 = [...new Set(aaaa)]; } catch(e){ if(!rec.pub_err) rec.pub_err = e.code||e.message; }
    const sys = new dns.Resolver();
    try { rec.ns = (await sys.resolveNs(h)).sort(); } catch(e){ rec.ns_err = e.code||e.message; }
    out[h] = rec;
    process.stdout.write('.');
  }
}
await Promise.all(Array.from({length: CONC}, worker));
console.log('\ndone via', PUB);
fs.writeFileSync('.analysis/dns_public.json', JSON.stringify(out));
