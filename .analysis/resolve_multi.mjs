import dns from 'node:dns/promises';
import fs from 'node:fs';
const items = JSON.parse(fs.readFileSync('.analysis/items.json','utf-8'));
const domains = items.filter(i=>i.type==='domain').map(i=>i.value.trim());
const urlHosts = items.filter(i=>i.type==='url').map(i=>{ try { return new URL(i.value).hostname; } catch { return i.value.trim(); } });
const hosts = [...new Set([...domains, ...urlHosts])];
const RESOLVERS = { sys: null, alidns: '223.5.5.5', google: '8.8.8.8', dnspod: '119.29.29.29', cn114: '114.114.114.114' };
const out = {}; let idx = 0; const CONC = 25;
async function q(host, srv, type){
  const r = new dns.Resolver({ timeout: 3000, tries: 1 });
  if (srv) r.setServers([srv]);
  try {
    if (type === 'A') return [...new Set(await r.resolve4(host))];
    if (type === 'AAAA') return [...new Set(await r.resolve6(host))];
    return [...new Set(await r.resolve(host, 'CNAME'))];
  } catch (e) { return { err: e.code || e.message }; }
}
async function worker(){
  while (true) {
    const i = idx++; if (i >= hosts.length) return;
    const h = hosts[i];
    const rec = { host: h };
    for (const [name, srv] of Object.entries(RESOLVERS)) {
      const a = await q(h, srv, 'A');
      const aaaa = await q(h, srv, 'AAAA');
      const cname = await q(h, srv, 'CNAME');
      rec[name] = { A: a, AAAA: aaaa, CNAME: cname };
    }
    out[h] = rec;
    process.stdout.write('.');
  }
}
const t0 = Date.now();
await Promise.all(Array.from({length: CONC}, worker));
console.log('\ndone in', ((Date.now()-t0)/1000).toFixed(1)+'s');
fs.writeFileSync('.analysis/dns_multi.json', JSON.stringify(out));
