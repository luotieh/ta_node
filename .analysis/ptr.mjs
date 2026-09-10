import dns from 'node:dns/promises';
import fs from 'node:fs';
const sys = JSON.parse(fs.readFileSync('.analysis/dns_results.json','utf-8'));
const pub = JSON.parse(fs.readFileSync('.analysis/dns_public.json','utf-8'));
const ips = new Set();
for (const r of Object.values(sys)) for (const ip of [...r.ipv4, ...r.ipv6]) ips.add(ip);
for (const r of Object.values(pub)) for (const ip of [...r.pub_ipv4, ...r.pub_ipv6]) ips.add(ip);
const list=[...ips].filter(x=>!x.includes(':'));
console.log('unique ipv4 for PTR:', list.length);
const out={}; let idx=0; const CONC=30;
async function worker(){ while(true){ const i=idx++; if(i>=list.length) return; const ip=list[i];
  try { out[ip]=(await dns.reverse(ip)).sort(); } catch(e){ out[ip]=['<no-ptr>']; } process.stdout.write('.'); } }
await Promise.all(Array.from({length:CONC}, worker));
console.log('\ndone');
fs.writeFileSync('.analysis/ptr.json', JSON.stringify(out));
