import dns from 'node:dns/promises';
import fs from 'node:fs';
const items = JSON.parse(fs.readFileSync('.analysis/items.json','utf-8'));
const ips = [...new Set(items.filter(i=>i.type==='ip').map(i=>i.value))];
const out = {}; let idx = 0; const CONC = 30;
async function worker(){ while(true){ const i=idx++; if(i>=ips.length) return; const ip=ips[i];
  try { out[ip] = (await dns.reverse(ip)).sort(); } catch(e){ out[ip] = ['<no-ptr>']; } process.stdout.write('.'); } }
await Promise.all(Array.from({length:CONC}, worker));
console.log('\nunique ip rules:', ips.length);
fs.writeFileSync('.analysis/ptr_ips.json', JSON.stringify(out));
