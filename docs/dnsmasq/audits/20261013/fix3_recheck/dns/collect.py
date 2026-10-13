#!/usr/bin/env python3
"""Read-only local derivation; raw packet TTLs are never normalized."""
import argparse,copy,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
def sha(b):return hashlib.sha256(b).hexdigest()
def digest(o):return sha(json.dumps(o,sort_keys=True,separators=(',',':')).encode())
def read(f):return json.loads((a.raw/f).read_text())
def artifact(f,remote):
 b=(a.raw/f).read_bytes();return {'path':remote,'sha256':sha(b),'bytes':len(b)}
root='/home/ubuntu/dnsmasq-fix3-recheck-20261013/private/'
n=read('n1.json');out={'source_commit':'74c6b453','baseline_main':'be531cee','previous_audit_product':'e3a37f55','n1':{'identities':n['identities'],'raw':artifact('n1.json',root+'dns-n1/result.json'),'runs':[]},'boundaries':{'raw':[],'profiles':[],'case_count':0,'new_vs_pre':[],'current_vs_C_differences':[],'current_vs_main_differences':[]},'limits':[
 'Boundary route-local profile intentionally recorded as a sequential stream, not nine independent HUP-clear reconstructions. Cache mutation makes two representative C/Rust routing differences visible; no claim of closing the prior nine C TCP routing differences.',
 'First boundary driver stopped in the new observer when exact C emitted a zero-length TCP frame at the 65536-byte response. Its first 90 completed cases and old script remain intact. A defensive short-frame decoder plus optional profile selection then ran the remaining 34 cases in a new directory. No product code changed.',
 'Time-specific expiry/stale/max-ttl and live HUP during upstream waits were reviewed statically, not executed in these new runs. Cached TTLs observed here remain 120; local TTLs 37.',
]}
for r in n['runs']:
 c,f=r['sides']['c'],r['sides']['fix'];checks={'response_exact':c['response']==f['response'],'upstream_count':len(c['upstream'])==len(f['upstream']),'healthy':all(x['alive'] and x['exit']==0 for x in [c,f])}
 if r['warmth']!='cold':checks['warm_exact']=c['warm_response']==f['warm_response'];checks['warm_upstream_count']=len(c['warm_upstream'])==len(f['warm_upstream'])
 out['n1']['runs'].append({'name':r['name'],'checks':checks,'main_rcode':r['sides']['main']['response']['header'][1]&15,'C_rcode':c['response']['header'][1]&15,'current_rcode':f['response']['header'][1]&15})
assert len(out['n1']['runs'])==72 and all(all(x['checks'].values()) for x in out['n1']['runs'])
out['n1']['passed']=True;out['n1']['representative_evidence']=[r for r in n['runs'] if r['repeat']==1 and not r['debug'] and r['qtype']==6]

def concise_side(v):
 d=copy.deepcopy(v['decoded'])
 for r in d.get('records',[]):
  if isinstance(r['rdata'],str) and len(r['rdata'])>512:r['rdata']={'hex_characters':len(r['rdata']),'sha256':sha(bytes.fromhex(r['rdata']))}
 response=v['response'];wire=bytes.fromhex(response.get('hex',''))
 return {'decoded':d,'decoded_sha256':digest(v['decoded']),'wire_bytes':len(wire),'wire_sha256':sha(wire),'wire':response.get('hex') if len(wire)<512 else None,'upstream_count':len(v['upstream'])}
for local,remote in [('boundaries.json','dns-boundaries'),('boundaries-tail.json','dns-boundaries-tail')]:
 d=read(local);out['boundaries']['raw'].append({'result':artifact(local,root+remote+'/result.json'),'identities':d['identities']})
 for profile in d['profiles']:
  entry={'name':profile['name'],'processes':profile['processes'],'cases':[]}
  for label,case in profile['cases'].items():
   out['boundaries']['case_count']+=1;row={'name':label,'query':case['query'],'sides':{s:concise_side(case[s]) for s in ['c','main','pre','fix']}}
   for other,field in [('pre','new_vs_pre'),('c','current_vs_C_differences'),('main','current_vs_main_differences')]:
    equal=case['fix']['decoded']==case[other]['decoded'] and len(case['fix']['upstream'])==len(case[other]['upstream'])
    if not equal:out['boundaries'][field].append({'profile':profile['name'],'case':label})
   entry['cases'].append(row)
  out['boundaries']['profiles'].append(entry)
assert out['boundaries']['case_count']==124
assert out['boundaries']['new_vs_pre']==[{'profile':'known-ordinary','case':'known.test-tcp'}]
a.out.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'N1':out['n1']['passed'],'boundary_cases':out['boundaries']['case_count'],'new_vs_pre':out['boundaries']['new_vs_pre'],'current_C_diffs':out['boundaries']['current_vs_C_differences']}))
