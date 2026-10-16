#!/usr/bin/env python3
from pathlib import Path
import argparse,collections,hashlib,json,re,subprocess
parser=argparse.ArgumentParser(description='Compare bound E/PGO linker sections, without inferring CPU or merging instantiations')
parser.add_argument('baseline',type=Path);parser.add_argument('use_map',type=Path);parser.add_argument('retained',type=Path);parser.add_argument('output',type=Path);args=parser.parse_args()
paths={'E':args.baseline,'use':args.use_map}
raw=json.loads(args.retained.read_text());original=json.loads(args.baseline.with_name('build.json').read_text());build=json.loads(raw['use/build.json']['text'])
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(paths['E'])==original['link_map']['sha256'] and sha(paths['use'])==build['link_map']['sha256']
assert original['source_files']==build['source_files'] and original['sdk']==build['sdk']
def parse(path):
 body=path.read_text().split('Linker script and memory map',1)[1];lines=body.splitlines();outputs={};rows=[]
 for i,line in enumerate(lines):
  m=re.match(r'^(\.[^\s]+)\s*(.*)$',line)
  if not m:continue
  tail=m[2] or (lines[i+1].strip() if i+1<len(lines) else '')
  v=re.match(r'^(0x[0-9a-f]+)\s+(0x[0-9a-f]+)',tail)
  if v and int(v[1],16)>0:outputs[m[1]]={'address':int(v[1],16),'bytes':int(v[2],16)}
 for i,line in enumerate(lines):
  m=re.match(r'^ (\.[^\s]+)\s*(.*)$',line)
  if not m:continue
  tail=m[2] or (lines[i+1].strip() if i+1<len(lines) else '')
  v=re.match(r'^(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(.+)$',tail)
  if not v or not int(v[1],16) or not int(v[2],16):continue
  address,size=int(v[1],16),int(v[2],16)
  parent=[name for name,sec in outputs.items() if sec['address']<=address<address+size<=sec['address']+sec['bytes']]
  if not parent and not m[1].startswith(('.text','.rodata')):continue
  if len(parent)>1:
   preferred=[name for name in parent if m[1]==name or m[1].startswith(name+'.')]
   parent=[max(preferred,key=len)] if preferred else parent
  assert len(parent)==1,(m[1],address,size,parent)
  obj=v[3].split('/')[-1];row={'section':m[1],'address':address,'bytes':size,'object':obj,'output':parent[0]}
  if parent[0]=='.text':
   row['temperature']='hot' if m[1].startswith('.text.hot.') else 'unlikely' if m[1].startswith('.text.unlikely.') else 'ordinary'
   row['symbol']=re.sub(r'^\.text\.(?:hot\.|unlikely\.)?','',m[1])
   row['key']=obj+'::'+row['symbol']
  rows.append(row)
 return outputs,rows
parsed={side:parse(path) for side,path in paths.items()};a,b=[parsed[k][0] for k in paths]
print('SECTIONS')
for n in sorted(set(a)|set(b),key=lambda n:b.get(n,{}).get('bytes',0)-a.get(n,{}).get('bytes',0),reverse=True):
 d=b.get(n,{}).get('bytes',0)-a.get(n,{}).get('bytes',0)
 if d:print(n,a.get(n),b.get(n),'delta',d)
tables={};summaries={}
for side,(sections,rows) in parsed.items():
 text=[r for r in rows if r['output']=='.text'];groups=collections.defaultdict(list)
 for r in text:groups[r['key']].append(r)
 duplicates={key:len(v) for key,v in groups.items() if len(v)>1};assert not duplicates,duplicates
 ranges=sorted((r['address'],r['address']+r['bytes']) for r in text)
 assert all(left[1]<=right[0] for left,right in zip(ranges,ranges[1:])),side
 tables[side]={k:v[0] for k,v in groups.items()}
 summaries[side]={'count':len(text),'attributed_bytes':sum(r['bytes'] for r in text),'output_bytes':sections['.text']['bytes'],'thermal_bytes':{t:sum(r['bytes'] for r in text if r['temperature']==t) for t in ['hot','unlikely','ordinary']}}
 print(side,summaries[side])
show=raw['profile-show.stdout']['text'];assert hashlib.sha256(show.encode()).hexdigest()==raw['profile-show.stdout']['sha256'];profile={}
for m in re.finditer(r'^  (\S+):\n    Hash: (\S+)\n    Counters: (\d+)\n    Block counts: \[([^\]]*)\]',show,re.M):
 values=[int(i.strip()) for i in m[4].split(',') if i.strip()];assert len(values)==int(m[3]);profile[m[1]]={'hash':m[2],'max_counter':max(values,default=0),'sum_counters':sum(values)}
profile_index=collections.defaultdict(list)
for name,value in profile.items():profile_index[name.split(';',1)[-1]].append({'profile_name':name,**value})
print('PROFILE_RECORDS',len(profile),'AMBIGUOUS',sum(len(v)>1 for v in profile_index.values()))
keys=sorted(set(tables['E'])|set(tables['use']));delta=[]
for key in keys:
 old,new=tables['E'].get(key),tables['use'].get(key);symbol=(new or old)['symbol'];d=(new['bytes'] if new else 0)-(old['bytes'] if old else 0)
 candidates=profile_index.get(symbol,[])
 observed=candidates[0] if len(candidates)==1 else None
 delta.append({'key':key,'symbol':symbol,'delta':d,'E':old,'use':new,'profile':observed,'activity':'positive_counter' if observed and observed['max_counter']>0 else 'all_zero_counters' if observed else 'not_matched'})
program=subprocess.check_output(['xcrun','--find','llvm-cxxfilt'],text=True).strip();names=[r['symbol'] for r in delta];pretty=subprocess.run([program,'--no-strip-underscore'],input='\n'.join(names)+'\n',text=True,capture_output=True,check=True).stdout.splitlines();assert len(pretty)==len(names)
for r,n in zip(delta,pretty):r['name']=n
for label,values in [('GROWTH',sorted(delta,key=lambda r:r['delta'],reverse=True)[:25]),('SHRINK',sorted(delta,key=lambda r:r['delta'])[:20])]:
 print(label)
 for r in values:print(r['delta'],r['E']['bytes'] if r['E'] else 0,r['use']['bytes'] if r['use'] else 0,r['use']['temperature'] if r['use'] else '-',r['activity'],r['name'][:200])
print('MATCHES',len(set(tables['E'])&set(tables['use'])),'ONLY_E',len(set(tables['E'])-set(tables['use'])),'ONLY_USE',len(set(tables['use'])-set(tables['E'])))
for activity in ['positive_counter','all_zero_counters','not_matched']:
 rows=[r for r in delta if r['activity']==activity];print('ACTIVITY',activity,'E',sum(r['E']['bytes'] if r['E'] else 0 for r in rows),'use',sum(r['use']['bytes'] if r['use'] else 0 for r in rows),'net',sum(r['delta'] for r in rows),'growth',sum(max(0,r['delta']) for r in rows),'shrink',sum(min(0,r['delta']) for r in rows))

def union_bytes(rows):
 intervals=sorted((r['address'],r['address']+r['bytes']) for r in rows);merged=[]
 for begin,end in intervals:
  if merged and begin<=merged[-1][1]:merged[-1][1]=max(merged[-1][1],end)
  else:merged.append([begin,end])
 return sum(end-begin for begin,end in merged)
sections=[{'section':name,'E':a.get(name,{}).get('bytes',0),'use':b.get(name,{}).get('bytes',0),'delta':b.get(name,{}).get('bytes',0)-a.get(name,{}).get('bytes',0)} for name in sorted(set(a)|set(b))]
activity={}
for label in ('positive_counter','all_zero_counters','not_matched'):
 rows=[r for r in delta if r['activity']==label]
 activity[label]={'E_bytes':sum(r['E']['bytes'] if r['E'] else 0 for r in rows),'use_bytes':sum(r['use']['bytes'] if r['use'] else 0 for r in rows),'net_bytes':sum(r['delta'] for r in rows),'growth_bytes':sum(max(0,r['delta']) for r in rows),'shrink_bytes':sum(min(0,r['delta']) for r in rows)}
rodata={}
for side,(outputs,rows) in parsed.items():
 records=[r for r in rows if r['output']=='.rodata']
 rodata[side]={'output_bytes':outputs['.rodata']['bytes'],'input_declared_bytes_not_additive':sum(r['bytes'] for r in records),'input_range_union_bytes':union_bytes(records),'warning':'Merged string/input sections overlap; do not sum input declarations or pair anonymous constant ordinals as semantic identities.'}
ranked=sorted(delta,key=lambda r:(-r['delta'],r['key']))
report={'scope':'Same-link map storage comparison only; no use ELF disassembly, optimization remarks or CPU attribution','input_sha256':{'E_map':sha(paths['E']),'E_build':sha(args.baseline.with_name('build.json')),'use_map':sha(paths['use']),'retained_receipts':sha(args.retained),'analyzer':sha(Path(__file__)),'profile_show':raw['profile-show.stdout']['sha256']},'artifacts':{'E':original['artifacts'],'use':build['artifacts']},'matching':'Exact full mangled symbol plus input-object basename; only .text.hot./.text.unlikely. placement prefixes removed. No crate-hash, LLVM clone, closure, generic-argument or instantiation identifiers removed. Display demangling does not define identity.','demangler':{'path':program,'version':subprocess.check_output([program,'--version'],text=True).strip(),'sha256':sha(Path(program))},'matched_count':len(set(tables['E'])&set(tables['use'])),'only_E_count':len(set(tables['E'])-set(tables['use'])),'only_use_count':len(set(tables['use'])-set(tables['E'])),'output_sections':sections,'text_summaries':summaries,'text_attributed_delta':sum(r['delta'] for r in delta),'text_growth_bytes':sum(max(0,r['delta']) for r in delta),'text_shrink_bytes':sum(min(0,r['delta']) for r in delta),'rodata':rodata,'training_activity':activity,'profile_record_count':len(profile),'ambiguous_profile_symbol_count':sum(len(v)>1 for v in profile_index.values()),'profile_match_rule':'Exact mangled symbol after optional module-prefix semicolon; match only unique record, never combine ambiguity. Counter activity is from generate training, not timing.','largest_increases':ranked[:40],'largest_decreases':sorted(delta,key=lambda r:(r['delta'],r['key']))[:40],'full_comparisons_sha256':hashlib.sha256(json.dumps(ranked,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'file_growth_bytes':build['artifacts'][0]['bytes']-original['artifacts'][0]['bytes'],'mapped_output_section_growth_bytes':sum(r['delta'] for r in sections)}
report['file_growth_minus_mapped_section_growth']=report['file_growth_bytes']-report['mapped_output_section_growth_bytes']
assert report['text_attributed_delta']==summaries['use']['attributed_bytes']-summaries['E']['attributed_bytes']
args.output.write_text(json.dumps(report,indent=2)+'\n')

