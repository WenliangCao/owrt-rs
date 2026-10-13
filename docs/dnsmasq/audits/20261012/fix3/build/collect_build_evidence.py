#!/usr/bin/env python3
import hashlib,json,statistics,re
from pathlib import Path
R=Path('/home/ubuntu/dnsmasq-audit-fix3-20261013');P=R/'private';O=R/'derived-build';O.mkdir(exist_ok=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
def save(name,v):(O/name).write_text(json.dumps(v,indent=2)+'\n')
summary={'scope':'Fresh main/fix release + unit tests; original SDK copied to private workspace, source compilation without frozen ELF, fixed-path repeatability, isolated runtime RELRO and startup resource measurements','release':{},'sdk':{},'unit':{},'runtime':{},'startup':[],'raw_files':{}}
for side in ('main','fix'):
 summary['release'][side]=read(P/f'release-{side}/build.json')
 for name in ('sections.txt','layout.txt'):(O/f'{side}-release-{name}').write_text((P/f'release-{side}'/name).read_text())
 summary['sdk'][side]=read(P/f'sdk-acquire-{side}/manifest.json')
 summary['unit'][side]=read(P/f'tests-{side}/build.json')
 for name in ('lib-dnsmasq_rs','bin-dnsmasq-rs'):
  path=P/f'unit-{side}-{name}.driver.log';summary['unit'][side][name]=[s for s in path.read_text().splitlines() if s.startswith('test result:')]
summary['sdk']['fix-verify']=read(P/'sdk-verify-fix/manifest.json')
for name in ('relro-release-main','relro-release-fix','relro-sdk-fix'):
 summary['runtime'][name]=read(P/name/'result.json')
 save(name+'.json',summary['runtime'][name])
startup=read(P/'startup-resources/result.json');save('startup-resources.json',startup)
for count in startup['counts']:
 row={'count':count}
 for side in ('c','main','head'):
  samples=[r for r in startup['runs'] if r['count']==count and r['variant']==side];assert len(samples)==3 and all(r['passed'] for r in samples)
  row[side]={}
  for metric in ('VmHWM_kib','VmRSS_kib','Pss_kib','VmData_kib','initial_cache_reload_log_observed_seconds','ready_cpu_seconds'):
   vals=[r[metric] for r in samples];row[side][metric]={'samples':vals,'median':statistics.median(vals)}
 summary['startup'].append(row)
summary['startup_passed']=startup['passed'];summary['startup_main_level']=startup['main_level']
summary['build_sequence']=read(P/'build-sequence.json');summary['runtime_sequence']=read(P/'build-runtime-sequence.json')
summary['package_tool_unit']=(P/'package-tool-unit.log').read_text()
# Hash only audit artifacts; never copy binaries, APK payloads, rootfs or source trees into Git.
selected=list(P.glob('*.driver.log'))+[P/'build-sequence.json',P/'build-runtime-sequence.json',P/'package-tool-unit.log']
for side in ('main','fix'):
 selected += [p for p in (P/f'release-{side}').iterdir() if p.is_file() and p.name!='dnsmasq-rs']
 selected += [p for p in (P/f'tests-{side}').iterdir() if p.is_file() and not p.name.startswith(('bin-','lib-'))]
for name in ('sdk-acquire-main','sdk-acquire-fix','sdk-verify-fix','relro-release-main','relro-release-fix','relro-sdk-fix'):
 selected += [p for p in (P/name).iterdir() if p.is_file() and (p.suffix in ('.log','.json','.maps','.readelf') or p.name=='budget.json')]
selected += [p for p in (P/'startup-resources').rglob('*') if p.is_file() and 'image' not in p.relative_to(P/'startup-resources').parts]
for p in sorted(set(selected)):
 summary['raw_files'][str(p.relative_to(R))]={'bytes':p.stat().st_size,'sha256':sha(p)}
save('summary.json',summary)
print(json.dumps({'startup':summary['startup'],'sdk':{k:{'elf':v['elf'],'apk':v['artifact'],'status':v['status']} for k,v in summary['sdk'].items()}},indent=2))
