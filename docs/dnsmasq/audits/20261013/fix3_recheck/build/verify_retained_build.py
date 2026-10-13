#!/usr/bin/env python3
"""Read-only rehash of retained SDK source-build evidence against exact HEAD inputs."""
import argparse,hashlib,importlib.util,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args();R=a.root.resolve();S=R/'source';out=R/'private/retained-build-rehash.json';assert not out.exists()
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def read(p):return json.loads(Path(p).read_text())
identity=read(R/'head-input-identity.json');summary=read(R/'types-summary.json');report={'head':identity['head'],'source_digest':identity['digest'],'controller_sha256':sha(__file__),'passed':False,'files':{},'sdk':[]}
def verify(path,expected,expected_size=None):
 path=Path(path);actual=sha(path);size=path.stat().st_size
 assert actual==expected,(str(path),actual,expected)
 if expected_size is not None:assert size==expected_size,(str(path),size,expected_size)
 report['files'][str(path)]={'sha256':actual,'bytes':size}
def receipts(value):
 if isinstance(value,dict):
  if isinstance(value.get('path'),str) and value['path'].startswith('/') and 'sha256' in value:
   verify(value['path'],value['sha256'],value.get('bytes',value.get('size')))
  for item in value.values():receipts(item)
 elif isinstance(value,list):
  for item in value:receipts(item)
try:
 assert summary['source_digest']==identity['digest'];assert summary['source_input_count']==identity['count']==177
 receipts(summary)
 spec=importlib.util.spec_from_file_location('package',S/'tools/dnsmasq/build_package.py');package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)
 for row in summary['sdk']:
  m=read(row['manifest']['path']);assert m['source_files']==identity['source_files']
  assert m['source_digest']==identity['digest'];assert m['source_build_passed'] and m['sdk_recipe_restored'] and not m['frozen_elf']
  assert m['stages']=={'prepare':{'exit_code':0},'compile':{'exit_code':0}}
  source=Path(m['argv'][m['argv'].index('--source')+1]);assert package.inputs(source)==identity['source_files']
  assert package.inputs(Path(m['fixed_source_path']))==identity['source_files']
  sdk=Path(m['sdk']['path']);current=package.sdk_inputs(sdk);assert current==m['sdk']['files']
  archive_name,expected=json.loads((source/'manifests/release-25.12.5.json').read_text())['inputs']['sdk'].split(' sha256 ');verify(sdk.parent/archive_name,expected)
  for path,expected in current.items():verify(sdk/path,expected)
  for path,expected in m.get('private_link_map_wrappers',{}).items():verify(path,expected)
  copied=Path(m['fixed_source_path'])/'packaging/openwrt/owrt-dnsmasq';active=Path(m['sdk_recipe_path'])
  report['sdk'].append({'manifest':row['manifest'],'status':m['status'],'source_commit':m['source_commit'],'inputs_match_head':True,'source_inputs_count':len(m['source_files']),'sdk_inputs_count':len(current),'sdk_input_digest':hashlib.sha256(json.dumps(current,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'source_tree':str(source),'fixed_source_tree':m['fixed_source_path'],'elf':m['elf'],'artifact':m['artifact'],'stages':m['stages'],'artifact_identity_verified':m.get('artifact_identity_verified',False),'apk_byte_identical':m.get('apk_byte_identical',False),'original_budget_passed':not bool(m.get('budget_error'))})
 oldroot=Path(summary['source_archive']['path']).parents[1]
 for kind in ('release','tests'):
  folder=oldroot/'private'/f'{kind}-types';receipt=read(folder/'build.json');assert receipt==summary[kind]
  for artifact in receipt['artifacts']:verify(folder/artifact['path'],artifact['sha256'],artifact['bytes'])
 report['sdk_payloads_identical']=len({x['elf']['sha256'] for x in report['sdk']})==1
 report['sdk_apks_identical']=len({x['artifact']['sha256'] for x in report['sdk']})==1
 assert report['sdk_payloads_identical'] and report['sdk_apks_identical'];report['passed']=True
except BaseException as error:report['error']=repr(error);raise
finally:out.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'passed':report['passed'],'files_rehashed':len(report['files']),'sdk_builds':len(report['sdk'])}))
