import hashlib,json,os,subprocess,time
from pathlib import Path
root=Path('/srv/owrt-archive/dnsmasq-work/private/device-tools-887976f8')
inputs=json.loads((root/'build-inputs.json').read_text());out=root/'bin';out.mkdir()
tc=Path('/srv/owrt-archive/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl');cc=tc/'bin/aarch64-openwrt-linux-musl-gcc';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
report={'status':'building','scope':inputs['scope'],'input_sha256':sha(root/'build-inputs.json'),'compiler_sha256':sha(cc),'artifacts':{}}
for name,item in inputs['tool_sources'].items():
 source=root/item['source'];assert sha(source)==item['source_sha256']
 target=out/name;command=[str(cc),*inputs['flags'],str(source),'-o',str(target)]
 with (root/(name+'.stdout')).open('wb') as stdout,(root/(name+'.stderr')).open('wb') as stderr:
  result=subprocess.run(command,stdout=stdout,stderr=stderr,env=dict(os.environ,STAGING_DIR=str(tc)),timeout=60)
 record={'command':command,'returncode':result.returncode,'source_sha256':sha(source),'stderr_sha256':sha(root/(name+'.stderr'))}
 report['artifacts'][name]=record
 (root/'build-result.json').write_text(json.dumps(report,indent=2)+'\n')
 assert result.returncode==0,name
 record.update(bytes=target.stat().st_size,sha256=sha(target))
 if 'expected_historical_artifact' in item:
  record['matches_historical']= {'bytes':record['bytes'],'sha256':record['sha256']}==item['expected_historical_artifact']
 (root/'build-result.json').write_text(json.dumps(report,indent=2)+'\n')
report['status']='built-support-only';report['programs_executed']=False
(root/'build-result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'built':len(report['artifacts']),'historical_matches':sum(v.get('matches_historical',False) for v in report['artifacts'].values()),'artifacts':{k:{f:v[f] for f in ('bytes','sha256')} for k,v in report['artifacts'].items()}},indent=2))
