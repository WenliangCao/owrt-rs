#!/usr/bin/env python3
"""Fresh runtime permissions and host-record startup/resource observations."""
import hashlib,json,subprocess,time
from pathlib import Path
R=Path('/home/ubuntu/dnsmasq-audit-fix3-20261013'); S=R/'source-fix'; I=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
P=R/'private/build-runtime-sequence.json'; report={'commands':[],'complete':False}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save():P.write_text(json.dumps(report,indent=2)+'\n')
def run(name,argv):
 row={'name':name,'argv':list(map(str,argv)),'started':time.time()}; report['commands'].append(row);save()
 log=R/'private'/f'{name}.driver.log'
 with log.open('wb') as f: proc=subprocess.run(row['argv'],stdout=f,stderr=f,timeout=600)
 row.update(exit=proc.returncode,seconds=time.time()-row['started'],log_sha256=sha(log));save();assert proc.returncode==0,row
start=time.monotonic()
while not json.loads((R/'private/build-sequence.json').read_text()).get('complete'):
 assert time.monotonic()-start<1200,'build sequence did not complete'
 time.sleep(2)
iso=['sudo','-n','sh',S/'tools/dnsmasq/run_isolated.sh','python3']
for side in ('main','fix'):
 argv=iso+[R/'build_protections_probe.py',S,R/f'private/release-{side}/dnsmasq-rs',R/f'private/relro-release-{side}','--image-root',I]
 if side=='fix':argv+=['--require-relro']
 run('relro-release-'+side,argv)
run('relro-sdk-fix',iso+[R/'build_protections_probe.py',S,R/'private/sdk-acquire-fix/payload/usr/sbin/dnsmasq',R/'private/relro-sdk-fix','--image-root',I,'--require-relro'])
run('startup-resources',iso+[R/'startup_resources.py','--source',S,'--image-root',I,'--rust',R/'private/release-fix/dnsmasq-rs','--main',R/'private/release-main/dnsmasq-rs','--out',R/'private/startup-resources','--source-commit','e3a37f55b2939ee2a0c229b0ac96a2a9c407b8aa'])
report['complete']=True;save()
