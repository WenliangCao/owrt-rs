import json,subprocess,hashlib
from pathlib import Path
base=Path('/dev/shm/full-inotify-fix-20261014/private')
tools=base/'source/tools/dnsmasq'
oldtools=Path('/dev/shm/full-integrated-fix-20261014/private/tools')
elf=base/'release-final/dnsmasq-rs'
sha='edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d'
assert hashlib.sha256(elf.read_bytes()).hexdigest()==sha
image='/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files'
cases=[('core-tcp-hup',oldtools/'full_tcp_hosts_cgroup.py',['--budget-mib','64','--hup']),('core-tcp-snapshot',oldtools/'full_tcp_hosts_snapshot.py',[]),('core-held-hup-cache',oldtools/'full_r2_hosts_recovery_v2.py',['--rust-sha256',sha,'--source-commit','340ed73e83e58ba845e0a645eb21e9ead0d0f108','--services','shared','--initial-rows','2000','--headroom-kib','256,512,1024','--repeats','1','--held-tcp','--cache-expiry'])]
results=[]
for label,driver,extra in cases:
 argv=['env','PYTHONPATH='+str(tools),'sh',str(tools/'run_isolated.sh'),'python3',str(driver),'--image-root',image,'--rust',str(elf),'--output',str(base/label),*extra]
 receipt={'argv':argv,'elf_sha256':sha,'driver_sha256':hashlib.sha256(driver.read_bytes()).hexdigest()}
 (base/(label+'.command.json')).write_text(json.dumps(receipt,indent=2)+'\n')
 with (base/(label+'.log')).open('x') as f:r=subprocess.run(argv,stdout=f,stderr=f,timeout=300)
 results.append({'case':label,'exit':r.returncode});print(json.dumps(results[-1]),flush=True)
(base/'core-suite.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(any(r['exit'] for r in results))
