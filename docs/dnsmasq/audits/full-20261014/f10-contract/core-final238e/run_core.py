import json,subprocess,hashlib
from pathlib import Path
base=Path('/dev/shm/full-f10-product-20261014/private')
tools=base/'source-238e/tools/dnsmasq'
old=Path('/dev/shm/full-integrated-fix-20261014/private/tools')
elf=base/'release-238e/dnsmasq-rs'
sha='2692c760be3719b15f4bcadb6c5a1445a9f37993a11c1369619550218e4c76eb'
assert hashlib.sha256(elf.read_bytes()).hexdigest()==sha
image='/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files'
cases=[('core-238e-tcp-hup',old/'full_tcp_hosts_cgroup.py',['--budget-mib','64','--hup']),('core-238e-tcp-snapshot',old/'full_tcp_hosts_snapshot.py',[]),('core-238e-held-hup',old/'full_r2_hosts_recovery_v2.py',['--rust-sha256',sha,'--source-commit','238e7ca4374b1889696f91816c1c239d7fe32baa','--services','shared','--initial-rows','2000','--headroom-kib','256,512,1024','--repeats','1','--held-tcp','--cache-expiry','--sides','rust'])]
for held in [False,True]:
 cases.append(('core-238e-inotify-'+('held'if held else'noheld'),old/'full_r2_hosts_recovery_v2.py',['--rust-sha256',sha,'--source-commit','238e7ca4374b1889696f91816c1c239d7fe32baa','--services','shared','--initial-rows','2000','--new-rows','6000','--headroom-kib','256,512,1024,none','--repeats','1','--hostsdir','--sides','rust']+(['--held-tcp']if held else[])))
rows=[]
for label,driver,extra in cases:
 argv=['env','PYTHONPATH='+str(tools),'sh',str(tools/'run_isolated.sh'),'python3',str(driver),'--image-root',image,'--rust',str(elf),'--output',str(base/label),*extra]
 (base/(label+'.command.json')).write_text(json.dumps({'argv':argv,'driver_sha256':hashlib.sha256(driver.read_bytes()).hexdigest(),'elf_sha256':sha},indent=2)+'\n')
 with (base/(label+'.log')).open('x') as f:r=subprocess.run(argv,stdout=f,stderr=f,timeout=300)
 rows.append({'case':label,'exit':r.returncode});print(json.dumps(rows[-1]),flush=True)
(base/'core-238e-suite.json').write_text(json.dumps(rows,indent=2)+'\n')
raise SystemExit(any(r['exit']for r in rows))
