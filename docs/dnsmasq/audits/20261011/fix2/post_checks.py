"""Resource and lease-write recovery checks; wait for the bounded cost screen to end."""
from pathlib import Path
import fcntl,hashlib,json,os,subprocess,sys,time
ROOT=Path('/home/ubuntu/dnsmasq-audit-fix2-20261011');SOURCE=ROOT/'source';OUT=ROOT/'private/post-checks';TOOLS=SOURCE/'tools/dnsmasq'
IMAGE=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files');ELF=ROOT/'private/release/dnsmasq-rs'
sys.path.insert(0,str(TOOLS))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,v):Path(p).write_text(json.dumps(v,indent=2)+'\n')
if len(sys.argv)>1 and sys.argv[1]=='alarm':
 assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
 from m2_rootfs import image_elf_command
 from audit_20261011_runtime_signals import run_alarm_maintenance
 out=OUT/'alarm';out.mkdir()
 rows=[run_alarm_maintenance(k,image_elf_command(IMAGE,b),b,out) for k,b in [('c',IMAGE/'usr/sbin/dnsmasq'),('fix',ELF)]]
 result=dict(rows=rows,passed=all(r['ack']==5 and r['lease_absent_before_alarm'] and r['lease_persisted_after_alarm'] and r['lease_dump_seen'] and r['daemon_alive'] and r['dns_after'] for r in rows));save(out/'result.json',result);assert result['passed'];raise SystemExit(0)
OUT.mkdir(exist_ok=False)
print('Waiting for performance lock; no load started',flush=True)
with Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 assert json.loads((ROOT/'private/performance/run.json').read_text())['status']=='complete'
 assert sha(ELF)=='47378bda5776614960c5336a024da9bf22947d82891a5cfc1310065f0634e060'
 result=dict(elf_sha256=sha(ELF),commands=[],passed=False)
 jobs=[('hosts-memory',['sudo','-n','sh',str(TOOLS/'run_isolated.sh'),'python3',str(TOOLS/'audit_20261011_hosts_memory.py'),'--image-root',str(IMAGE),'--rust',str(ELF),'--out',str(OUT/'hosts-memory')]),('alarm',['sudo','-n','sh',str(TOOLS/'run_isolated.sh'),'python3',str(Path(__file__)),'alarm'])]
 for name,argv in jobs:
  row=dict(name=name,argv=argv,started=time.time());result['commands'].append(row);save(OUT/'result.json',result);print('START',name,flush=True)
  with (OUT/(name+'.log')).open('wb') as log:proc=subprocess.run(argv,stdout=log,stderr=log,timeout=90)
  row.update(returncode=proc.returncode,elapsed_seconds=time.time()-row['started'],log_sha256=sha(OUT/(name+'.log')));save(OUT/'result.json',result)
  assert proc.returncode==0,row
  row['result_sha256']=sha(OUT/name/'result.json');print('PASS',name,flush=True)
 result['passed']=True;save(OUT/'result.json',result)
