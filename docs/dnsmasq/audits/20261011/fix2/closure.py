from pathlib import Path
import json,hashlib,os,fcntl
ROOT=Path('/home/ubuntu/dnsmasq-audit-fix2-20261011')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text())
identity=read(ROOT/'private/identity.json');checks={}
for variant,item in identity['variants'].items():
 checks[variant]=all(sha(Path(item['source'])/name)==digest for name,digest in item['files'].items())
plan=read(ROOT/'private/performance/plan.json');checks['performance_assets']=all(sha(name)==digest for name,digest in plan['assets'].items())
summary=read(ROOT/'private/performance/summary.json');checks['performance_raw_inputs']=all(sha(ROOT/'private/performance'/row['id']/name)==digest for row in summary['windows'] for name,digest in row['raw_files'].items())
checks['post_checks']=read(ROOT/'private/post-checks/result.json')['passed']
checks['startup_resources']=read(ROOT/'private/startup-resources-01/result.json')['passed']
checks['sdk_elf_identity']=sha(ROOT/'private/sdk-verify/payload/usr/sbin/dnsmasq')=='0dcaf03b88f9e035a20c9d92d3a46830fa552c6833d1e6bd2e6a288e6c955bd7'
checks['image']=sha(identity['image']['path'])==identity['image']['sha256']
ancestors=set();pid=os.getpid()
while pid>0:
 ancestors.add(pid)
 try:pid=int(Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[1])
 except OSError:break
processes=[]
for p in Path('/proc').iterdir():
 if not p.name.isdigit() or int(p.name) in ancestors:continue
 try:
  argv=(p/'cmdline').read_bytes().split(b'\0')
  if any(str(ROOT).encode() in arg for arg in argv):processes.append(dict(pid=int(p.name),argv=[arg.decode(errors='replace') for arg in argv if arg]))
 except OSError:pass
checks['no_task_processes']=not processes
with Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as lock:
 try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);checks['build_lock_available']=True
 except BlockingIOError:checks['build_lock_available']=False
result=dict(checks=checks,passed=all(checks.values()),remaining_task_processes=processes,source_commit=identity['source_commit'],main_commit=identity['main_commit'],performance_summary_sha256=sha(ROOT/'private/performance/summary.json'),performance_plan_sha256=sha(ROOT/'private/performance/plan.json'))
(ROOT/'private/closure.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));assert result['passed']
