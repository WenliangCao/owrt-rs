import hashlib,json,os,signal,subprocess,time
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');OUT=ROOT/'private/lookup-sigpipe-b8617f57-attempt2';OUT.mkdir(exist_ok=True)
BINARY=ROOT/'private/final-b8617f57/sdk-smoke/dnsmasq-rs'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
assert sha(BINARY)=='c30fad397d582fd544d7af31e8e70f1408f18bb6c29e143bcd5abc12ed309eaa'
report={'scope':'proc-present isolated diagnostic of actual b861 lookup dispatcher; does not qualify production no-proc jail','source_commit':'b8617f574d6d3674e35627f7beedb73a9dd655eb','binary_sha256':sha(BINARY),'restore_signals_before_exec':True,'observations':[]}
for label in ('exec-control-sleep','lookup-dispatch'):
 fds=[]
 if label=='lookup-dispatch':
  cr,cw=os.pipe2(os.O_CLOEXEC);rr,rw=os.pipe2(os.O_CLOEXEC);fds=[cr,cw,rr,rw]
  args=[str(BINARY),'--dnsmasq-internal-lookup-v1',str(cr)+':'+str(rw)];passing=(cr,rw);wanted='pipe_read'
 else:args=['/bin/sleep','30'];passing=();wanted='hrtimer_nanosleep'
 child=subprocess.Popen(args,pass_fds=passing,restore_signals=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 try:
  deadline=time.monotonic()+3
  while True:
   assert child.poll() is None,(label,child.returncode,child.stderr.read())
   proc=Path('/proc')/str(child.pid);wchan=(proc/'wchan').read_text().strip()
   if wchan==wanted or label=='lookup-dispatch' and wchan=='anon_pipe_read':break
   assert time.monotonic()<deadline,(label,wchan)
   time.sleep(.01)
  text=(proc/'status').read_text();(OUT/(label+'.status')).write_text(text)
  value=next(line.split()[1] for line in text.splitlines() if line.startswith('SigIgn:'))
  row={'label':label,'argv':args,'pid_in_namespace':child.pid,'wchan':wchan,'executable_sha256':sha(proc/'exe'),'sigign_hex':value,'sigpipe_ignored':bool(int(value,16)&(1<<(signal.SIGPIPE-1)))}
  report['observations'].append(row)
 finally:
  child.terminate();_,err=child.communicate(timeout=3);(OUT/(label+'.stderr')).write_bytes(err)
  for fd in fds:os.close(fd)
assert not report['observations'][0]['sigpipe_ignored']
assert report['observations'][1]['executable_sha256']==report['binary_sha256']
(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
