import hashlib,json,os,signal,socket,struct,subprocess,time
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');BASE=ROOT/'private/proc-free-8adcdeaf';OUT=BASE/'comm-observation';OUT.mkdir(exist_ok=True)
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
build=json.loads((BASE/'native/native-daemon-build.json').read_text())
rows=[];sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
for side,binary in [('k-fork',ROOT/'private/baseline-k/dnsmasq-rs'),('new-fexecve',Path(build['binary']))]:
 out=OUT/side;out.mkdir()
 script=out/'hook.sh';script.write_text('#!/bin/sh\necho "$1" >> '+str(out/'events')+'\nif [ "$1" = init ]; then echo "0 02:00:00:00:00:07 127.0.0.17 seeded *"; fi\n');script.chmod(0o755)
 config=out/'config';config.write_text('no-hosts\nno-resolv\nuser=root\ngroup=root\nlisten-address=127.0.0.1\nport=15453\nhost-record=comm.test,192.0.2.17\ndhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,10m\nleasefile-ro\ndhcp-script='+str(script)+'\npid-file='+str(out/'daemon.pid')+'\n')
 with (out/'stderr').open('wb') as log:
  process=subprocess.Popen([str(binary),'-k','-C',str(config)],stdout=log,stderr=log)
  try:
   packet=struct.pack('!6H',0x1234,0x100,1,0,0,0)+b'\x04comm\x04test\0\0\x01\0\x01';deadline=time.monotonic()+5
   while True:
    assert process.poll() is None,(side,process.returncode)
    try:
     with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
      client.settimeout(.1);client.sendto(packet,('127.0.0.1',15453));reply,_=client.recvfrom(4096)
     assert reply.endswith(bytes([192,0,2,17]))
     if (out/'events').exists() and 'old' in (out/'events').read_text().splitlines():break
    except (OSError,AssertionError):pass
    assert time.monotonic()<deadline,(side,'readiness')
    time.sleep(.01)
   children=(Path('/proc')/str(process.pid)/'task'/str(process.pid)/'children').read_text().split();assert len(children)==1,(side,children)
   values={}
   for label,pid in [('owner',process.pid),('helper',int(children[0]))]:
    proc=Path('/proc')/str(pid);status=(proc/'status').read_text();(out/(label+'.status')).write_text(status)
    values[label]={'pid':pid,'comm':(proc/'comm').read_text().strip(),'exe_sha256':sha(proc/'exe'),'sigign':next(line.split()[1] for line in status.splitlines() if line.startswith('SigIgn:'))}
    assert values[label]['exe_sha256']==sha(binary)
   rows.append({'side':side,'binary':str(binary),'binary_sha256':sha(binary),**values})
   process.send_signal(signal.SIGTERM);assert process.wait(5)==0
  finally:
   if process.poll() is None:process.kill();process.wait()
result={'scope':'actual kernel comm of parent-spawned helper; native new daemon vs accepted K, proc-present and no SDK/jail qualification','new_source_commit':build['source_commit'],'observations':rows}
(OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
