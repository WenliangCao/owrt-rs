import hashlib,json,os,signal,socket,struct,subprocess,time
from pathlib import Path
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
ROOT=Path('/srv/owrt-archive/dnsmasq-work')
OUT=ROOT/'private/final-b8617f57/sdk-smoke/startup'
OUT.mkdir()
BINARY=OUT.parent/'dnsmasq-rs'
assert hashlib.sha256(BINARY.read_bytes()).hexdigest()=='c30fad397d582fd544d7af31e8e70f1408f18bb6c29e143bcd5abc12ed309eaa'
script=OUT/'script.sh'
script.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> '+str(OUT/'script-events')+'\nif [ "$1" = init ]; then printf "0 02:00:00:00:00:07 127.0.0.17 seeded *\\n"; fi\n')
script.chmod(0o755)
pidfile=OUT/'dnsmasq.pid'
config=OUT/'dnsmasq.conf'
config.write_text('no-resolv\nno-hosts\nuser=root\ngroup=root\nlisten-address=127.0.0.1\nport=15453\nhost-record=smoke.test,192.0.2.17\nserver=localhost#9\ndhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,10m\nleasefile-ro\ndhcp-script='+str(script)+'\npid-file='+str(pidfile)+'\n')
report={'status':'running','checks':[],'binary_sha256':hashlib.sha256(BINARY.read_bytes()).hexdigest(),'netns':os.readlink('/proc/self/ns/net'),'mntns':os.readlink('/proc/self/ns/mnt'),'pidns':os.readlink('/proc/self/ns/pid')}
def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')

def query():
 packet=struct.pack('!6H',0x4567,0x100,1,0,0,0)+b'\x05smoke\x04test\0\0\x01\0\x01'
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
  client.settimeout(.1);client.sendto(packet,('127.0.0.1',15453));reply,_=client.recvfrom(4096)
  assert struct.unpack('!6H',reply[:12])[:4]==(0x4567,0x8580,1,1),reply.hex()
  assert reply.endswith(bytes([192,0,2,17]))

def ready(process=None):
 deadline=time.monotonic()+5
 while True:
  if process is not None:assert process.poll() is None,'daemon exited before ready'
  try:query();return
  except (OSError,AssertionError):
   if time.monotonic()>=deadline:raise
   time.sleep(.02)

process=None;daemon_pid=None
try:
 for name,args in [('version',['--version']),('configuration',['--test','-C',str(config)])]:
  r=subprocess.run([str(BINARY),*args],capture_output=True,timeout=5)
  (OUT/(name+'.stdout')).write_bytes(r.stdout);(OUT/(name+'.stderr')).write_bytes(r.stderr)
  assert r.returncode==0,(name,r.returncode,r.stderr)
  report['checks'].append(name);save()
 with (OUT/'foreground.log').open('wb') as log:
  process=subprocess.Popen([str(BINARY),'-k','-C',str(config)],stdout=log,stderr=log)
  ready(process)
  assert 'init' in (OUT/'script-events').read_text().splitlines()
  report['checks'].append('foreground-DNS-after-production-helper-init-and-localhost-lookup')
  process.send_signal(signal.SIGTERM);assert process.wait(5)==0;process=None
  report['checks'].append('foreground-normal-shutdown');save()
 pidfile.unlink(missing_ok=True)
 before=(OUT/'script-events').read_text().splitlines().count('init')
 with (OUT/'daemonized.log').open('wb') as log:
  result=subprocess.run([str(BINARY),'-C',str(config)],stdout=log,stderr=log,timeout=5)
  assert result.returncode==0
  daemon_pid=int(pidfile.read_text());assert daemon_pid>1
  ready()
  assert (OUT/'script-events').read_text().splitlines().count('init')==before+1
  report['checks'].append('daemonized-startup-pidfile-helper-and-DNS');save()
  os.kill(daemon_pid,signal.SIGTERM)
  deadline=time.monotonic()+5
  while True:
   pid,status=os.waitpid(daemon_pid,os.WNOHANG)
   if pid:
    assert os.waitstatus_to_exitcode(status)==0;daemon_pid=None;break
   assert time.monotonic()<deadline,'daemonized shutdown timeout'
   time.sleep(.01)
  report['checks'].append('daemonized-normal-shutdown')
 report['status']='passed'
except BaseException as error:
 report.update(status='failed',error=repr(error));raise
finally:
 if process is not None and process.poll() is None:process.kill();process.wait()
 if daemon_pid is not None:
  try:os.kill(daemon_pid,signal.SIGKILL)
  except ProcessLookupError:pass
 save()
print(json.dumps(report))
