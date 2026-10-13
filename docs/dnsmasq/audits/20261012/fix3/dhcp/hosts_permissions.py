#!/usr/bin/env python3
"""Record the intentional EVENT_INIT privilege boundary against main and C."""
import argparse,hashlib,json,os,signal,socket,struct,subprocess,sys,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--image',type=Path,required=True);p.add_argument('--main',type=Path,required=True);p.add_argument('--fix',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
assert 'private' in a.out.resolve().parts
sys.path.insert(0,str(a.source/'tools/dnsmasq'))
from m2_rootfs import image_elf_command,STOCK_SHA256
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
stock=a.image/'usr/sbin/dnsmasq';assert sha(stock)==STOCK_SHA256
# Set traverse on the unique synthetic fixture's tree, never any shared parent.
a.out.mkdir(parents=True,exist_ok=False);a.out.chmod(0o755)

def query():
    req=struct.pack('!6H',0x4455,0x100,1,0,0,0)+b'\x06secret\x04test\0\0\1\0\1'
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(1);s.sendto(req,('127.0.0.1',15353));raw=s.recv(4096)
    return {'rcode':raw[3]&15,'answers':int.from_bytes(raw[6:8],'big'),'wire':raw.hex()}

report={'script_sha256':sha(__file__),'rows':[]}
for permissions,debug in [(0o600,False),(0o644,False),(0o600,True)]:
    for side,binary in [('c',stock),('main',a.main),('fix',a.fix)]:
        d=a.out/f'{permissions:o}-{"debug" if debug else "foreground"}-{side}';d.mkdir(mode=0o755)
        hosts=d/'hosts';hosts.write_text('192.0.2.7 secret.test\n');hosts.chmod(permissions)
        cmd=image_elf_command(a.image,binary)+['-d' if debug else '-k','-C','/dev/null','--user=nobody','--group=nogroup','--pid-file=','--log-facility=-','--no-resolv','--no-hosts','--listen-address=127.0.0.1','--bind-interfaces','--port=15353','--addn-hosts='+str(hosts)]
        row=dict(side=side,debug=debug,mode=oct(permissions),binary_sha256=sha(binary),argv=cmd)
        with (d/'log').open('wb') as log:
            proc=subprocess.Popen(cmd,stdout=log,stderr=log,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'})
            try:
                time.sleep(.2)
                if proc.poll() is not None:raise RuntimeError((d/'log').read_text())
                row['startup']=query();proc.send_signal(signal.SIGHUP);time.sleep(.1);row['after_hup']=query()
                hosts.chmod(0o644);proc.send_signal(signal.SIGHUP);time.sleep(.1);row['permission_restored_hup']=query()
                row['uid']=[line for line in Path(f'/proc/{proc.pid}/status').read_text().splitlines() if line.startswith('Uid:')]
            finally:
                if proc.poll() is None:proc.terminate()
                proc.wait(timeout=3);row['exit']=proc.returncode
        row['log']=(d/'log').read_text();report['rows'].append(row)
(a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
