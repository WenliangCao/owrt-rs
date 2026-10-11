from pathlib import Path
import json,hashlib,subprocess
ROOT=Path('/home/ubuntu/dnsmasq-audit-fix2-20261011')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
record={'source_commit':'6d001a77f06a0cf0111537507827f5399cb49a14','main_commit':'be531cee49e366bb5044443d473944dbea45b87e','variants':{},'image':{},'host':subprocess.check_output(['uname','-a'],text=True).strip()}
for k,d in [('fix','source'),('main','main-source')]:
 s=ROOT/d
 files={str(p.relative_to(s)):sha(p) for folder in ['components/dnsmasq','components/ubus','packaging/openwrt/owrt-dnsmasq'] for p in sorted((s/folder).rglob('*')) if p.is_file() and 'target' not in p.parts}
 record['variants'][k]={'source':str(s),'files':files,'files_digest':hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()}
p=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files/usr/sbin/dnsmasq')
record['image']={'path':str(p),'sha256':sha(p),'bytes':p.stat().st_size}
(ROOT/'private/identity.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({'source_commit':record['source_commit'],'main_commit':record['main_commit'],'source_files':{k:len(v['files']) for k,v in record['variants'].items()},'image':record['image']}))
