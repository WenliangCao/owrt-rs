"""Freeze and execute the original R5 27-startup reproduction after builds."""
from pathlib import Path
import hashlib,json,os,subprocess,time
ROOT=Path('/home/ubuntu/dnsmasq-fix2-repair-20261011');SOURCE=ROOT/'source-qualified'
OUT=ROOT/'private/startup-resources-qualified'
MAIN=Path('/home/ubuntu/dnsmasq-audit-fix2-20261011/private/main-release/dnsmasq-rs')
ELF=ROOT/'private/release-qualified/dnsmasq-rs'
IMAGE=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
source=json.loads((ROOT/'private/source-qualified-identity.json').read_text())
assert sha(MAIN)=='0846cb40b702bc863386441b8c52daf7c0675f023fa7cbb33e471210f3d5918e'
script=SOURCE/'docs/dnsmasq/audits/20261011/fix2/build/startup_resources.py'
argv=['sudo','-n','sh',str(SOURCE/'tools/dnsmasq/run_isolated.sh'),'python3',str(script),
 '--source',str(SOURCE),'--source-commit',source['source_commit'],'--image-root',str(IMAGE),
 '--main',str(MAIN),'--rust',str(ELF),'--out',str(OUT),'--require-main-level']
record=dict(argv=argv,source_commit=source['source_commit'],tool_sha256=sha(script),
 main_sha256=sha(MAIN),release_sha256=sha(ELF),started=time.time(),passed=False)
receipt=ROOT/'private/startup-resources-qualified-command.json'
assert not receipt.exists();receipt.write_text(json.dumps(record,indent=2)+'\n')
with (ROOT/'private/startup-resources-qualified.log').open('wb') as log:
 record['returncode']=subprocess.run(argv,stdout=log,stderr=log).returncode
result=json.loads((OUT/'result.json').read_text())
record.update(result_sha256=sha(OUT/'result.json'),ended=time.time(),passed=record['returncode']==0 and result['passed'],main_level=result.get('main_level'))
receipt.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))
raise SystemExit(0 if record['passed'] else 1)
