from pathlib import Path
import hashlib,json,os,pwd,shutil,tarfile
base=Path('/home/ubuntu/odhcpd-image-v030-20261018')
out=base/'guard-checks'
result=json.loads((out/'result.json').read_text());assert result['passed']
archive=base/'guard-evidence.tar.gz'
paths=[out/n for n in ('inputs.json','progress.json','result.json','guard/result.json','handoff/identity.json','handoff/result.json','handoff/normal/result.json','handoff/delayed-service-stop/result.json')]
paths+=sorted((out/'logs').iterdir())
paths+=sorted((out/'guard').glob('*.log'))
paths+=[p for p in (out/'handoff').rglob('*.log') if '/root/' not in str(p)]
with tarfile.open(archive,'x:gz') as t:
 for p in paths:
  assert p.is_file(),p;t.add(p,arcname=str(p.relative_to(out)))
 t.add(base/'qualify_guard.py',arcname='qualify_guard.py')
user=pwd.getpwnam('ubuntu')
for p in [archive,out/'result.json',out/'deploy-prepared/trial-config.tar.gz',out/'deploy-prepared/trial-config.tar.json']:
 os.chown(p,user.pw_uid,user.pw_gid);os.chmod(p,0o600)
os.chown(out,user.pw_uid,user.pw_gid);os.chmod(out,0o700)
os.chown(out/'deploy-prepared',user.pw_uid,user.pw_gid);os.chmod(out/'deploy-prepared',0o700)
receipt={'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'archive_bytes':archive.stat().st_size,'archive_files':len(paths)+1,'qualification_result_sha256':hashlib.sha256((out/'result.json').read_bytes()).hexdigest(),'trial_config_sha256':result['prepared_archive_sha256'],'trial_metadata_sha256':result['prepared_metadata_sha256']}
p=base/'guard-export-receipt.json';p.write_text(json.dumps(receipt,indent=2)+'\n');os.chown(p,user.pw_uid,user.pw_gid);os.chmod(p,0o600)
print(json.dumps(receipt,indent=2))
