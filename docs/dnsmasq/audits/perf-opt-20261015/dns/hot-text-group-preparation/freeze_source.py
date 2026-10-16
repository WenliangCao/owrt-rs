"""Freeze exact local source bytes only; never select or execute a candidate."""
from pathlib import Path
import gzip,hashlib,importlib.util,io,json,shutil,subprocess,sys,tarfile
assert sys.version_info >= (3,11), "Frozen canonical helper requires Python3.11+ (local Python3.14 is available)."
BASE=Path.cwd();SOURCE=BASE.parent/'owrt-perf-hot-text-group-20261016'
WARM=BASE.parent/'owrt-perf-warm-address-encode-preparation-20261016'
COMMIT='c95c5571fe8915c4a67af8e438026e5f4f5d3a61'
OLD='6ab0f064b69087add3be1cb2bf5604fbaf42dffa'
OUT=BASE/'private/perf-opt-20261015/hot-text-group-preparation'
OUT.mkdir(parents=True,exist_ok=False)
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
helper=WARM/'private/perf-opt-20261015/warm-address-encode-preparation/canonical-builder/build_package.py'
assert sha(helper)=='f280b97d7ca572b8311e2cd9564ffb7e641cc1e98c0fc1ac69622bc47f819310'
spec=importlib.util.spec_from_file_location('frozen_sdk_helper',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
files=module.inputs(SOURCE);assert len(files)==179
raw=subprocess.check_output(['git','ls-tree','-rz',COMMIT]);tree={}
for row in raw.split(b'\0'):
 if not row:continue
 meta,name=row.split(b'\t');mode,kind,blob=meta.decode().split();assert kind=='blob' and mode in ['100644','100755'];tree[name.decode()]={'mode':int(mode,8)&0o777,'blob':blob}
for name,digest in files.items():
 data=(SOURCE/name).read_bytes();assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==tree[name]['blob'];assert hashlib.sha256(data).hexdigest()==digest
identity={'commit':COMMIT,'epoch':subprocess.check_output(['git','show','-s','--format=%ct',COMMIT],text=True).strip(),'git_blob_sha1':{name:tree[name]['blob'] for name in files}}
for name,value in [('source-files.json',files),('research-git-identity.json',identity)]:
 with (OUT/name).open('x') as file:file.write(json.dumps(value,indent=2)+'\n')
archive=OUT/'source-c95c5571.tar';subprocess.run(['git','-c','tar.umask=0022','archive','--format=tar','--output',str(archive),COMMIT],check=True)
with tarfile.open(archive,'a') as tar:
 data=(OUT/'research-git-identity.json').read_bytes();member=tarfile.TarInfo('research-git-identity.json');member.mode=0o644;member.mtime=int(identity['epoch']);member.size=len(data);tar.addfile(member,io.BytesIO(data))
with archive.open('rb') as source,(OUT/'source-c95c5571.tar.gz').open('xb') as destination:
 with gzip.GzipFile(fileobj=destination,mode='wb',mtime=0,compresslevel=6) as compressed:shutil.copyfileobj(source,compressed)
seen=set()
with tarfile.open(OUT/'source-c95c5571.tar.gz','r:gz') as tar:
 for member in tar.getmembers():
  if member.isdir():continue
  assert member.isfile() and member.name not in seen;seen.add(member.name);data=tar.extractfile(member).read()
  if member.name=='research-git-identity.json':assert data==(OUT/member.name).read_bytes() and member.mode==0o644
  else:
   row=tree[member.name];assert member.mode==row['mode'];assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==row['blob']
   if member.name in files:assert hashlib.sha256(data).hexdigest()==files[member.name]
assert seen==set(tree)|{'research-git-identity.json'}
old_rows=subprocess.check_output(['git','ls-tree','-rz',OLD]);old={row.split(b'\t')[1].decode():row.split(b'\t')[0].decode().split()[2] for row in old_rows.split(b'\0') if row}
changed=[name for name in files if tree[name]['blob']!=old.get(name)]
bundle=OUT/'canonical-builder';bundle.mkdir()
for name,digest in [('perf_opt_sdk_build.py','f4540b1cbfd235ab2decde1bf7a09a6326fdb6fda7fe4d906239eac55a785f33'),('build_package.py','f280b97d7ca572b8311e2cd9564ffb7e641cc1e98c0fc1ac69622bc47f819310')]:
 origin=helper.with_name(name);assert sha(origin)==digest;shutil.copy2(origin,bundle/name);assert sha(bundle/name)==digest
result={'status':'LOCAL_EXACTC95_SOURCE_ARCHIVE_RESEARCH_SELECTED_EXECUTION_DISABLED','source_commit':COMMIT,'base_source_commit':OLD,'local_source':str(SOURCE),'source_date_epoch':identity['epoch'],'source_files':files,'source_file_count':len(files),'source_manifest_sha256':sha(OUT/'source-files.json'),'git_identity_sha256':sha(OUT/'research-git-identity.json'),'SDK_input_changes_from6ab':changed,'archive':{'path':str(OUT/'source-c95c5571.tar.gz'),'bytes':(OUT/'source-c95c5571.tar.gz').stat().st_size,'sha256':sha(OUT/'source-c95c5571.tar.gz'),'Git_regular_files':len(tree),'regular_files_including_identity':len(seen),'all_Git_file_modes_and_blobs_verified':True,'SDK_source_files_verified':179},'canonical_builder_local_bundle':{name:{'sha256':sha(bundle/name),'bytes':(bundle/name).stat().st_size} for name in ['perf_opt_sdk_build.py','build_package.py']},'source_tree_builder_outside_179':{'path':'tools/dnsmasq/perf_opt_sdk_build.py','sha256':sha(SOURCE/'tools/dnsmasq/perf_opt_sdk_build.py'),'scope':'Not the frozen canonical f454 builder; do not use source-tree builder for a later selected SDK run.'},'selection_authorized':True,'execution_authorized':False,'execution_enabled':False,'selected_source':COMMIT,'actual_related':None,'actual_SDK':None,'actual_signals':None,'explicit_slot_release':None,'uploaded':False,'oracle_accessed':False,'build_or_test_run':False,'frozen_source_modified':False}
path=BASE/'docs/dnsmasq/audits/perf-opt-20261015/dns/hot-text-group-preparation/source-binding.json';path.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'path':str(path),'sha256':sha(path),'archive':result['archive'],'changed':changed}))
