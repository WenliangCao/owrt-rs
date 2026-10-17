import hashlib,json,shutil,sys
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');INPUTS=ROOT/'private/correctness-inputs'
old=INPUTS/'image-runner';new=INPUTS/'image-runner-v022-root';assert not new.exists();new.mkdir()
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
sys.path.insert(0,str(ROOT/'source-8adcdeaf/tools/dnsmasq'))
from dns_udp_refusal_diff import TARGET_FILES,verify_reference
for name,digest in TARGET_FILES.items():
 assert sha(old/name)==digest;target=new/name;target.parent.mkdir(exist_ok=True,parents=True);shutil.copy2(old/name,target);assert sha(target)==digest
runner=new/'dnsmasq-image-runner';runner.write_text(f'#!/bin/sh\nexec {new}/lib/libc.so --library-path {new}/lib {new}/usr/sbin/dnsmasq "$@"\n');runner.chmod(0o755)
identity=json.loads((old/'image-identity.json').read_text());identity['runner_sha256']=sha(runner)
(new/'image-identity.json').write_text(json.dumps(identity,indent=2)+'\n');reference=verify_reference(runner,new/'image-identity.json')
base=json.loads((INPUTS/'family-base-identity.json').read_text());base['bindings']['ubus_image_runner']=str(runner);base['bindings']['ubus_image_identity']=str(new/'image-identity.json');base['ubus_helpers']['reference']=reference
out=INPUTS/'family-base-v022-root.json';assert not out.exists();out.write_text(json.dumps(base,indent=2)+'\n')
proof={'reason':'preserved original wrapper points at retired old root; new wrapper uses verified five exact image files at new root','original_wrapper_sha256':sha(old/'dnsmasq-image-runner'),'original_identity_sha256':sha(old/'image-identity.json'),'new_wrapper_sha256':sha(runner),'new_identity_sha256':sha(new/'image-identity.json'),'original_base_sha256':sha(INPUTS/'family-base-identity.json'),'new_base_sha256':sha(out),'target_file_hashes':TARGET_FILES}
(new/'root-relocation.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof,indent=2))
