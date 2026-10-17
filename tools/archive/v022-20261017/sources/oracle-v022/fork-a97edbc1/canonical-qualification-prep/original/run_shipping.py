import hashlib,json,os,sys
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');BASE=ROOT/'private/fork-a97edbc1';SOURCE=ROOT/'source-a97edbc1';USE=BASE/'pgo/train-stage/use';OUT=BASE/'correctness/shipping'
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1' and os.geteuid()==0
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
built=json.loads((USE/'build.json').read_text());state=json.loads((BASE/'pgo/train-stage/state.json').read_text());assert state['status']=='trained-use-built-unqualified'
elf=USE/'dnsmasq-rs';package=USE/built['artifact']['name'];assert sha(elf)==built['artifacts'][0]['sha256'] and sha(package)==built['artifact']['sha256'];assert elf.stat().st_size<=2500000 and package.stat().st_size<=1400000
assert built['source_commit']=='a97edbc1382fc92b83110ed0822284aafeee7461' and built['source_digest']=='c47f95e99a966ec6433f37e0a7d36a8d8a7e9b360f63de6e905e0993e1bfc671' and built['features']=='' and built['opt_level']=='3'
sys.path.insert(0,str(SOURCE/'tools/dnsmasq'));from audit_20261011_static_pie import observe
OUT.mkdir();value=observe(Path('/srv/owrt-archive/image-bases/d5dd3ffe9243f02d308c08eb76dd4feb1a65da6cd10612808251d2cde5eb3f6c'),elf,OUT/'actual-pgo')
assert value['elf_type']==3 and value['distinct_bases']==3 and all(r['relro_readonly'] and not r['stack_executable'] for r in value['runs'])
result={'status':'passed-existing-shipping-runtime','source_commit':built['source_commit'],'source_digest':built['source_digest'],'elf_sha256':sha(elf),'elf_bytes':elf.stat().st_size,'apk_sha256':sha(package),'apk_bytes':package.stat().st_size,'same_build_receipt_sha256':sha(USE/'build.json'),'observed':value,'strict_canonical_pgo_identity_and_warning_gate':'separate required receipt; this runtime proof does not substitute it'}
(OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'elf_bytes':result['elf_bytes'],'apk_bytes':result['apk_bytes'],'distinct_bases':value['distinct_bases'],'full_relro':True}))
