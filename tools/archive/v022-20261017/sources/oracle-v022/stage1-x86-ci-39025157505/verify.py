import hashlib
import json
import re
from pathlib import Path
import struct
import sys
import importlib.util
import tarfile

spec = importlib.util.spec_from_file_location('recorded_scanner', Path(__file__).with_name('compiler_warnings-at-run.py'))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)
scan = scanner.scan

root = Path(__file__).resolve().parent
out = root / 'artifact'
manifest = json.loads((out / 'manifest.json').read_text())
source = json.loads((out / 'source-manifest.json').read_text())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert manifest['runner_commit'] == '59b437de5a425de688f293a0308b3c3b5722a0fe'
assert manifest['source_commit'] == manifest['frozen_product_commit'] == source['commit'] == '08f665502ad0ef72f3a33fcc5717ff1fea9e50f7'
assert manifest['source_digest'] == source['digest'] == '5d1c283e5603a1d943312fa92d3b9cf80cb3d29c86fcb90385eb9ff74bfbb379'
assert manifest['source_files'] == source['files'] and len(source['files']) == 183
assert sha(out / 'source.tar') == source['archive_sha256']
with tarfile.open(out / 'source.tar') as archive:
    files = {item.name: hashlib.sha256(archive.extractfile(item).read()).hexdigest() for item in archive if item.isfile()}
assert files == source['files']
assert hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest() == source['digest']
verified = {}
for name, record in manifest['retained'].items():
    path = out / name
    actual = {'bytes':path.stat().st_size,'sha256':sha(path)}
    assert actual == record, name
    verified[name] = actual
for field, name in [('elf','dnsmasq-rs'),('artifact',manifest['artifact']['name'])]:
    path = out / name
    assert path.stat().st_size == manifest[field]['size'] and sha(path) == manifest[field]['sha256']
elf = (out / 'dnsmasq-rs').read_bytes()
assert elf[:6] == b'\x7fELF\x02\x01'
elf_type, elf_machine = struct.unpack_from('<HH',elf,16)
assert elf_type == 3 and elf_machine == 183
assert manifest['elf_layout']['machine'] == 'AArch64' and manifest['elf_layout']['linkage'] == 'static-pie'
assert 'host: x86_64-unknown-linux-gnu' in manifest['toolchain']['rustc']
assert 'release: 1.98.1' in manifest['toolchain']['rustc']
assert manifest['pgo'] is False and manifest['firmware_built'] is False and manifest['physical_boot_tested'] is False
warnings = scan(sorted(out.glob('*.log')))
assert warnings == manifest['warnings'] == json.loads((out / 'warnings.json').read_text())
assert warnings['strict_compiler_warnings_zero'] is False
assert len(warnings['compiler_or_unclassified']) == 2
assert all(row['text'] == "WARNING: can't open config file: /builder/shared-workdir/build/staging_dir/host/etc/ssl/openssl.cnf" for row in warnings['compiler_or_unclassified'])
log=(out/'compile.log').read_text()
assert '-Dwarnings' in log and '-Cprofile-use' not in log and '-Cprofile-generate' not in log
assert manifest['status'] == 'failed'
assert manifest['error'] == 'Rust/Cargo or unclassified compiler warning; see warnings.json and original logs'
clean = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', log)
rust_warnings = [line for line in clean.splitlines() if re.match(r'^\s*warning(?:\[[^\]]+\])?:',line)]
assert rust_warnings == []
assert max(row['line'] for row in warnings['compiler_or_unclassified']) < next(i for i,line in enumerate(clean.splitlines(),1) if 'Compiling' in line)
result = {'status':'verified-artifacts-from-failed-warning-classification-gate','run':39025157505,'runner_commit':manifest['runner_commit'],
          'source_commit':source['commit'],'source_files':len(source['files']),'source_digest':source['digest'],
          'compiler_warning_diagnostics':len(rust_warnings), 'raw_warning_gate_status':'failed', 'raw_warning_gate_rejections':warnings['compiler_or_unclassified'],
          'sdk_metadata_diagnostics':len(warnings['sdk_metadata']),
          'rustc':manifest['toolchain']['rustc'],'target_cc':manifest['toolchain']['target_cc'],
          'elf':manifest['elf'],'artifact':manifest['artifact'],'elf_layout':manifest['elf_layout'],
          'verified_retained_files':len(verified),'verified_retained':verified,
          'pgo':False,'firmware_built':False,'physical_boot_tested':False,
          'qualification':'stage1 frozen-source target build proof only; not final candidate acceptance'}
(root/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k != 'verified_retained'},indent=2))
