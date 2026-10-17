import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent
REPO = 'WenliangCao/owrt-control-plane-rs'
RUN = 39045487550
COMMIT = '02cb0b2f4a1b805dca623e727168e19a6269c0ea'
SOURCE = 'a97edbc1382fc92b83110ed0822284aafeee7461'
DIGEST = 'c47f95e99a966ec6433f37e0a7d36a8d8a7e9b360f63de6e905e0993e1bfc671'

def write(path, obj):
    path.write_text(json.dumps(obj, indent=2) + '\n')

def api(path, output):
    value = subprocess.check_output(['gh', 'api', path])
    output.write_bytes(value)
    return json.loads(value)

def identity(path):
    return {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size}

run = api(f'repos/{REPO}/actions/runs/{RUN}', ROOT / 'api/run.json')
artifacts = api(f'repos/{REPO}/actions/runs/{RUN}/artifacts', ROOT / 'api/artifacts.json')
with (ROOT / 'run.log').open('wb') as log:
    subprocess.run(['gh', 'run', 'view', str(RUN), '--repo', REPO, '--log'], stdout=log, check=True)
assert run['head_sha'] == COMMIT
assert len(artifacts['artifacts']) == 1, 'expected original artifact even on failure'
artifact = artifacts['artifacts'][0]
archive = ROOT / 'artifact.zip'
with archive.open('xb') as stream:
    subprocess.run(['gh', 'api', f"repos/{REPO}/actions/artifacts/{artifact['id']}/zip"], stdout=stream, check=True)
write(ROOT / 'download-receipt.json', {'run': RUN, 'commit': COMMIT, 'conclusion': run['conclusion'],
                                     'artifact': artifact, 'zip': identity(archive)})
directory = ROOT / 'artifact'
directory.mkdir()
with zipfile.ZipFile(archive) as stream:
    stream.extractall(directory)
assert run['conclusion'] == 'success', 'CI failed; original logs/ZIP/artifacts preserved'
manifest_file = directory / 'manifest.json'
manifest = json.loads(manifest_file.read_text())
assert manifest['status'] == 'built-instrumented-training-only'
assert manifest['pgo_stage'] == 'generate'
assert manifest['artifact_purpose'] == 'instrumented-training-only'
assert manifest['release_qualified'] is False
assert manifest['source_commit'] == SOURCE and manifest['source_digest'] == DIGEST
assert len(manifest['source_files']) == 193
assert manifest['compiler_warnings']['strict_compiler_warnings_zero'] is True
assert manifest['warnings']['strict_compiler_warnings_zero'] is True
assert manifest['pgo']['profile_diagnostics'] == []
assert manifest['pgo']['mode'] == 'generate'
assert manifest['pgo']['invocation']['mode'] == 'generate'
assert manifest['budget'] == {'elf_max_bytes': 6000000, 'apk_max_bytes': 3500000}
assert manifest['final_release_budget'] == {'elf_max_bytes': 2500000, 'apk_max_bytes': 1400000}
elf = directory / 'dnsmasq-rs'
elf_id = identity(elf)
assert elf_id == {'sha256': manifest['elf']['sha256'], 'bytes': manifest['elf']['size']}
assert elf_id['bytes'] <= 6000000
package = directory / manifest['artifact']['name']
assert identity(package) == {'sha256': manifest['artifact']['sha256'], 'bytes': manifest['artifact']['size']}
assert package.stat().st_size <= 3500000
mapping = directory / 'pgo-compilation/link.map'
assert identity(mapping) == {key: manifest['link_map'][key] for key in ('sha256', 'bytes')}
for name, expected in manifest['pgo']['compilation_evidence'].items():
    assert identity(directory / 'pgo-compilation' / name) == expected
assert 'host: x86_64-unknown-linux-gnu' in manifest['toolchain']['rustc']
assert 'rustc 1.98.1' in manifest['toolchain']['rustc']
result = {'run': RUN, 'passed': True, 'source_commit': SOURCE, 'source_digest': DIGEST, 'source_files': 193,
          'manifest': identity(manifest_file), 'elf': elf_id, 'apk': identity(package), 'link_map': identity(mapping),
          'compiler_warnings_zero': True, 'profile_diagnostics': []}
write(ROOT / 'verification.json', result)
print(json.dumps(result, indent=2))
