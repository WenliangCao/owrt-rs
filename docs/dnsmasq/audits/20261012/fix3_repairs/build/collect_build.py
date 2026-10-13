#!/usr/bin/env python3
"""Derive the retained build receipt; no build or daemon is started."""
import hashlib
import json
from pathlib import Path
ROOT = Path('/home/ubuntu/dnsmasq-fix3-repair-20261013')
P = ROOT / 'private'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_text())
def receipt(path):
    path=Path(path);return dict(path=str(path),sha256=sha(path),bytes=path.stat().st_size)
identity=read(P/'source-identity.json');controller=read(P/'build-result.json')
assert controller['passed'] and controller['ordinary_units']['failed']==0
sdk=[]
for name in ('sdk-acquire','sdk-verify'):
    path=P/name/'manifest.json';m=read(path)
    assert m['source_build_passed'] and m['sdk_inputs_unchanged'] and m['source_inputs_unchanged'] and m['sdk_recipe_restored']
    assert not m['frozen_elf'] and m['failure_boundary']=='size-target'
    assert sha(m['elf']['path'])==m['elf']['sha256'] and sha(m['artifact']['path'])==m['artifact']['sha256']
    omitted={'source_files','prepared_source_files','sdk','payload_files'}
    row={key:value for key,value in m.items() if key not in omitted}
    row.update(manifest=receipt(path),source_input_count=len(m['source_files']),
        sdk_input_count=len(m['sdk']['files']),sdk_archive_sha256=m['sdk']['archive_sha256'],
        sdk_input_digest=hashlib.sha256(json.dumps(m['sdk']['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        logs={log_name:receipt(path.parent/log_name) for log_name in ('prepare.log','compile.log','elf-readelf.log','apk-metadata.log','sstrip-check.log')})
    sdk.append(row)
assert sdk[0]['elf']['sha256']==sdk[1]['elf']['sha256'] and sdk[0]['artifact']['sha256']==sdk[1]['artifact']['sha256']
assert sdk[1]['artifact_identity_verified'] and sdk[1]['apk_byte_identical']
result=dict(schema='dnsmasq-fix3-shared-answer-build-v1',source_commit=identity['source_commit'],product_tip=identity['product_tip'],
    source_digest=identity['source_digest'],source_input_count=identity['source_input_count'],
    source_archive=receipt(P/'source.tar'),source_identity=receipt(P/'source-identity.json'),
    source_extract=read(P/'source-extract.json'),sdk_copy=read(P/'sdk-copy.json'),sdk_prepared=receipt(P/'sdk-prepared.json'),
    summary=dict(ordinary_units=controller['ordinary_units'],sdk_source_builds=2,
        standard_and_map_clean_rebuild_elf_apk_identical=True,original_size_budget_passed=False,
        runtime_protection_maps_retested=False,scope='Source builds, complete ordinary units and artifact identity. Function/performance and deployment qualification remain separate.'),
    release=read(P/'release/build.json'),tests=read(P/'tests/build.json'),controller=controller,
    controller_result=receipt(P/'build-result.json'),controller_log=receipt(P/'build-sequence.driver.log'),
    sdk=sdk,exact_sdk_link_map=sdk[1]['link_map'],
    map_method='First build uses the unchanged product recipe and standard SDK compiler. The second clean source build uses a private Cargo wrapper only to select a compiler passthrough adding -Wl,-Map at the actual final GCC link; Rustflags and product recipe are unchanged. Full ELF and APK must be byte-identical before its map is accepted for the standard payload.',
    raw_log_limits='Build output contains pre-existing compiler/lint and SDK host-wrapper LD_PRELOAD warnings. Exit/stage/identity checks above passed; warning-free compilation is not claimed.',
    collector=receipt(__file__))
(P/'build-derived.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(dict(output=str(P/'build-derived.json'),sha256=sha(P/'build-derived.json'))))
