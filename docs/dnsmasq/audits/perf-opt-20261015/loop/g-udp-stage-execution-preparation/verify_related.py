"""Verify original diagnostic gate evidence without rerunning or selecting tests."""
import hashlib
import json
from pathlib import Path
import re
import time

root = Path('/home/ubuntu/dnsmasq-perf-20261015')
inputs = root / 'loop/private/g-udp-stage-inputs'
out = root / 'loop/private/g-udp-stage-linux-gates-20261016'
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
plan = json.loads((inputs / 'manifest.json').read_text())
launch = json.loads((inputs / 'related-launch.json').read_text())
raw = json.loads((out / 'result.json').read_text())
assert not Path('/proc', str(launch['pid'])).exists()
assert raw['status'] == 'complete' and raw['active'] is None and len(raw['candidates']) == 1
assert raw['affinity'] == [2] and raw['nice'] >= 10
assert sha(inputs / 'run_g_udp_stage_related.py') == plan['adapted_related_runner']['sha256']
candidate = raw['candidates'][0]
assert candidate['name'] == 'g-udp-stage' and candidate['status'] == 'passed'
assert candidate['source_commit'] == plan['source_commit']
assert candidate['source_inputs_verified_before'] == candidate['source_inputs_verified_after'] == 180
assert candidate['prepared_identity_sha256'] == plan['git_identity_sha256']
folder = out / 'g-udp-stage'
build = folder / 'tests'
assert sha(build / 'build.json') == candidate['build_receipt_sha256']
built = json.loads((build / 'build.json').read_text())
assert built['source'] == plan['planned_remote_source'] and built['kind'] == 'tests'
assert built['artifacts'] == candidate['artifacts'] and len(built['artifacts']) == 2
for artifact in built['artifacts']:
    path = build / artifact['path']
    assert sha(path) == artifact['sha256'] and path.stat().st_size == artifact['bytes']
assert [{'name': row['name'], 'argv': row['argv']} for row in candidate['commands']] == plan['related_commands']
checked = {}
fixture = 'dns::udp_stage_diagnostic::tests::synthetic_replies_match_the_fixed_input_and_address_contract'
for row in candidate['commands']:
    assert row['returncode'] == 0
    for stream in ['stdout', 'stderr']:
        assert sha(folder / (row['name'] + '.' + stream)) == row[stream + '_sha256']
    if row['name'] == 'build':
        continue
    text = (folder / (row['name'] + '.stdout')).read_text()
    matches = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', text)
    assert len(matches) == 1
    status, passed, failed, ignored, measured, filtered = matches[0]
    assert status == 'ok' and int(failed) == int(measured) == 0
    names = re.findall(r'^test (.+) \.\.\. ok$', text, re.M)
    ignored_names = re.findall(r'^test (.+) \.\.\. ignored(?:,.*)?$', text, re.M)
    assert len(names) == len(set(names)) == int(passed) == row['passed']
    assert len(ignored_names) == len(set(ignored_names)) == int(ignored) == row['ignored']
    assert names == row['passed_test_names'] and ignored_names == row['ignored_test_names']
    binary = build / ('lib-dnsmasq_rs' if row['name'] == 'stage-fixture' else 'bin-dnsmasq-rs')
    assert sha(binary) == row['binary_sha256']
    if row['name'] == 'stage-fixture':
        assert names == [fixture]
    checked[row['name']] = {'passed': int(passed), 'ignored': int(ignored), 'filtered': int(filtered),
                            'passed_names': names, 'ignored_names': ignored_names}
assert checked['bin']['passed'] > 0
assert set(checked['bin-ignored-live']['passed_names']) == set(checked['bin']['ignored_names'])
assert checked['bin-ignored-live']['ignored'] == 0
source = Path(plan['planned_remote_source'])
assert sha(source / 'research-git-identity.json') == plan['git_identity_sha256']
identity = json.loads((source / 'research-git-identity.json').read_text())
assert len(identity['git_blob_sha1']) == 180 and set(identity['git_blob_sha1']) == set(plan['source_files'])
for name, digest in plan['source_files'].items():
    data = (source / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == identity['git_blob_sha1'][name]
report = {'status': 'PASS_FRESH_G_STAGE_ORIGINAL_THREE_RELATED_SELECTIONS', 'epoch': time.time(),
          'source_commit': plan['source_commit'], 'source_inputs_verified': 180,
          'git_identity_sha256': plan['git_identity_sha256'], 'source_manifest_sha256': plan['source_manifest_sha256'],
          'runner_sha256': plan['adapted_related_runner']['sha256'], 'raw_result_sha256': sha(out / 'result.json'),
          'build_receipt_sha256': sha(build / 'build.json'), 'artifacts': built['artifacts'],
          'actual_groups': checked, 'total_actual_test_passes': sum(row['passed'] for row in checked.values()),
          'original_ignored_selection_matches_fresh_normal_bin_inventory': True,
          'all_eight_log_hashes_and_both_binaries_rechecked': True, 'controller_exited': True,
          'no_gate_rerun': True, 'full_lib_or_product_fivegroups_run': False,
          'scope': 'Excluded diagnostic fixture/bin/ignored-bin only; no full44, timing, product or deployment qualification.'}
path = inputs / 'related-verified.json'
assert not path.exists()
path.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'path': str(path), 'sha256': sha(path), 'status': report['status'],
                  'actual_counts': {key: row['passed'] for key, row in checked.items()},
                  'total': report['total_actual_test_passes']}))
