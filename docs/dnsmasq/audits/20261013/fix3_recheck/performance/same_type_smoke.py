#!/usr/bin/env python3
"""C/main/final --test and direct raw-A plus cached-A functional preflight.

Must run under run_isolated.sh. The 1s/100QPS smoke has no timing claims.
"""
import json
import os
from pathlib import Path
import subprocess

import same_type_pairs as base
from m2_rootfs import image_elf_command

assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
out = base.ROOT / 'private/performance-same-type-smoke'
out.mkdir(exist_ok=False)
config = out / 'config'
config.write_text('no-hosts\nno-resolv\n' + ''.join(
    f'dns-rr=unused{i}.audit.test,1,c0000201\n' for i in range(1000)))
final = base.ROOT / 'private/release/dnsmasq-rs'
binaries = {'c': base.IMAGE / 'usr/sbin/dnsmasq',
            'main': base.PRIOR / 'private/release-main/dnsmasq-rs', 'fix': final}
result = dict(scope='Functional only; builds may overlap. TYPE A raw option must parse and answer directly over UDP/TCP, then ordinary cached A smoke must pass.',
              config_sha256=base.sha(config), cases=[])
for variant, elf in binaries.items():
    argv = image_elf_command(base.IMAGE, elf) + ['--test', '-C', str(config)]
    test = subprocess.run(argv, capture_output=True, text=True)
    row = dict(variant=variant, sha256=base.sha(elf), syntax=dict(argv=argv,
               returncode=test.returncode, stdout=test.stdout, stderr=test.stderr))
    result['cases'].append(row)
    base.save(out / 'summary.json', result)
    assert test.returncode == 0, row
    folder = out / variant
    argv = ['python3', str(base.SCRIPTS / 'same_type_window.py'), str(base.SOURCE), '1000',
            '--implementation', 'c' if variant == 'c' else 'rs', '--rust', str(final if variant == 'c' else elf),
            '--expected-rust-sha', base.sha(final if variant == 'c' else elf), '--image-root', str(base.IMAGE),
            '--loadgen', str(base.NATIVE / 'm6a_loadgen'), '--upstream', str(base.NATIVE / 'm6a_upstream'),
            '--preflight', '--scenario', 'hit', '--tcp-profile', 'hit', '--rate', '100', '--cache-names', '4096',
            '--clients', '20', '--warmup', '1', '--duration', '1', '--saturation-seconds', '0',
            '--drain-sample-seconds', '0,1', '--drain-timeout-seconds', '30', '--output', str(folder)]
    with (out / (variant + '.log')).open('wb') as log:
        process = subprocess.run(argv, stdout=log, stderr=log)
    row.update(argv=argv, returncode=process.returncode)
    base.save(out / 'summary.json', result)
    assert process.returncode == 0, row
    measured = json.loads((folder / 'result.json').read_text())
    identity = json.loads((folder / 'process-identity.json').read_text())
    direct = json.loads((folder / 'same-type-proof.json').read_text())
    assert identity['sha256'] == base.sha(elf)
    assert all(proof['correct'] for proof in direct['replies'].values())
    for phase in ('warmup', 'measurement'):
        counts = measured['measurement']['load'][phase]
        assert counts['sent'] == counts['correct'] == 100
        assert all(counts[k] == 0 for k in ('wrong', 'timeout', 'transport_error', 'scheduled_skipped'))
    row.update(passed=True, direct_proof=direct,
               raw_files={name: base.sha(folder / name) for name in
                          ('result.json', 'process-identity.json', 'same-type-proof.json', 'cache-proof.json', 'upstream.json')})
    base.save(out / 'summary.json', result)
result['passed'] = all(case['passed'] for case in result['cases'])
base.save(out / 'summary.json', result)
print(json.dumps(dict(passed=result['passed'], variants=[r['variant'] for r in result['cases']])))
