#!/usr/bin/env python3
"""Fresh config, TFTP and signal checks; all daemon commands use private namespaces."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--image', type=Path, required=True)
    a = p.parse_args()
    source = a.root / 'source-fix'
    tools = source / 'tools/dnsmasq'
    old = source / 'docs/dnsmasq/audits/20261011'
    out = a.root / 'private/config'
    out.mkdir(exist_ok=False)
    jobs = []
    for side in ('main', 'fix'):
        binary = a.root / f'private/release-{side}/dnsmasq-rs'
        common = ['--rust', str(binary), '--out']
        jobs += [
            (f'{side}-config', old / 'fix2/config/config_normal.py',
             ['--source', str(source), '--image', str(a.image), *common, str(out / f'{side}-config')]),
            (f'{side}-tftp-policy', old / 'independent/config_signals_tftp_probe.py',
             ['--image', str(a.image), *common, str(out / f'{side}-tftp-policy')]),
            (f'{side}-inactive', tools / 'audit_20261011_config.py',
             ['--image-root', str(a.image), *common, str(out / f'{side}-inactive')]),
        ]
    jobs.append(('fix-dump', old / 'fix2/config/dump_rows.py',
                 ['--source', str(source), '--image', str(a.image), '--rust',
                  str(a.root / 'private/release-fix/dnsmasq-rs'), '--source-revision',
                  'e3a37f55b2939ee2a0c229b0ac96a2a9c407b8aa', '--require-match',
                  '--out', str(out / 'fix-dump')]))
    jobs.append(('fix-signals', Path(__file__).with_name('signal_probe.py'),
                 ['--source', str(source), '--image', str(a.image), '--root', str(a.root),
                  '--out', str(out / 'fix-signals')]))
    report = {'controller_sha256': sha(__file__), 'started': time.time(), 'commands': []}
    for name, script, args in jobs:
        argv = ['sudo', '-n', 'sh', str(tools / 'run_isolated.sh'), 'python3', str(script), *args]
        start = time.time()
        log = out / f'{name}.log'
        with log.open('wb') as stream:
            result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, timeout=300)
        path = out / name / 'result.json'
        report['commands'].append(dict(name=name, argv=argv, exit=result.returncode,
                                       seconds=time.time() - start, tool_sha256=sha(script),
                                       log_sha256=sha(log), result_sha256=sha(path) if path.exists() else None))
        (out / 'controller.json').write_text(json.dumps(report, indent=2) + '\n')
        print(name, result.returncode, flush=True)
    report['finished'] = time.time()
    (out / 'controller.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
