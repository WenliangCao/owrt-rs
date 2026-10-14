#!/usr/bin/env python3
"""Replay the unchanged predeployment DNS/reload/packet corpus in fresh namespaces.

Raw arguments, captures, names and packets remain in private. The C phase can run
before the replacement binary exists; the Rust phase requires its frozen digest.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--side', choices=('c', 'rust'), required=True)
    p.add_argument('--rust', type=Path)
    p.add_argument('--rust-sha256')
    p.add_argument('--jobs', type=int, default=2)
    a = p.parse_args()
    source = a.root / 'source'
    tools = source / 'tools/dnsmasq'
    out = a.root / 'private/actual'
    out.mkdir(parents=True, exist_ok=True)
    image = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
    capture = Path('/home/ubuntu/dnsmasq-dhcp-network-actual-20261001/private/runtime-source/rootfs')
    reference = Path('/home/ubuntu/dnsmasq-rewrite-20260929/c-native-01')
    topology = Path('/home/ubuntu/dnsmasq-northstar-dns-20261002/private/c-network-07/topology.json')
    cidr = json.loads(topology.read_text())['router']
    binary = image / 'usr/sbin/dnsmasq' if a.side == 'c' else a.rust
    expected = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87' if a.side == 'c' else a.rust_sha256
    assert binary and expected and sha(binary) == expected
    plans = []
    for label, script, flags in [
        ('focused', 'predeploy_audit_dns.py', ['--focused']),
        ('public-cache', 'predeploy_audit_dns.py', ['--public-cache-only']),
        ('regular', 'predeploy_audit_dns.py', ['--saturation']),
        ('reload', 'predeploy_audit_reload.py', []),
        ('robustness', 'predeploy_audit_robustness.py', []),
    ]:
        folder = out / (a.side + '-' + label)
        assert not folder.exists(), folder
        argv = ['sudo', '-n', 'sh', str(tools / 'run_isolated.sh'),
                'python3', str(tools / 'actual_config_network.py'), '--source-root', str(capture),
                '--router-cidr', cidr, '--output', str(folder) + '-network', '--',
                'python3', str(tools / 'actual_config_rootfs.py'), '--source-root', str(capture), '--',
                'python3', str(tools / script), '--image-root', str(image),
                '--reference-build', str(reference), '--out', str(folder)]
        if label == 'reload':
            argv += ['--side', a.side, '--rust', str(binary)]
        else:
            argv += ['--binary', str(binary)] + flags
            if a.side == 'c' and label != 'robustness':
                argv += ['--image-elf']
        plans.append(dict(label=label, argv=argv, tool_sha256=sha(tools / script)))
    receipt_path = out / (a.side + '-invocations.json')
    assert not receipt_path.exists()
    report = dict(side=a.side, binary_sha256=expected, runner_sha256=sha(__file__), runs=[])

    def execute(plan):
        log = out / (a.side + '-' + plan['label'] + '.log')
        started = time.time()
        with log.open('xb') as handle:
            process = subprocess.run(plan['argv'], stdout=handle, stderr=subprocess.STDOUT, timeout=600)
        folder = out / (a.side + '-' + plan['label'])
        result = folder / 'result.json'
        return dict(**plan, exit=process.returncode, started=started, ended=time.time(),
                    log_sha256=sha(log), result_sha256=sha(result) if result.exists() else None)

    with ThreadPoolExecutor(max_workers=a.jobs) as pool:
        for row in pool.map(execute, plans):
            report['runs'].append(row)
            receipt_path.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps({k: row[k] for k in ('label', 'exit', 'result_sha256')}), flush=True)
    assert sha(binary) == expected
    assert all(row['exit'] == 0 for row in report['runs'])


if __name__ == '__main__':
    main()
