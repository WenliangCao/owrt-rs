#!/usr/bin/env python3
"""Freeze and run final SDK/C/main cached-DNS triples using retained machinery.

Only prepares evidence and executes isolated probes. Does not compile or edit
product inputs. All private files stay on Oracle; exported JSON is derived data.
"""
import argparse
import json
from pathlib import Path
import sys

HARNESS = Path('/home/ubuntu/dnsmasq-fix4-repairs-20261013/performance')
FINAL = Path('/home/ubuntu/dnsmasq-fix4-repair-20261013')
PRODUCT_COMMIT = '3e2c7b17b03cdd4c0005419b447db2cf0eda9d92'
SDK_SHA = '55ea363f626f3e14279f280b1dba708a1d751877ab22a3503d312985c9efd6ca'
sys.path.insert(0, str(HARNESS))
import three_way as old


def prepare(args):
    # Reuse its identity/receipt validation and the raw matrix before adding
    # the ordinary and type-absent controls. No load starts until the plan is final.
    args.candidate = FINAL / 'private/release-final/dnsmasq-rs'
    args.candidate_commit = PRODUCT_COMMIT
    args.suite = 'raw'
    old.prepare(args)
    plan_path = args.output / 'plan.json'
    plan = json.loads(plan_path.read_text())
    sdk = FINAL / 'private/sdk-verify-final/payload/usr/sbin/dnsmasq'
    manifest = FINAL / 'private/sdk-verify-final/manifest.json'
    source_identity = FINAL / 'private/source-final-identity.json'
    identity = json.loads(source_identity.read_text())
    receipt = json.loads(manifest.read_text())
    assert identity['source_commit'] == receipt['source_commit'] == PRODUCT_COMMIT
    assert receipt['build_mode'] == 'compile-and-package' and not receipt['frozen_elf']
    assert receipt['expected_elf_sha256'] == old.sha(sdk) == SDK_SHA
    source = FINAL / 'source-final'
    assert old.inputs(source) == identity['source_files']
    plan['groups']['current'] = dict(
        elf=str(sdk), sha256=SDK_SHA, bytes=sdk.stat().st_size,
        source_commit=PRODUCT_COMMIT, source_files=identity['source_files'],
        sdk_manifest=dict(path=str(manifest), sha256=old.sha(manifest)),
        source_identity=dict(path=str(source_identity), sha256=old.sha(source_identity)),
        build_mode=receipt['build_mode'], original_size_budget_passed=False)
    plan['scope'] = 'Fresh final SDK / exact-image C / unchanged main; Oracle screening, not router qualification'
    plan['suite'] = 'final-sdk-seven-profiles'
    plan['method'] = ('Three balanced Latin-square rounds, all windows retained, no retry. '
        '1000 QPS, 20 clients, 3 s warmup, 15 s measurement, 4096 individually proven cached A names. '
        'Upstream disabled during measured load. CPU0/1/2/3 daemon/upstream/load/controller. '
        'Cgroup service-tree CPU includes C TCP children. Descriptive medians/ranges only. '
        'Ordinary window is shorter than the historical 30/120-second control.')
    profiles = [('tcp-ordinary', 'tcp', 0, 1), ('tcp-raw-a-100', 'tcp', 100, 1),
                ('tcp-raw-a-1000', 'tcp', 1000, 1), ('udp-raw-a-100', 'hit', 100, 1),
                ('udp-raw-a-1000', 'hit', 1000, 1), ('tcp-absent-100', 'tcp', 100, 65401),
                ('tcp-absent-1000', 'tcp', 1000, 65401)]
    orders = [['c', 'main', 'current'], ['main', 'current', 'c'], ['current', 'c', 'main']]
    templates = {v: next(w['argv'] for w in plan['windows'] if w['variant'] == v) for v in orders[0]}
    plan['windows'] = []
    for round_no, order in enumerate(orders, 1):
        for profile, scenario, count, rrtype in profiles:
            for variant in order:
                ident = f'{profile}-r{round_no}-{variant}'
                argv = list(templates[variant])
                argv[3] = str(HARNESS / ('type_absent_window.py' if rrtype == 65401 else 'raw_window.py'))
                argv[5:7] = [str(count), str(rrtype)]
                values = {'--scenario': scenario, '--round': str(round_no),
                          '--seed': str(0x4d533100 + round_no), '--output': str(args.output / ident)}
                if variant != 'main':
                    values.update({'--rust': str(sdk), '--expected-rust-sha': SDK_SHA})
                for flag, value in values.items():
                    argv[argv.index(flag) + 1] = value
                plan['windows'].append(dict(id=ident, profile=profile, variant=variant,
                                           round=round_no, declarations=count, rrtype=rrtype, argv=argv))
    # Bind the imported measurement/control code, SDK provenance and every
    # final product input. Source identity is also independently matched to Git
    # by this audit's local identity check.
    assets = [Path(__file__).resolve(), sdk, manifest, source_identity, HARNESS / 'type_absent_window.py']
    assets += [p for p in old.TOOLS.iterdir() if p.is_file() and p.suffix in ('.py', '.sh')]
    for path in assets:
        plan['assets'][str(path)] = old.sha(path)
    old.save(plan_path, plan)
    print('frozen final SDK windows', len(plan['windows']), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run', 'summarize'))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--warmup', type=int, default=3)
    parser.add_argument('--duration', type=int, default=15)
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(args)
    else:
        getattr(old, args.action)(args)
