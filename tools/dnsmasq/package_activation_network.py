#!/usr/bin/env python3
"""Real APK activation with an independent veth DHCP/UDP/TCP client.

Run only through run_isolated.sh and actual_config_network.py. The original
image init/procd/ujail run unchanged except for the init shipped in the APK.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import time

from m2_lifecycle import Scenario
from m2_rootfs import STOCK_SHA256, sha256
from test_deploy_oracle import Deployment, wait


class PackageActivation(Deployment):
    def __init__(self, args):
        self.args, self.out = args, args.output
        self.out.mkdir(parents=True, exist_ok=False)
        fixture_args = argparse.Namespace(image_root=args.image_root,
            rust_binary=args.rust_binary, implementation='c', output=self.out / 'fixture',
            jail_procfs=False, skip_odhcpd=True)
        self.fixture = Scenario(fixture_args)
        self.root = self.fixture.root
        if args.procd:
            assert sha256(args.procd) == args.procd_sha256
            shutil.copy2(args.procd, self.root / 'sbin/procd')
        self.rust = sha256(args.rust_binary)
        self.hashes = {STOCK_SHA256, self.rust}
        for path, name in ((args.stock_apk, 'stock.apk'), (args.candidate_apk, 'candidate.apk')):
            shutil.copy2(path, self.root / 'm2' / name)
        self.configs = {name: sha256(self.root / name) for name in
                        ('etc/config/dhcp', 'etc/config/network', 'etc/dnsmasq.conf')}
        self.row = {'passed': False, 'support': {}, 'steps': {},
                    'candidate_sha256': self.rust, 'stock_sha256': STOCK_SHA256,
                    'candidate_apk_sha256': sha256(args.candidate_apk),
                    'stock_apk_sha256': sha256(args.stock_apk),
                    'source_commit': args.source_commit, 'tool_sha256': sha256(Path(__file__)),
                    'automatic_activation': True, 'explicit_restarts': []}
        self.ubusd = None

    def daemons(self, digest=None):
        rows = []
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                exe = os.readlink(proc / 'exe')
                if not exe.removesuffix(' (deleted)').endswith('/dnsmasq'):
                    continue
                actual = sha256(proc / 'exe')
                if actual not in self.hashes or (digest and actual != digest):
                    continue
                rows.append({'pid': int(proc.name), 'sha256': actual, 'exe': exe,
                             'start_ticks': (proc / 'stat').read_text().split()[21]})
            except (FileNotFoundError, ProcessLookupError):
                pass
        return rows

    def state(self, label, expected, previous=None, identical=False):
        daemon = wait(lambda: self.one(expected), label + ' actual ELF')
        if previous:
            old = (previous['pid'], previous['start_ticks'])
            new = (daemon['pid'], daemon['start_ticks'])
            assert (old == new) == identical, (label, old, new)
            if not identical:
                wait(lambda: not Path('/proc', str(previous['pid'])).exists(), label + ' old exit')
        client = wait(self.client, label + ' independent client')
        assert {name: sha256(self.root / name) for name in self.configs} == self.configs
        service = self.fixture.bus('service', 'list', {'name': 'dnsmasq', 'verbose': True})
        procd_pid = self.row['support']['/sbin/procd']['pid']
        memory = {line.split(':')[0]: line.split(':', 1)[1].strip()
                  for line in Path('/proc', str(procd_pid), 'status').read_text().splitlines()
                  if line.startswith(('VmRSS:', 'VmHWM:'))}
        self.row['steps'][label] = {'daemon': daemon, 'client': client,
                                    'service': service, 'procd_memory': memory}
        self.save()
        return daemon

    def transaction(self, label, apk, expected, previous, reinstall=False, identical=False):
        started = time.monotonic()
        argv = ['/usr/bin/apk', '--no-network', '--allow-untrusted', 'add']
        if reinstall:
            argv.append('--force-reinstall')
        self.run(*argv, '/m2/' + apk)
        result = self.state(label, expected, previous, identical)
        self.row['steps'][label]['transaction_and_health_seconds'] = time.monotonic() - started
        self.save()
        return result

    def save(self):
        (self.out / 'result.json').write_text(json.dumps(self.row, indent=2) + '\n')

    def execute(self):
        self.boot()
        stock = self.state('stock', STOCK_SHA256)
        current = self.transaction('upgrade', 'candidate.apk', self.rust, stock)
        current = self.transaction('identical-reinstall', 'candidate.apk', self.rust, current,
                                   reinstall=True, identical=True)
        self.run('/etc/init.d/dnsmasq', 'reload')
        current = self.state('unchanged-reload', self.rust, current, identical=True)
        # Real archive corruption must fail without changing the current service.
        payload = (self.root / 'm2/candidate.apk').read_bytes()
        (self.root / 'm2/broken.apk').write_bytes(payload[:len(payload) // 2])
        result = self.run('/usr/bin/apk', '--no-network', '--allow-untrusted',
                          'add', '--force-reinstall', '/m2/broken.apk', check=False)
        assert result.returncode != 0, 'truncated APK was accepted'
        current = self.state('rejected-broken-archive', self.rust, current, identical=True)
        self.row['steps']['rejected-broken-archive']['apk_exit'] = result.returncode
        self.transaction('direct-stock-downgrade', 'stock.apk', STOCK_SHA256, current)
        self.row['passed'] = True
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image-root', 'rust-binary', 'stock-apk', 'candidate-apk', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--procd', type=Path)
    parser.add_argument('--procd-sha256')
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert os.environ.get('DNSMASQ_CLIENT_PID') and 'private' in args.output.resolve().parts
    assert bool(args.procd) == bool(args.procd_sha256)
    case = PackageActivation(args)
    try:
        case.execute()
    except Exception as error:
        case.row['error'] = repr(error)
        raise
    finally:
        case.fixture.close()
        case.row['remaining_daemons'] = case.daemons()
        case.row['passed'] &= not case.row['remaining_daemons']
        case.save()
    print(json.dumps({'passed': case.row['passed'], 'steps': list(case.row['steps'])}))
    return int(not case.row['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
