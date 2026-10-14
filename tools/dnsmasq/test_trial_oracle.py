#!/usr/bin/env python3
"""Exercise deploy/dnsmasq-trial in disposable exact-image rootfses.

Run on the AArch64 Oracle build host as root, inside run_isolated.sh. Each case
boots the image's ubusd/logd/procd/netifd and stock init, then checks which
ELF actually runs (by /proc exe hash) and that a real veth client still gets a
DHCP lease and DNS answers. Never invoke this on OpenWrt.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import time

from m2_lifecycle import Scenario
from m2_rootfs import STOCK_SHA256, sha256
from test_deploy_oracle import Deployment, host, wait

CASES = ('confirm-rollback', 'deadline', 'crash', 'hang', 'watch-killed',
         'partial-rollback', 'reload')
TRIAL = '/usr/sbin/dnsmasq-trial'


class Trial(Deployment):
    def __init__(self, args):
        self.args, self.out = args, args.output
        self.out.mkdir(parents=True, exist_ok=False)
        fixture_args = argparse.Namespace(image_root=args.image_root,
            rust_binary=args.rust_binary, implementation='c', output=self.out / 'fixture',
            jail_procfs=False, skip_odhcpd=True)
        self.fixture = Scenario(fixture_args)
        self.root = self.fixture.root
        identity = json.loads((self.out / 'fixture/rootfs-identity.json').read_text())
        (self.root / 'rom').mkdir(exist_ok=True)
        host('mount', '--bind', identity['filesystem']['lower'], self.root / 'rom')
        host('mount', '-o', 'remount,bind,ro', self.root / 'rom')
        assert sha256(self.root / 'rom/usr/sbin/dnsmasq') == STOCK_SHA256
        shutil.copy2(args.trial, self.root / TRIAL.lstrip('/'))
        (self.root / TRIAL.lstrip('/')).chmod(0o755)
        self.rust = sha256(args.rust_binary)
        self.hashes = {STOCK_SHA256, self.rust}
        self.row = {'case': args.case, 'passed': False, 'support': {}, 'steps': {},
                    'candidate_sha256': self.rust, 'stock_sha256': STOCK_SHA256,
                    'trial_sha256': sha256(args.trial)}
        self.ubusd = None

    def debug(self):
        for cmd in (['/bin/pidof', 'dnsmasq'], ['/bin/sh', '-c', 'for p in $(pidof dnsmasq); do sha256sum /proc/$p/exe; done'],
                    ['/usr/bin/nslookup', 'lifecycle.lan', '192.168.1.1'], ['/bin/sh', '-c', 'for p in $(pidof dnsmasq); do readlink /proc/$p/exe; done']):
            r = self.run(*cmd, check=False)
            print('DEBUG', cmd, r.returncode, r.stdout[-300:], r.stderr[-300:], flush=True)

    def trial(self, *args, check=True):
        return self.run(TRIAL, *args, check=check)

    def start(self, seconds=600):
        self.trial('start', '/usr/sbin/dnsmasq-rs', self.rust, 'lifecycle.lan',
                   '192.168.1.1', str(seconds))
        self.row['steps']['candidate'] = wait(lambda: self.one(self.rust), 'candidate running')
        self.row['steps']['candidate_client'] = wait(self.client, 'candidate client')

    def back_to_c(self, label, seconds=60):
        self.row['steps'][label] = wait(lambda: self.one(STOCK_SHA256), label, seconds)
        self.row['steps'][label + '_client'] = wait(self.client, label + ' client')
        assert ' /usr/sbin/dnsmasq ' not in self.run('/bin/cat', '/proc/mounts').stdout

    def close(self):
        try:
            self.trial('rollback', check=False)
        finally:
            self.fixture.close()

    def helper(self, name):
        return int(self.run('/bin/cat', f'/tmp/dnsmasq-trial/{name}.pid').stdout)

    def execute(self):
        self.boot()
        case = self.args.case
        if case == 'confirm-rollback':
            self.start()
            self.trial('confirm')
            time.sleep(12)
            assert self.one(self.rust), 'confirmed candidate replaced'
            self.trial('rollback')
            self.back_to_c('rollback')
            self.trial('rollback')  # idempotent from stock C
            self.back_to_c('second_rollback')
        elif case == 'deadline':
            self.start(seconds=20)
            self.back_to_c('deadline_rollback', seconds=60)
        elif case == 'crash':
            self.start()
            source = self.out / 'crash.c'
            source.write_text('int main(void) { return 1; }\n')
            crash = self.out / 'crash'
            host('cc', '-static', '-Os', '-s', source, '-o', crash)
            # Stack it over the candidate: every procd respawn now crashes.
            shutil.copy2(crash, self.root / 'tmp/dnsmasq-crash')
            self.run('/bin/mount', '--bind', '/tmp/dnsmasq-crash', '/usr/sbin/dnsmasq')
            for pid in [row['pid'] for row in self.daemons(self.rust)]:
                os.kill(pid, signal.SIGKILL)
            self.back_to_c('crash_rollback', seconds=90)
        elif case == 'hang':
            self.start()
            for row in self.daemons(self.rust):
                os.kill(row['pid'], signal.SIGSTOP)
            self.back_to_c('hang_rollback', seconds=90)
        elif case == 'watch-killed':
            self.start(seconds=25)
            os.kill(self.helper('watch'), signal.SIGKILL)
            self.back_to_c('deadline_after_watch_killed', seconds=60)
        elif case == 'partial-rollback':
            self.start()
            os.kill(self.helper('watch'), signal.SIGKILL)
            os.kill(self.helper('deadline'), signal.SIGKILL)
            # A rollback interrupted right after unmounting: Rust still runs.
            self.run('/bin/umount', '/usr/sbin/dnsmasq')
            assert self.one(self.rust), 'candidate should still run'
            self.trial('rollback')
            self.back_to_c('rollback_after_partial')
        elif case == 'reload':
            self.start()
            before = self.one(self.rust)
            self.run('/etc/init.d/dnsmasq', 'reload')
            time.sleep(3)
            after = wait(lambda: self.one(self.rust), 'candidate after reload')
            assert after['pid'] == before['pid'], (before, after)
            self.row['steps']['reload_client'] = wait(self.client, 'reload client')
            self.trial('rollback')
            self.back_to_c('rollback')
        self.row['passed'] = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust-binary', type=Path, required=True)
    parser.add_argument('--trial', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=CASES, required=True)
    args = parser.parse_args()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or not os.environ.get('DNSMASQ_CLIENT_PID'):
        raise RuntimeError('run through run_isolated.sh and actual_config_network.py')
    trial = Trial(args)
    try:
        trial.execute()
    except Exception as error:  # record and re-raise for a nonzero exit
        trial.row['error'] = repr(error)
        raise
    finally:
        (args.output / 'result.json').write_text(json.dumps(trial.row, indent=2, default=str) + '\n')
        trial.close()
    print(json.dumps({'case': args.case, 'passed': trial.row['passed']}))


if __name__ == '__main__':
    main()
