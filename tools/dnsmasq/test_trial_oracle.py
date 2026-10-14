#!/usr/bin/env python3
"""Exercise deploy/dnsmasq-trial in disposable exact-image rootfses.

Run on the AArch64 Oracle build host as root, inside run_isolated.sh. Each case
boots the image's ubusd/logd/procd/netifd and stock init, then checks which
ELF actually runs (by /proc exe hash) and that a real veth client still gets a
DHCP lease and DNS answers. Never invoke this on OpenWrt.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

from m2_lifecycle import Scenario
from m2_rootfs import STOCK_SHA256, command, sha256
from test_deploy_oracle import Deployment, host, wait

CASES = ('confirm-rollback', 'deadline', 'crash', 'hang', 'watch-killed',
         'partial-rollback', 'reload', 'rollback-killed',
         'confirmed-rollback-killed', 'rollback-cleanup-killed', 'rollback-c-dns-loss', 'documented-path')
TRIAL = '/usr/sbin/dnsmasq-trial'


def interrupt_rollback(pid, phase, ready, evidence):
    """Observe unchanged shell syscalls and inject exactly one SIGKILL.

    No product hooks or substituted commands: the parent is stopped between
    syscalls so even the interval before the first unmount is observable.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long

    def ptrace(request, data=0):
        result = libc.ptrace(request, pid, ctypes.c_void_p(0), ctypes.c_void_p(data))
        if result == -1:
            raise OSError(ctypes.get_errno(), 'ptrace')

    ptrace(0x4206, 1)  # PTRACE_SEIZE, PTRACE_O_TRACESYSGOOD
    ptrace(0x4207)  # PTRACE_INTERRUPT
    os.waitpid(pid, 0)
    Path(ready).touch()
    deliver = 0
    root = Path(f'/proc/{pid}/root/tmp/dnsmasq-trial')
    while True:
        ptrace(24, deliver)  # PTRACE_SYSCALL
        _, status = os.waitpid(pid, 0)
        assert os.WIFSTOPPED(status), status
        stop = os.WSTOPSIG(status)
        deliver = 0 if stop in (signal.SIGTRAP, signal.SIGTRAP | 0x80) else stop
        if stop != signal.SIGTRAP | 0x80:
            continue
        mounted = ' /usr/sbin/dnsmasq ' in Path(f'/proc/{pid}/mounts').read_text()
        helpers = sorted(path.name for path in root.glob('*.pid'))
        reached = {
            'requested': (root / 'rollback').exists() and mounted,
            'unmounted': not mounted,
            'helpers-cleared': not helpers,
        }[phase]
        if reached:
            Path(evidence).write_text(json.dumps({'pid': pid, 'phase': phase,
                'mounted': mounted, 'helper_files': helpers, 'signal': 'SIGKILL'}))
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            return


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

    def kill_rollback(self, phase):
        process = subprocess.Popen(command(self.root, '/bin/sh', '-c',
            f'kill -STOP $$; exec {TRIAL} rollback interruption-test'),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ready, evidence = self.out / 'trace-ready', self.out / 'fault.json'
        tracer = subprocess.Popen([sys.executable, __file__, '_trace',
            str(process.pid), phase, str(ready), str(evidence)])
        try:
            wait(ready.exists, 'tracer attached', 5)
            os.kill(process.pid, signal.SIGCONT)
            assert tracer.wait(30) == 0
            self.row['fault'] = json.loads(evidence.read_text())
            self.row['rollback_exit'] = process.wait(2)
            assert self.row['rollback_exit'] == -signal.SIGKILL
        finally:
            for child in (tracer, process):
                if child.poll() is None:
                    child.kill()
                    child.wait(5)

    def execute(self):
        case = self.args.case
        if case == 'documented-path':
            # Match the runbook's example name while retaining the fixture's
            # lifecycle.lan answer for the independent DHCP/DNS client.
            with (self.root / 'etc/hosts').open('a') as hosts:
                hosts.write('192.168.1.1 OpenWrt.lan\n')
        self.boot()
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
        elif case in ('rollback-killed', 'confirmed-rollback-killed', 'rollback-cleanup-killed'):
            self.start(seconds=25)
            phase = 'requested'
            if case == 'confirmed-rollback-killed':
                self.trial('confirm')
                phase = 'unmounted'
            elif case == 'rollback-cleanup-killed':
                phase = 'helpers-cleared'
            self.kill_rollback(phase)
            self.back_to_c('automatic_recovery', seconds=60)
            wait(lambda: not list((self.root / 'tmp/dnsmasq-trial').glob('*.pid')),
                 'helpers stopped after C health', 15)
            self.row['steps']['helpers_cleared'] = True
        elif case == 'rollback-c-dns-loss':
            self.start()
            rules = [['INPUT', '-d', '192.168.1.1', '-p', protocol,
                      '--dport', '53', '-j', 'DROP'] for protocol in ('udp', 'tcp')]
            for rule in rules:
                host('iptables', '-I', *rule)
            process = subprocess.Popen(command(self.root, TRIAL, 'rollback', 'dns-loss'),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, stderr = process.communicate(timeout=55)
                self.row['unhealthy_rollback'] = {'exit': process.returncode,
                    'stdout': stdout, 'stderr': stderr}
                assert process.returncode == 1, 'unresponsive C reported healthy'
                assert self.one(STOCK_SHA256), 'C identity should already match'
                assert (self.root / 'tmp/dnsmasq-trial/rollback').exists()
                for name in ('deadline', 'watch'):
                    pid = self.helper(name)
                    state = Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()[0]
                    assert state != 'Z', (name, pid, state)
                self.row['steps']['owners_kept_for_unresponsive_c'] = True
            finally:
                for rule in rules:
                    host('iptables', '-D', *rule)
                if process.poll() is None:
                    process.kill()
                    process.wait(5)
            self.back_to_c('dns_restored_automatic_recovery')
            wait(lambda: not list((self.root / 'tmp/dnsmasq-trial').glob('*.pid')),
                 'helpers stopped after restored C DNS', 15)
        elif case == 'documented-path':
            script, candidate = '/tmp/dnsmasq-trial.sh', '/tmp/dnsmasq-rs'
            shutil.copy2(self.args.trial, self.root / script.lstrip('/'))
            shutil.copy2(self.args.rust_binary, self.root / candidate.lstrip('/'))
            (self.root / script.lstrip('/')).chmod(0o644)
            self.run('/bin/chmod', '755', script)
            hashes = self.run('/usr/bin/sha256sum', candidate, script).stdout
            assert self.rust in hashes and self.row['trial_sha256'] in hashes
            self.row['uploaded_hashes'] = hashes
            argv = ['/bin/sh', script, 'start', candidate, self.rust,
                    'OpenWrt.lan', '127.0.0.1', '600']
            self.row['documented_start_argv'] = argv
            self.run(*argv)
            self.row['steps']['candidate'] = wait(lambda: self.one(self.rust), 'candidate running')
            self.row['steps']['candidate_client'] = wait(self.client, 'candidate client')
            assert 'trial active:' in self.run('/bin/sh', script, 'status').stdout
            self.run('/bin/sh', script, 'confirm')
            time.sleep(6)
            assert self.one(self.rust), 'confirmed candidate replaced'
            self.run('/bin/sh', script, 'rollback')
            self.back_to_c('documented_rollback')
            # Adjacent failure boundary: a bad upload identity still fails
            # before mounts/helpers and leaves the exact C serving clients.
            argv[4] = '0' * 64
            rejected = self.run(*argv, check=False)
            assert rejected.returncode == 1 and 'candidate hash mismatch' in rejected.stdout
            self.row['steps']['bad_upload_hash_rejected'] = True
            self.back_to_c('bad_upload_preserved_c')
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
    if sys.argv[1:2] == ['_trace']:
        interrupt_rollback(int(sys.argv[2]), *sys.argv[3:])
    else:
        main()
