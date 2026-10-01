#!/usr/bin/env python3
"""Mount the captured dnsmasq runtime files in a private mount namespace.

Shared by startup checks and the actual-config DHCP/DNS experiment. Inputs and
outputs are private; this never edits the captured source files.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess


def prepare(source_root):
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    original = source_root / 'var/etc/dnsmasq.conf.cfg01411c'
    expected = hashlib.sha256(original.read_bytes()).hexdigest()
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    for directory in ('/etc', '/tmp', '/var', '/usr/share', '/run'):
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=0755', 'dnsmasq-actual-config', directory], check=True)
        source = source_root / directory.lstrip('/')
        if source.exists():
            shutil.copytree(source, directory, dirs_exist_ok=True)
    Path('/tmp').chmod(0o1777)
    # procd supplies this writable PID directory before dropping privileges.
    runtime = Path('/var/run/dnsmasq')
    runtime.mkdir(parents=True, exist_ok=True)
    os.chown(runtime, 453, 453)
    runtime.chmod(0o755)
    Path('/run/ubus').mkdir(parents=True, exist_ok=True)
    Path('/var/run/ubus').mkdir(parents=True, exist_ok=True)
    subprocess.run(['mount', '--bind', '/run/ubus', '/var/run/ubus'], check=True)
    assert hashlib.sha256(Path('/var/etc/dnsmasq.conf.cfg01411c').read_bytes()).hexdigest() == expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    assert command
    prepare(args.source_root)
    return subprocess.run(command).returncode


if __name__ == '__main__':
    raise SystemExit(main())
