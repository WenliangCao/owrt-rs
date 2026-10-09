#!/usr/bin/env python3
"""Replay captured WAN6 notify_proto inputs in isolated Linux namespaces.

Raw captures and all detailed outputs contain private addresses: keep them out
of Git. The printed summary contains counts and identities, not network data.
No router access is performed. Requires root, iproute2, and a matching rootfs.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

CONFIG = '''config globals 'globals'
 option ula_prefix 'fd00:1234:5678::/48'
config interface 'loopback'
 option device 'lo'
 option proto 'static'
 option ipaddr '127.0.0.1/8'
config device
 option name 'br-lan'
 option type 'bridge'
 option macaddr '02:00:00:00:00:20'
 list ports 'lan0'
config interface 'lan'
 option device 'br-lan'
 option proto 'static'
 option ipaddr '192.0.2.1/24'
 option ip6assign '60'
config interface 'wan6'
 option device 'wan'
 option proto 'healthreplay'
'''
PROTO = '''#!/bin/sh
. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"
proto_healthreplay_init_config() { :; }
proto_healthreplay_setup() {
 proto_init_update "$2" 1
 proto_send_update "$1"
}
proto_healthreplay_teardown() { :; }
add_protocol healthreplay
'''


def run(*argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, capture_output=True, **kwargs).stdout


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(capture):
    messages = []
    for line in capture.read_text().splitlines():
        if not line.startswith('<-') or 'invoke: ' not in line:
            continue
        if '"method":"notify_proto"' not in line:
            continue
        event = json.loads(line.split('invoke: ', 1)[1])
        if event['data'].get('interface') == 'wan6':
            messages.append(event['data'])
    if len(messages) != 13 or any(x.get('action') != 0 for x in messages):
        raise ValueError('expected the 13 captured WAN6 action-0 inputs')
    return messages


def snapshot(root, index):
    def ubus(iface):
        return json.loads(run('chroot', str(root), 'ubus', 'call',
                              'network.interface.' + iface, 'status'))
    knobs = {}
    for dev in ('all', 'default', 'wan', 'br-lan'):
        knobs[dev] = {}
        directory = Path('/proc/sys/net/ipv6/conf', dev)
        if not directory.exists():
            knobs[dev] = {'missing': True}
            continue
        for path in sorted(directory.iterdir()):
            try:
                knobs[dev][path.name] = path.read_text().strip()
            except OSError as error:
                knobs[dev][path.name] = {'errno': error.errno}
    return {'index': index, 'addresses': json.loads(run('ip', '-j', '-6', 'addr', 'show')),
            'routes': json.loads(run('ip', '-j', '-6', 'route', 'show', 'table', 'all')),
            'rules': json.loads(run('ip', '-j', '-6', 'rule', 'show')),
            'sysctl': knobs, 'wan6': ubus('wan6'), 'lan': ubus('lan')}


def inside(args):
    root, out = args.root, args.out
    run('mount', '-t', 'sysfs', 'sysfs', '/sys')
    run('mount', '-t', 'proc', 'proc', str(root / 'proc'))
    run('mount', '-t', 'sysfs', 'sysfs', str(root / 'sys'))
    run('mount', '-t', 'tmpfs', '-o', 'mode=1777', 'tmpfs', str(root / 'dev'))
    for name, minor in (('null', 3), ('zero', 5), ('urandom', 9)):
        run('mknod', '-m', '666', str(root / 'dev' / name), 'c', '1', str(minor))
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'add', 'wan', 'address', '02:00:00:00:00:10', 'type', 'veth',
        'peer', 'name', 'upstream', 'address', '02:00:00:00:00:11')
    run('ip', 'link', 'add', 'lan0', 'address', '02:00:00:00:00:20', 'type', 'veth',
        'peer', 'name', 'lan-client', 'address', '02:00:00:00:00:21')
    if args.dad == 'off':
        Path('/proc/sys/net/ipv6/conf/default/accept_dad').write_text('0')
    for dev in ('wan', 'upstream', 'lan0', 'lan-client'):
        if args.dad == 'off':
            Path('/proc/sys/net/ipv6/conf', dev, 'accept_dad').write_text('0')
        run('ip', 'link', 'set', dev, 'up')
    dump(out / 'namespaces.json', {n: os.readlink('/proc/self/ns/' + n)
                                 for n in ('pid', 'net', 'mnt')})
    with (out / 'ubusd.log').open('w') as log:
        subprocess.Popen(['chroot', str(root), '/sbin/ubusd'], stdout=log, stderr=log)
    time.sleep(0.5)
    with (out / 'netifd.log').open('w') as log:
        argv = ['/sbin/netifd', '-S', '-l', '7'] if args.side == 'c' else ['/sbin/netifd-rs']
        subprocess.Popen(['chroot', str(root), *argv], stdout=log, stderr=log)
    for _ in range(60):
        try:
            status = json.loads(run('chroot', str(root), 'ubus', 'call',
                                    'network.interface.wan6', 'status'))
            if status.get('up'):
                break
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(0.1)
    else:
        raise RuntimeError('WAN6 did not reach UP; replay not tested')
    time.sleep(2.2 if args.dad == 'on' else 1)
    with (out / 'netlink.log').open('w') as log:
        subprocess.Popen(['ip', '-ts', 'monitor', 'address', 'route'], stdout=log, stderr=log)
    snapshots = [snapshot(root, 0)]
    replies = []
    captured = extract(args.capture)
    def notify(event):
        return ['ubus', 'call', 'network.interface.wan6', 'notify_proto', json.dumps(event)]
    commands = [notify(event) for event in captured]
    if args.natural_expiry:
        short = copy.deepcopy(captured[0])
        short['ip6prefix'] = [p.split(',')[0] + ',6,6' for p in short['ip6prefix']]
        commands = [notify(short)]
    # Exercise deletion and re-addition as well as the captured renewals.
    withdrawn = copy.deepcopy(captured[-1])
    withdrawn['ip6prefix'] = []
    if args.lifecycle:
        expired = copy.deepcopy(captured[-1])
        expired['ip6prefix'] = [p.split(',')[0] + ',0,0' for p in expired['ip6prefix']]
        failed = copy.deepcopy(captured[-1])
        failed['ip6prefix'] = ['2001:db8:bad::/64,7200,3600']
        recovered = copy.deepcopy(failed)
        recovered['ip6prefix'] = ['2001:db8:bad::/64,1800,3600']
        commands.extend([
        notify(withdrawn), notify(captured[-1]), notify(expired), notify(captured[-1]),
        ['sh', '-c', 'uci delete network.lan.ip6assign && uci commit network && ubus call network reload'],
        ['sh', '-c', 'uci set network.lan.ip6assign=60 && uci commit network && ubus call network reload'],
        ['ubus', 'call', 'network.interface.lan', 'down'],
        ['ubus', 'call', 'network.interface.lan', 'up'],
        notify(failed), notify(recovered),
        ['ubus', 'call', 'network.interface.wan6', 'down'],
    ])
    immediate = []
    schedule = int(time.monotonic()) + 1.25
    timing = []
    for index, command in enumerate(commands, 1):
        # Both daemons must observe the same whole-second intervals. Otherwise
        # captured lifetime deltas can cancel a renewal on only one side and
        # create a false updated/prefixes or ifupdate mismatch.
        deadline = schedule + (index - 1) * 3
        time.sleep(max(0, deadline - time.monotonic()))
        lateness = time.monotonic() - deadline
        if lateness > 0.25:
            raise RuntimeError('missed replay clock slot: timing comparison invalid')
        timing.append(lateness)
        proc = subprocess.run(['chroot', str(root), *command], text=True, capture_output=True)
        replies.append({'index': index, 'rc': proc.returncode,
                        'stdout': proc.stdout, 'stderr': proc.stderr})
        if proc.returncode:
            dump(out / 'replies.json', replies)
            raise RuntimeError('notify_proto rejected: replay not tested')
        immediate.append(json.loads(run('ip', '-j', '-6', 'addr', 'show')))
        time.sleep(max(0, deadline + 2.2 - time.monotonic()))
        snapshots.append(snapshot(root, index))
    if args.natural_expiry:
        # No second notification: this must be handled by the daemon timer.
        time.sleep(max(0, schedule + 8.2 - time.monotonic()))
        snapshots.append(snapshot(root, 2))
    dump(out / 'immediate-addresses.json', immediate)
    dump(out / 'schedule-lateness-seconds.json', timing)
    dump(out / 'snapshots.json', snapshots)
    dump(out / 'replies.json', replies)
    shutil.copyfile(root / 'tmp/hotplug.txt', out / 'hotplug.txt')


def differences(a, b, path=''):
    # Only elapsed clocks are tolerated, with a two-second bound. Finite vs
    # infinite lifetimes, address flags, route expiry presence, and list order
    # are compared. No address/route/ifupdate content is filtered out.
    if type(a) is not type(b):
        return [path + ': type']
    if isinstance(a, dict):
        if a.keys() != b.keys():
            return [path + ': keys ' + str(sorted(a.keys() ^ b.keys()))]
        return [d for k in a for d in differences(a[k], b[k], path + '/' + k)]
    if isinstance(a, list):
        if path.endswith('/routes'):
            # rtnetlink dump order among equal-priority routes on different
            # devices is not routing priority. Compare the complete multiset;
            # retain duplicates and every field, excluding clocks only from
            # the sort key. Ubus assignment and policy-rule order stay strict.
            key = lambda row: json.dumps({k: v for k, v in row.items() if k != 'expires'}, sort_keys=True)
            a, b = sorted(a, key=key), sorted(b, key=key)
        if len(a) != len(b):
            return [path + ': lengths ' + str((len(a), len(b)))]
        return [d for i, (x, y) in enumerate(zip(a, b))
                for d in differences(x, y, path + '/' + str(i))]
    timed = path.rsplit('/', 1)[-1] in ('uptime', 'preferred', 'valid',
                                       'preferred_life_time', 'valid_life_time', 'expires')
    if timed and isinstance(a, (int, float)) and a > 0 and b > 0 and abs(a - b) <= 2:
        return []
    return [] if a == b else [path + ': values']


def main(args):
    if os.geteuid() != 0:
        raise RuntimeError('run with sudo: namespaces are mandatory')
    if args.out.exists():
        raise RuntimeError('output already exists; use a fresh directory')
    args.out.mkdir(parents=True)
    messages = extract(args.capture)
    cc = args.out / 'ns-exec'
    run('cc', '-O2', '-Wall', '-Wextra', '-Werror',
        str(Path(__file__).resolve().parents[1] / 'benchmark/ns_exec.c'), '-o', str(cc))
    for side in ('c', 'rs'):
        out = args.out / side
        out.mkdir()
        root = Path(tempfile.mkdtemp(prefix='health-netifd-')) / 'root'
        run('cp', '-a', str(args.rootfs), str(root))
        for directory in ('etc/config', 'var/run/ubus', 'var/lock', 'var/state'):
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root / 'etc/config/network').write_text(CONFIG)
        (root / 'etc/config/wireless').write_text('')
        (root / 'lib/netifd/proto/healthreplay.sh').write_text(PROTO)
        (root / 'lib/netifd/proto/healthreplay.sh').chmod(0o755)
        (root / 'sbin/hotplug-call').write_text('''#!/bin/sh
printf '%s %s %s %s %s\\n' "$ACTION" "$INTERFACE" "$IFUPDATE_ADDRESSES" "$IFUPDATE_ROUTES" "$IFUPDATE_PREFIXES" >> /tmp/hotplug.txt
''')
        (root / 'sbin/hotplug-call').chmod(0o755)
        shutil.copyfile(args.candidate, root / 'sbin/netifd-rs')
        (root / 'sbin/netifd-rs').chmod(0o755)
        run('chown', '-R', 'root:root', str(root / 'usr/share/acl.d'))
        cmd = [str(cc), sys.executable, str(Path(__file__).resolve()),
               '--side', side, '--root', str(root), '--out', str(out),
               '--capture', str(args.capture), '--dad', args.dad]
        if args.lifecycle:
            cmd.append('--lifecycle')
        if args.natural_expiry:
            cmd.append('--natural-expiry')
        result = subprocess.run(cmd, text=True, capture_output=True)
        (out / 'outer.log').write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f'{side} namespace failed; retained {root}')
        shutil.rmtree(root.parent)
    c = json.loads((args.out / 'c/snapshots.json').read_text())
    rs = json.loads((args.out / 'rs/snapshots.json').read_text())
    diff = differences(c, rs)
    hotplug_equal = (args.out / 'c/hotplug.txt').read_bytes() == (args.out / 'rs/hotplug.txt').read_bytes()
    replies_equal = (args.out / 'c/replies.json').read_bytes() == (args.out / 'rs/replies.json').read_bytes()
    offlink_nets = {str(ipaddress.ip_network(f"{a['ipaddr']}/{a['mask']}", strict=False))
                    for event in messages for a in event['ip6addr'] if a.get('offlink')}
    def protections(snapshot):
        return {'rules': [r for r in snapshot['rules'] if r.get('priority') == 4_200_000_000],
                'routes': [r for r in snapshot['routes']
                           if r.get('type') == 'unreachable' and r.get('dst') in offlink_nets]}
    reference_protections = [protections(s) for s in c]
    candidate_protections = [protections(s) for s in rs]
    protection_diff = differences(reference_protections, candidate_protections)
    if not reference_protections[1]['rules'] or not reference_protections[1]['routes']:
        raise RuntimeError('reference protection routes/rules never appeared: untested')
    if args.natural_expiry and (reference_protections[-1]['rules'] or c[-1]['wan6']['ipv6-prefix']):
        raise RuntimeError('reference did not expire the short PD: untested')
    summary = {'capture_sha256': sha(args.capture), 'candidate_sha256': sha(args.candidate),
               'reference_sha256': sha(args.rootfs / 'sbin/netifd'),
               'inputs': 1 if args.natural_expiry else len(messages),
               'captured_inputs': len(messages), 'natural_expiry': args.natural_expiry,
               'kernel_release': platform.release(), 'machine': platform.machine(),
               'snapshots_per_side': len(c), 'dad': args.dad, 'input_interval_seconds': 3,
               'lifecycle': args.lifecycle, 'differences': diff,
               'core_differences': differences(c[:14], rs[:14]),
               'protection_differences': protection_diff,
               'reference_source_rule_counts': [len(s['rules']) for s in reference_protections],
               'candidate_source_rule_counts': [len(s['rules']) for s in candidate_protections],
               'route_rule_differences': [d for i, (a, b) in enumerate(zip(c, rs))
                   for key in ('routes', 'rules') for d in differences(a[key], b[key], f'/{i}/{key}')], 'hotplug_equal': hotplug_equal,
               'replies_equal': replies_equal, 'lifetime_tolerance_seconds': 2,
               'addresses_per_input': [len(x['ip6addr']) for x in (messages[:1] if args.natural_expiry else messages)]}
    dump(args.out / 'summary.json', summary)
    print(json.dumps(summary, indent=2))
    return bool(diff or not hotplug_equal or not replies_equal)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rootfs', type=Path)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--side', choices=('c', 'rs'))
    parser.add_argument('--dad', choices=('on', 'off'), default='off')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--lifecycle', action='store_true')
    modes.add_argument('--natural-expiry', action='store_true')
    parser.add_argument('--root', type=Path)
    options = parser.parse_args()
    if options.side:
        inside(options)
    else:
        sys.exit(main(options))
