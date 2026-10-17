#!/usr/bin/env python3
"""Compare renewal kernel writes with pinned C netifd, in Linux namespaces.

Counts actual netlink sendmsg/sendto requests with strace, not notifications:
the kernel may suppress a notification for a redundant CREATE|REPLACE write.
Only synthetic addresses/configuration are used; no router is contacted.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


CONFIG = """config interface 'loopback'
 option device 'lo'
 option proto 'static'
 option ipaddr '127.0.0.1/8'
config interface 'wan'
 option device 'wan'
 option proto 'renewaltest'
"""
PROTO = """#!/bin/sh
. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"
proto_renewaltest_init_config() { :; }
proto_renewaltest_setup() {
 proto_init_update "$2" 1
 proto_send_update "$1"
}
proto_renewaltest_teardown() { :; }
add_protocol renewaltest
"""
KINDS = ('RTM_NEWADDR', 'RTM_DELADDR', 'RTM_NEWROUTE', 'RTM_DELROUTE')
C_SHA256 = '8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90'


def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True).stdout


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def writes(trace):
    text = trace.read_text() if trace.exists() else ''
    return {kind: len(re.findall('nlmsg_type=' + kind + r'[,}]', text)) for kind in KINDS}


def inside(args):
    root, out = args.root, args.out
    run('mount', '-t', 'sysfs', 'sysfs', '/sys')
    run('mount', '-t', 'proc', 'proc', str(root / 'proc'))
    run('mount', '-t', 'sysfs', 'sysfs', str(root / 'sys'))
    run('mount', '-t', 'tmpfs', '-o', 'mode=1777', 'tmpfs', str(root / 'dev'))
    for name, minor in (('null', 3), ('zero', 5), ('urandom', 9)):
        run('mknod', '-m', '666', str(root / 'dev' / name), 'c', '1', str(minor))
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'add', 'wan', 'address', '02:00:00:00:00:10',
        'type', 'veth', 'peer', 'name', 'peer')
    for dev in ('default', 'wan', 'peer'):
        Path('/proc/sys/net/ipv6/conf', dev, 'accept_dad').write_text('0')
        Path('/proc/sys/net/ipv6/conf', dev, 'addr_gen_mode').write_text('1')
    for dev in ('wan', 'peer'):
        run('ip', 'link', 'set', dev, 'up')
    with (out / 'ubusd.log').open('w') as log:
        subprocess.Popen(['chroot', str(root), '/sbin/ubusd'], stdout=log, stderr=log)
    time.sleep(0.3)
    trace = out / 'netlink.trace'
    executable = '/sbin/netifd' if args.side == 'c' else '/sbin/netifd-rs'
    with (out / 'netifd.log').open('w') as log:
        subprocess.Popen(['strace', '-qq', '-v', '-s', '8192', '-e',
                          'trace=sendto,sendmsg', '-o', str(trace),
                          'chroot', str(root), executable, '-S'], stdout=log, stderr=log)

    def bus(method, data=None, obj='network.interface.wan'):
        return json.loads(run('chroot', str(root), 'ubus', 'call', obj,
                              method, json.dumps(data or {})) or '{}')

    for _ in range(100):
        try:
            if bus('status').get('up'):
                break
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(0.1)
    else:
        raise RuntimeError('test protocol did not reach UP')
    time.sleep(0.3)
    results = []

    def step(label, event, expected_addrs, expected_routes, compare=True):
        before = writes(trace)
        bus('notify_proto', {'action': 0, 'link-up': True, **event})
        time.sleep(0.05)
        after = writes(trace)
        delta = {k: after[k] - before[k] for k in KINDS}
        result = {'label': label, 'writes': delta, 'compare_kernel': compare,
                  'addresses': json.loads(run('ip', '-j', 'addr', 'show', 'dev', 'wan'))[0]['addr_info'],
                  'routes': json.loads(run('ip', '-j', 'route', 'show', 'table', 'all', 'dev', 'wan')),
                  'routes6': json.loads(run('ip', '-j', '-6', 'route', 'show', 'table', 'all', 'dev', 'wan')),
                  'status': bus('status')}
        results.append(result)
        save(out / 'results.json', results)
        if delta['RTM_NEWADDR'] != expected_addrs or delta['RTM_NEWROUTE'] != expected_routes:
            raise AssertionError(f'{label}: expected NEWADDR/NEWROUTE {expected_addrs}/{expected_routes}; got {delta}')
        if label == 'address-install-failure' and result['addresses']:
            raise AssertionError('disabled IPv6 did not produce a real address install failure')
        if label == 'route-install-failure' and any(r.get('dst') == '198.18.0.0/24' for r in result['routes']):
            raise AssertionError('unreachable gateway did not produce a real route install failure')
        if label.endswith('retry') and not (args.side == 'c' and label == 'address-reload-failure-retry'):
            for address in event.get('ip6addr', []):
                if not any(a.get('local') == address['ipaddr'] for a in result['addresses']):
                    raise AssertionError(f'{label}: retry did not restore the kernel address')
            for route in event.get('routes', []):
                if not any(r.get('dst') == route['target'] for r in result['routes']):
                    raise AssertionError(f'{label}: retry did not restore the kernel route')

    base = {'ipaddr': [{'ipaddr': '192.0.2.2', 'mask': '24'}],
            'routes': [{'target': '0.0.0.0', 'netmask': '0', 'gateway': '192.0.2.1'}]}
    step('initial', base, 1, 1)
    for i in range(7):
        step(f'identical-renewal-{i + 1}', base, 0, 0)
    step('keep-flag-renewal', {**base, 'keep': True}, 0, 0)
    explicit = copy.deepcopy(base)
    explicit['ipaddr'][0]['broadcast'] = '192.0.2.255'
    step('explicit-default-broadcast', explicit, 0, 0)
    changed = copy.deepcopy(base)
    changed['routes'][0]['gateway'] = '192.0.2.3'
    step('changed-gateway', changed, 0, 1)
    step('changed-gateway-repeat', changed, 0, 0)
    changed['routes'][0].update(proto='boot', mtu=1400)
    step('changed-route-proto-mtu', changed, 0, 1)
    step('changed-route-proto-mtu-repeat', changed, 0, 0)
    changed['ipaddr'][0]['broadcast'] = '192.0.2.127'
    step('changed-broadcast', changed, 1, 0)
    step('changed-broadcast-repeat', changed, 0, 0)
    changed['ipaddr'][0]['ptp'] = '192.0.2.4'
    step('changed-peer', changed, 1, 0)
    step('changed-peer-repeat', changed, 0, 0)

    v6 = {'ip6addr': [{'ipaddr': '2001:db8::2', 'mask': '64', 'offlink': True,
                       'preferred': 120, 'valid': 240}]}
    step('v6-finite-initial', v6, 1, 1)
    time.sleep(1.1)
    step('v6-lifetime-renewal', v6, 1, 0)
    infinite = copy.deepcopy(v6)
    infinite['ip6addr'][0].update(preferred=4294967295, valid=4294967295)
    step('v6-infinite-transition', infinite, 1, 0)
    step('v6-infinite-repeat', infinite, 0, 0)
    expiring = copy.deepcopy(v6)
    expiring['ip6addr'][0].update(preferred=1, valid=2)
    step('v6-short-lifetime', expiring, 1, 0)
    time.sleep(3.1)
    if any(a.get('local') == '2001:db8::2' for a in
           json.loads(run('ip', '-j', 'addr', 'show', 'dev', 'wan'))[0]['addr_info']):
        raise AssertionError('short-lived IPv6 address did not expire in the kernel')
    step('v6-expired-reinstall', infinite, 1, 1 if args.side == 'c' else 0)
    step('v6-expired-reinstall-repeat', infinite, 0, 0)

    # A failed first install must not be remembered as successfully applied.
    Path('/proc/sys/net/ipv6/conf/wan/disable_ipv6').write_text('1')
    failed = {'ip6addr': [{'ipaddr': '2001:db8:1::2', 'mask': '128'}]}
    step('address-install-failure', failed, 1, 0, compare=False)
    Path('/proc/sys/net/ipv6/conf/wan/disable_ipv6').write_text('0')
    step('address-install-retry', failed, 1, 0)
    step('address-install-retry-repeat', failed, 0, 0)

    # reload_ip retains state after a failed re-apply. Its failure flag must
    # force the next identical lease to restore the kernel address.
    Path('/proc/sys/net/ipv6/conf/wan/disable_ipv6').write_text('1')
    run('chroot', str(root), 'uci', 'set', 'network.wan.metric=10')
    run('chroot', str(root), 'uci', 'commit', 'network')
    bus('reload', obj='network')
    time.sleep(0.2)
    Path('/proc/sys/net/ipv6/conf/wan/disable_ipv6').write_text('0')
    # The pinned C set_enabled path ignores add_address's return value and
    # therefore misses this retry. Rust preserves its previous retry behavior.
    step('address-reload-failure-retry', failed,
         0 if args.side == 'c' else 1, 0 if args.side == 'c' else 1, compare=False)
    step('address-reload-failure-repeat', failed, 0, 0, compare=False)
    run('chroot', str(root), 'uci', 'set', 'network.wan.metric=0')
    run('chroot', str(root), 'uci', 'commit', 'network')
    bus('reload', obj='network')
    time.sleep(0.2)

    unreachable = {'routes': [{'target': '198.18.0.0/24', 'gateway': '198.51.100.1', 'metric': 42}]}
    step('route-install-failure', unreachable, 0, 1, compare=False)
    run('ip', 'addr', 'add', '198.51.100.2/24', 'dev', 'wan')
    step('route-install-retry', unreachable, 0, 1)
    step('route-install-retry-repeat', unreachable, 0, 0)
    run('ip', 'addr', 'del', '198.51.100.2/24', 'dev', 'wan')
    run('chroot', str(root), 'uci', 'set', 'network.wan.metric=10')
    run('chroot', str(root), 'uci', 'commit', 'network')
    bus('reload', obj='network')
    time.sleep(0.2)
    run('ip', 'addr', 'add', '198.51.100.2/24', 'dev', 'wan')
    step('route-reload-failure-retry', unreachable, 0, 1)
    step('route-reload-failure-repeat', unreachable, 0, 0)
    step('withdraw-all', {}, 0, 0)
    duplicates = {'ipaddr': [{'ipaddr': '203.0.113.2', 'mask': '24'}] * 2}
    step('same-address-distinct-indices', duplicates, 2, 2)
    step('same-address-distinct-indices-repeat', duplicates, 0, 0)
    step('same-address-distinct-indices-keep', {**duplicates, 'keep': True}, 0, 0)
    if len(bus('status')['ipv4-address']) != 2:
        raise AssertionError('distinct vlist indices were collapsed')
    step('withdraw-duplicates', {}, 0, 0)


def normalized(rows):
    # Compare every kernel field except remaining lifetime clocks. Zero and
    # infinity stay distinct; finite positive lifetimes are tested by writes.
    def normalize(value):
        if isinstance(value, dict):
            return {k: ('finite' if k in ('valid_life_time', 'preferred_life_time', 'expires')
                        and isinstance(v, (int, float)) and 0 < v < 4294967295
                        else normalize(v)) for k, v in value.items()}
        if isinstance(value, list):
            return sorted((normalize(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
        return value
    return normalize(rows)


def main(args):
    if os.geteuid() != 0 or sys.platform != 'linux':
        raise RuntimeError('requires Linux root and isolated namespaces')
    if hashlib.sha256((args.rootfs / 'sbin/netifd').read_bytes()).hexdigest() != C_SHA256:
        raise RuntimeError('C reference is not the pinned OpenWrt image netifd')
    args.out.mkdir(parents=True, exist_ok=False)
    launcher = args.out / 'ns-exec'
    run('cc', '-O2', '-Wall', '-Wextra', '-Werror',
        str(Path(__file__).resolve().parent / 'benchmark/ns_exec.c'), '-o', str(launcher))
    for side in ('c', 'rs'):
        out = args.out / side
        out.mkdir()
        root = Path(tempfile.mkdtemp(prefix='netifd-keep-')) / 'root'
        run('cp', '-a', str(args.rootfs), str(root))
        for directory in ('etc/config', 'var/run/ubus', 'var/lock', 'var/state'):
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root / 'etc/config/network').write_text(CONFIG)
        (root / 'etc/config/wireless').write_text('')
        (root / 'lib/netifd/proto/renewaltest.sh').write_text(PROTO)
        (root / 'lib/netifd/proto/renewaltest.sh').chmod(0o755)
        (root / 'sbin/hotplug-call').write_text('#!/bin/sh\nexit 0\n')
        (root / 'sbin/hotplug-call').chmod(0o755)
        shutil.copyfile(args.candidate, root / 'sbin/netifd-rs')
        (root / 'sbin/netifd-rs').chmod(0o755)
        run('chown', '-R', 'root:root', str(root / 'usr/share/acl.d'))
        result = subprocess.run([str(launcher), sys.executable, str(Path(__file__).resolve()),
                                 '--side', side, '--root', str(root), '--out', str(out)],
                                text=True, capture_output=True)
        (out / 'outer.log').write_text(result.stdout + result.stderr)
        shutil.rmtree(root.parent)
        if result.returncode:
            raise RuntimeError(f'{side} test failed; see {out}/outer.log')
    c, rs = [json.loads((args.out / side / 'results.json').read_text()) for side in ('c', 'rs')]
    differences = []
    for old, new in zip(c, rs, strict=True):
        if old['label'] != new['label']:
            raise AssertionError('case alignment failed')
        if old['compare_kernel']:
            for key in ('addresses', 'routes', 'routes6'):
                if normalized(old[key]) != normalized(new[key]):
                    differences.append(old['label'] + '/' + key)
    summary = {'cases': len(c), 'kernel_differences': differences,
               'kernel_compared_cases': sum(r['compare_kernel'] for r in c),
               'c_sha256': C_SHA256,
               'candidate_sha256': hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
               'identical_renewals': 7,
               'c_identical_writes': {k: sum(r['writes'][k] for r in c[1:8]) for k in KINDS},
               'rs_identical_writes': {k: sum(r['writes'][k] for r in rs[1:8]) for k in KINDS},
               'reload_address_failure_retry': {
                   side: next(r['writes'] for r in rows if r['label'] == 'address-reload-failure-retry')
                   for side, rows in [('c', c), ('rs', rs)]}}
    save(args.out / 'summary.json', summary)
    print(json.dumps(summary, sort_keys=True))
    if differences:
        raise AssertionError('kernel state differs from pinned C')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--side', choices=('c', 'rs'))
    parser.add_argument('--root', type=Path)
    arguments = parser.parse_args()
    inside(arguments) if arguments.side else main(arguments)
