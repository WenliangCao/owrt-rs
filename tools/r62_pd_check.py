#!/usr/bin/env python3
"""Compare real PD snapshots, preserving lifetimes with a 3-second tolerance."""
import json
import re
import sys
from pathlib import Path
from audit_checks import object_json, require, sections

PHASES = ('before-any', 'first-grant', 'countdown', 'renewal', 'replaced', 'parent56', 'parent60',
          'delegate-off', 'delegate-on', 'after-down')


def compare(a, b, path=''):
    if isinstance(a, dict) and isinstance(b, dict):
        require(a.keys() == b.keys(), path + ': JSON keys differ')
        for k in a:
            if k == 'uptime' and path.endswith('status'):
                continue
            if k in ('preferred', 'valid') and isinstance(a[k], int) and isinstance(b[k], int):
                require(abs(a[k] - b[k]) <= 3, path + '.' + k + ': lifetime differs by >3 seconds')
            else:
                compare(a[k], b[k], path + '.' + k)
    elif isinstance(a, list) and isinstance(b, list):
        require(len(a) == len(b), path + ': list length differs')
        for i, (x, y) in enumerate(zip(a, b)):
            compare(x, y, f'{path}[{i}]')
    else:
        require(a == b, f'{path}: {a!r} != {b!r}')


def snapshots(path):
    raw = path.read_text()
    notifies = re.findall(r'^--- notify rc=(\d+) out=\[(.*)\]$', raw, re.M)
    require(len(notifies) == 5 and all(rc == '0' and not text for rc, text in notifies),
            str(path) + ': not all five prefix updates succeeded')
    obj = sections(re.sub(r'^--- notify[^\n]*\n', '', raw, flags=re.M))
    for phase in PHASES:
        for suffix in ('lan v6 addr', 'lan v6 route', 'prefix null route', 'wan6 status', 'lan status'):
            key = f'{phase} {suffix}'
            require(key in obj, str(path) + ': missing ' + key)
            if suffix.endswith('status'):
                obj[key] = object_json(obj[key])
        require(obj[f'{phase} lan status'].get('up') is True, str(path) + ': LAN never came up')
        require(obj[f'{phase} wan6 status'].get('up') is (phase != 'after-down'),
                str(path) + ': uplink not in the expected state')
    initial = obj['first-grant wan6 status'].get('ipv6-prefix', [])
    later = obj['countdown wan6 status'].get('ipv6-prefix', [])
    require(initial and later and len(initial) == len(later), str(path) + ': no delegated prefix reported')
    for first, last in zip(initial, later):
        require(3588 <= first.get('preferred', -1) < 3600 and 7188 <= first.get('valid', -1) < 7200,
                str(path) + ': reported grant is not a remaining lifetime')
        for key in ('preferred', 'valid'):
            require(1 <= first[key] - last.get(key, first[key]) <= 6,
                    str(path) + ': prefix lifetime did not count down')
    assigned = obj['first-grant lan status'].get('ipv6-prefix-assignment', [])
    counted = obj['countdown lan status'].get('ipv6-prefix-assignment', [])
    require(assigned and len(assigned) == len(counted), str(path) + ': no downstream assignment')
    for first, last in zip(assigned, counted):
        for key in ('preferred', 'valid'):
            require(1 <= first.get(key, -1) - last.get(key, -1) <= 6,
                    str(path) + ': assignment lifetime did not count down')
    addresses = obj['first-grant wan6 status'].get('ipv6-address', [])
    counted_addresses = obj['countdown wan6 status'].get('ipv6-address', [])
    require(len(addresses) == len(counted_addresses) == 1, str(path) + ': protocol address missing')
    for key in ('preferred', 'valid'):
        require(1 <= addresses[0].get(key, -1) - counted_addresses[0].get(key, -1) <= 6,
                str(path) + ': address lifetime did not count down')
    require(obj['delegate-off lan status'].get('ipv6-prefix-assignment') == [],
            str(path) + ': delegate=0 still assigned a downstream prefix')
    require(obj['delegate-on lan status'].get('ipv6-prefix-assignment'),
            str(path) + ': delegate=1 did not restore assignment')
    require('2001:db8' in obj['first-grant lan v6 addr'], str(path) + ': delegation never reached kernel')
    require('2001:db8' in obj['first-grant prefix null route'], str(path) + ': unreachable prefix route missing')
    require('2001:db8' not in obj['after-down prefix null route'], str(path) + ': prefix route survived withdrawal')
    return obj


def main(out):
    a, b = snapshots(out / 'c.txt'), snapshots(out / 'rs.txt')
    require(a.keys() == b.keys(), 'snapshot sections differ')
    for key in a:
        if key.endswith('status'):
            compare(a[key], b[key], key)
        else:
            # Kernel counters remain in the transcript. Compare every lifetime
            # numerically, then all remaining bytes, including deprecation flags.
            pattern = r'(?:valid_lft|preferred_lft) (\d+)sec'
            av, bv = re.findall(pattern, a[key]), re.findall(pattern, b[key])
            require(len(av) == len(bv) and all(abs(int(x)-int(y)) <= 3 for x, y in zip(av, bv)),
                    key + ': kernel lifetimes differ by >3 seconds')
            require(re.sub(pattern, 'lifetime <seconds>', a[key]) == re.sub(pattern, 'lifetime <seconds>', b[key]),
                    key + ': kernel state differs')
    print('r62: prefix and assignment countdown, withdrawal and kernel state match (lifetime tolerance 3s)')


if __name__ == '__main__':
    try:
        main(Path(sys.argv[1]))
    except (OSError, ValueError, KeyError) as error:
        print('r62: FAILED:', error, file=sys.stderr)
        sys.exit(1)
