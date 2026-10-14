#!/usr/bin/env python3
"""Repeat the FIX7 initial-warm timeout scenario using the unchanged SOA flow."""
import argparse
import itertools
import json
import os
from pathlib import Path
import sys
import time

from negative_final import sha, strict_pair


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'image', 'fix', 'config-evidence', 'out'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--fix-sha256', required=True)
    a = p.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1' and os.geteuid() == 0
    assert 'private' in a.out.resolve().parts and sha(a.fix) == a.fix_sha256
    a.out.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(a.source / 'tools/dnsmasq'))
    import dhcp_negative_soa_boundaries as soa
    import dhcp_negative_cache_diff as base
    from m2_rootfs import prepare
    root = prepare(a.image, None, a.out, a.fix)
    config = json.loads(a.config_evidence.read_text())['config']
    (root / 'm2/dns.conf').write_text(config)
    case = dict(large=True, debug=False, host=base.HOST, transport='tcp', rd=True, do=False)
    report = dict(argv=sys.argv, started=time.time(), script_sha256=sha(__file__), fix_sha256=sha(a.fix),
                  c_sha256=sha(root / 'usr/sbin/dnsmasq'), case=case,
                  flow_sha256=sha(soa.__file__), base_driver_sha256=sha(base.__file__), runs=[])
    upstream = soa.Upstream()
    try:
        for i in range(10):
            folder = a.out / f'repeat{i:02d}'
            folder.mkdir()
            results = {side: soa.run(root, side, case, folder / side, upstream) for side in ('c', 'rust')}
            row = dict(name=folder.name, result_sha256=[sha(folder / side / 'result.json') for side in ('c', 'rust')],
                       daemon_argv=[json.loads((folder / side / 'command.json').read_text()) for side in ('c', 'rust')])
            try:
                row['comparison'] = strict_pair(results['c'], results['rust'])
            except Exception as error:
                row['error'] = repr(error)
            report['runs'].append(row)
            (a.out / 'checked.json').write_text(json.dumps(report, indent=2) + '\n')
            print(folder.name, 'PASS' if 'comparison' in row else row['error'], flush=True)
    finally:
        upstream.close()
    report.update(status='passed' if all('comparison' in r for r in report['runs']) else 'failed', finished=time.time())
    assert sha(a.fix) == report['fix_sha256']
    (a.out / 'checked.json').write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
