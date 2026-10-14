#!/usr/bin/env python3
"""Fresh retained-SOA + large local terminal owner boundary experiment.

Uses the unchanged DHCP/SOA flow, replacing only the last query with ANY and
adding normal TXT/MX configuration. Raw packets and logs remain private.
"""
import argparse
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'image', 'fix', 'config-evidence', 'out'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--fix-sha256', required=True)
    p.add_argument('--tails', default='184,192,211')
    a = p.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1' and os.geteuid() == 0
    assert 'private' in a.out.resolve().parts
    assert sha(a.fix) == a.fix_sha256
    a.out.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(a.source / 'tools/dnsmasq'))
    import dhcp_negative_soa_boundaries as soa
    import dhcp_negative_cache_diff as base
    from dns_service_probe import exact_read, query, semantics
    from m2_rootfs import prepare
    from negative_final import decode, strict_pair
    from checker_calibration import records
    root = prepare(a.image, None, a.out, a.fix)
    original_ask = soa.ask

    def ask(host, ident, transport, **kwargs):
        if ident != 0x6003:
            return original_ask(host, ident, transport, **kwargs)
        request = query(host, 255, ident)
        started = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect(('127.0.0.1', 15353))
            sock.sendall(struct.pack('!H', len(request)) + request)
            response = exact_read(sock, struct.unpack('!H', exact_read(sock, 2))[0])
        try:
            reply = semantics(response)
        except Exception as error:
            reply = dict(decode_error=repr(error))
        return dict(started=started, ended=time.monotonic(), request=request.hex(),
                    packet=response.hex(), reply=reply)

    soa.ask = ask
    upstream = soa.Upstream()
    report = dict(script_sha256=sha(__file__), fix_sha256=sha(a.fix), c_sha256=sha(root / 'usr/sbin/dnsmasq'),
                  config_evidence_sha256=sha(a.config_evidence), runs=[])
    initial_config = json.loads(a.config_evidence.read_text())['config']
    try:
        for tail, debug in itertools.product(tuple(map(int, a.tails.split(','))), (False, True)):
            label = f'tail{tail}-debug{int(debug)}-tcp'
            folder = a.out / label
            folder.mkdir()
            config = initial_config + ('no-round-robin\nhost-record=leases.test,192.0.2.20\n'
                       'mx-host=client1.leases.test,leases.test,10\n')
            config += ''.join('txt-record=client1.leases.test,' + f'{i:03d}' + 'x' * 252 + '\n' for i in range(60))
            config += 'txt-record=client1.leases.test,' + 'z' * tail + '\n'
            (folder / 'config.txt').write_text(config)
            (root / 'm2/dns.conf').write_text(config)
            case = dict(large=False, debug=debug, host=soa.ALIAS, transport='tcp', rd=True, do=False)
            results = {side: soa.run(root, side, case, folder / side, upstream) for side in ('c', 'rust')}
            row = dict(name=label, case=case, tail=tail, config_sha256=sha(folder / 'config.txt'), sides={})
            for side, result in results.items():
                final = next((e for e in result['events'] if e['label'] == 'boundary'), None)
                parsed = None
                try:
                    assert final is not None, result.get('error')
                    packet = bytes.fromhex(final['packet'])
                    parsed = decode(packet)
                    layout = list(records(packet))
                    details = dict(length=len(packet), header=parsed['header'],
                        types=[{'section': r['section'], 'type': r['type'], 'ttl': r['ttl']} for r in parsed['records']],
                        mx_targets=[r['data'] + 2 for r in layout if r['type'] == 15],
                        additional_owners=[packet[r['start']:r['fixed']].hex() for r in layout if r['section'] == 'additional'])
                except Exception as error:
                    details = dict(decode_error=repr(error))
                row['sides'][side] = dict(status=result['status'], error=result.get('error'), final=details,
                    result_sha256=sha(folder / side / 'result.json'), command=json.loads((folder / side / 'command.json').read_text()))
            try:
                row['comparison'] = strict_pair(results['c'], results['rust'])
            except Exception as error:
                row['comparison_error'] = repr(error)
            report['runs'].append(row)
            (a.out / 'checked.json').write_text(json.dumps(report, indent=2) + '\n')
            print(label, 'PASS' if 'comparison' in row else row['comparison_error'], flush=True)
    finally:
        upstream.close()
    assert sha(a.fix) == report['fix_sha256']
    report['status'] = 'passed' if all('comparison' in r for r in report['runs']) else 'failed'
    (a.out / 'checked.json').write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
