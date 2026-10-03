#!/usr/bin/env python3
"""Local-record family differential in an isolated exact-image rootfs.

Run via run_isolated.sh. C runs first and supplies every expected outcome.
The schedule preserves record/section order; only DNS name compression is
normalized. Failed attempts and all raw requests/replies remain in private/.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from dns_service_probe import Upstream, exact_read, name, read_name, semantics
from m2_rootfs import prepare, command, image_path, sha256, STOCK_SHA256

LISTEN = ('127.0.0.1', 15353)
BASE = ('no-hosts\nno-resolv\nport=15353\nlisten-address=127.0.0.1\n'
        'user=root\ngroup=root\nlocal-ttl=37\ncache-size=50\n'
        'host-record=ready.m5.test,192.0.2.254\nlocal=/m5.test/\n')


def decoded(packet):
    result = semantics(packet)
    # The common decoder treats other RDATA as opaque, which would compare
    # legal compressed/uncompressed MX/SRV/NAPTR spelling rather than semantics.
    pos = 12
    _, _, qd, an, ns, ar = struct.unpack_from('!6H', packet)
    for _ in range(qd):
        _, pos = read_name(packet, pos)
        pos += 4
    for row in result['records']:
        _, pos = read_name(packet, pos)
        kind, _, _, size = struct.unpack_from('!HHIH', packet, pos)
        pos += 10
        end = pos + size
        if kind == 15:
            row['data'] = [struct.unpack_from('!H', packet, pos)[0], read_name(packet, pos + 2)[0]]
        elif kind == 33:
            row['data'] = [*struct.unpack_from('!3H', packet, pos), read_name(packet, pos + 6)[0]]
        elif kind == 35:
            values = list(struct.unpack_from('!2H', packet, pos))
            cursor = pos + 4
            for _ in range(3):
                size = packet[cursor]
                cursor += 1
                values.append(packet[cursor:cursor + size].hex())
                cursor += size
            values.append(read_name(packet, cursor)[0])
            row['data'] = values
        pos = end
    return result


def profiles(hostname):
    records = ('host-record=host.m5.test,alias-host.m5.test,192.0.2.21,2001:db8::21,61\n'
               'host-record=multi.m5.test,192.0.2.22\nhost-record=multi.m5.test,192.0.2.23\n'
               'host-record=collision.m5.test,192.0.2.24\ncname=collision.m5.test,host.m5.test,19\n'
               'cname=chain.m5.test,collision.m5.test,17\ncname=orphan.m5.test,missing.m5.test\n'
               'txt-record=text.m5.test,first\ntxt-record=text.m5.test,"second,field",third\n'
               'ptr-record=custom.m5.test,first.m5.test\nptr-record=custom.m5.test,second.m5.test\n'
               'ptr-record=root.m5.test\ndns-rr=raw.m5.test,65401,01:02\ndns-rr=raw.m5.test,65401,03:04\n'
               'caa-record=raw.m5.test,0,issue,ca.m5.test\n'
               'naptr-record=nap.m5.test,1,2,"S","SIP+D2U","",_sip._udp.m5.test\n'
               'naptr-record=nap.m5.test,3,4,"U","SIP+D2U","",other.m5.test\n')
    names = [('host.m5.test', 1), ('host.m5.test', 28), ('host.m5.test', 255),
             ('alias-host.m5.test', 1), ('21.2.0.192.in-addr.arpa', 12),
             ('multi.m5.test', 1), ('multi.m5.test', 1), ('collision.m5.test', 1),
             ('chain.m5.test', 1), ('chain.m5.test', 5), ('orphan.m5.test', 1),
             ('text.m5.test', 16), ('custom.m5.test', 12), ('root.m5.test', 12),
             ('raw.m5.test', 255), ('nap.m5.test', 35)]
    names += [('text.m5.test', 16, 3), ('host.m5.test', 1, 3), ('missing.m5.test', 1), ('collision.m5.test', 255)]
    yield 'records', records, names
    yield 'host-record-ttl', ''.join(f'host-record=ttl{ttl}.m5.test,192.0.2.80,{ttl}\n' for ttl in [2147483647, 2147483648, 4294967295]), [(f'ttl{ttl}.m5.test', 1) for ttl in [2147483647, 2147483648, 4294967295]]
    mx = (f'mx-host=default.m5.test\nmx-host=mail.m5.test,a.m5.test,10\n'
          'mx-host=mail.m5.test,b.m5.test,20\nmx-host=mail.m5.test,a.m5.test,30\n'
          'host-record=a.m5.test,192.0.2.31,2001:db8::31,71\n'
          'host-record=b.m5.test,192.0.2.32,2001:db8::32,72\n'
          'cname=mail-alias.m5.test,mail.m5.test\n')
    lease = ('no-ping\ndhcp-authoritative\ndhcp-leasefile=/m2/leases\n'
             'dhcp-range=127.0.0.10,127.0.0.30,255.0.0.0,600s\ndomain=m5.test\ndhcp-ttl=60\n'
             'cname=lease.m5.test,host.m5.test,19\nhost-record=host.m5.test,192.0.2.71\n'
             'host-record=fixed.m5.test,127.0.0.22\nhost-record=same.m5.test,127.0.0.12\n'
             'cname=lease-alias.m5.test,free.m5.test,17\nmx-host=lease-mail.m5.test,free.m5.test\n')
    yield 'lease-records', lease, [('lease.m5.test', 1), ('lease', 1), ('fixed.m5.test', 1),
        ('fixed', 1), ('same.m5.test', 1), ('free.m5.test', 1), ('lease-alias.m5.test', 1),
        ('lease-mail.m5.test', 15), ('10.0.0.127.in-addr.arpa', 12), ('11.0.0.127.in-addr.arpa', 12)]
    yield 'mx', mx, [('mail.m5.test', 15), ('mail-alias.m5.test', 15), ('default.m5.test', 15)]
    for mode in ['mx-target=a.m5.test', 'localmx', 'selfmx', 'localmx\nselfmx']:
        yield mode.replace('=', '-').replace('\n', '-'), mode + '\n' + mx, [
            (hostname, 15), ('a.m5.test', 15), ('mail.m5.test', 15), ('default.m5.test', 15)]
    srv = ('domain=m5.test\nsrv-host=_sip._tcp,a.m5.test,5060,3,5\n'
           'srv-host=_sip._tcp,b.m5.test,5061,1,7\nsrv-host=_sip._tcp,c.m5.test,5062,2,9\n'
           'srv-host=_empty._tcp\nsrv-host=_root._tcp,.\n'
           'host-record=a.m5.test,192.0.2.41\nhost-record=b.m5.test,192.0.2.42\n'
           'host-record=c.m5.test,192.0.2.43\ncname=srv-alias.m5.test,_sip._tcp.m5.test\n')
    yield 'srv', srv, [('_sip._tcp.m5.test', 33)] * 4 + [('srv-alias.m5.test', 33),
                     ('_empty._tcp.m5.test', 33), ('_root._tcp.m5.test', 33)]
    yield 'srv-no-round-robin', 'no-round-robin\n' + srv, [('_sip._tcp.m5.test', 33)] * 4
    yield 'dynamic-additional', 'mx-host=dynamic-mail.m5.test,cache-target.example\n', [
        ('dynamic-mail.m5.test', 15), ('dynamic-mail.m5.test', 15)]
    # Optional Additional data cannot turn an otherwise fitting answer into TC.
    overflow = 'mx-host=large.m5.test,many.m5.test\n'
    overflow += ''.join(f'host-record=many.m5.test,192.0.2.{n}\n' for n in range(1, 61))
    overflow += 'txt-record=large-txt.m5.test,' + 'a' * 1500 + '\n'
    for size in [0, 255, 256]:
        overflow += f'txt-record=txt{size}.m5.test,' + 'b' * size + '\n'
    yield 'bounds', overflow, [('large.m5.test', 15), ('large-txt.m5.test', 16), *[(f'txt{size}.m5.test', 16) for size in [0, 255, 256]]]


def packet(host, kind, ident, cls=1):
    return struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + name(host) + struct.pack('!HH', kind, cls)


def exchange(request, transport, stream=None):
    if transport == 'tcp':
        stream.sendall(struct.pack('!H', len(request)) + request)
        return exact_read(stream, struct.unpack('!H', exact_read(stream, 2))[0])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(2)
        udp.sendto(request, LISTEN)
        return udp.recv(65535)


def parse_configs(root, side, out):
    cases = [
        'cname=a.test,b.test\ncname=b.test,a.test',
        'cname=a.test,b.test\ncname=A.test,c.test',
        'cname=a.test,b.test,c.test,19',
        'mx-host=mail.test', 'mx-host=mail.test,target.test,65535',
        'mx-host=mail.test,target.test,65536', 'mx-host=mail.test,target.test,-1',
        'srv-host=_srv._tcp', 'srv-host=_srv._tcp,.,65535,65535,65535',
        'srv-host=_srv._tcp,target.test,65536',
        'srv-host=_srv._tcp,target.test,12,65536',
        'srv-host=_srv._tcp,target.test,12,1,65536',
        'ptr-record=root.test', 'txt-record=text.test,',
        'txt-record=text.test,"comma,kept",second',
        'host-record=a.test,b.test,192.0.2.1,2001:db8::1,17',
        'host-record=a.test', *[f'host-record=a.test,192.0.2.1,{ttl}' for ttl in [2147483647,2147483648,4294967295]],
        'dns-rr=raw.test,65401,aa:bb', 'dns-rr=raw.test,65401,gg',
        'caa-record=caa.test,0,issue,ca.test', 'caa-record=caa.test,0,issue',
        'naptr-record=n.test,1,2,"S","SIP+D2U","",target.test',
    ]
    result = []
    corpus = out / 'config-corpus'
    corpus.mkdir(exist_ok=True)
    for index, text in enumerate(cases):
        (root / 'm2/parse.conf').write_text(BASE + text + '\n')
        completed = subprocess.run(command(root, side, '--test', '-C', '/m2/parse.conf'),
                                   capture_output=True, timeout=3)
        (out / f'parse-{index:02d}.stdout').write_bytes(completed.stdout)
        (out / f'parse-{index:02d}.stderr').write_bytes(completed.stderr)
        (corpus / f'parse-{index:02d}').write_bytes(text.encode())
        result.append({'input': text, 'exit': completed.returncode})
    return result


def run(args, side, out):
    root = prepare(args.image_root, None, out, args.rust)
    rows, processes = [], []
    hostname = socket.gethostname()
    for profile, extra, questions in profiles(hostname):
        upstream = Upstream() if profile == 'dynamic-additional' else None
        config = BASE + extra + (f'server=127.0.0.1#{upstream.port}\n' if upstream else '')
        work = out / profile
        work.mkdir()
        (root / 'm2/local.conf').write_text(config)
        if profile == 'lease-records':
            content = ''.join(f'0 02:00:00:00:00:{n:02x} 127.0.0.{n} {host} *\n'
                              for n, host in [(10, 'lease'), (11, 'fixed'), (12, 'same'), (13, 'free')])
            (root / 'm2/leases').write_text(content)
            (work / 'input.leases').write_text(content)
        (work / 'config').write_text(config)
        corpus = out / 'config-corpus'
        corpus.mkdir(exist_ok=True)
        (corpus / f'{profile}-complete').write_bytes(extra.encode())
        for index, line in enumerate(extra.splitlines()):
            (corpus / f'{profile}-{index:03d}').write_bytes(line.encode())
        log = (work / 'daemon.log').open('wb')
        process = subprocess.Popen(command(root, side, '-k', '-C', '/m2/local.conf'),
                                   stdout=log, stderr=log, start_new_session=True)
        stream = None
        try:
            deadline = time.monotonic() + 3
            while True:
                try:
                    exchange(packet('ready.m5.test', 1, 1), 'udp')
                    break
                except (socket.timeout, ConnectionError, OSError):
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError(f'{side}/{profile} startup failed')
            if upstream:
                for kind in [1, 28]:
                    exchange(packet('cache-target.example', kind, 2 + kind), 'udp')
            for transport in ['udp', 'tcp']:
                if transport == 'tcp':
                    stream = socket.create_connection(LISTEN, timeout=3)
                for question in questions:
                    host, kind, *classes = question
                    cls = classes[0] if classes else 1
                    request = packet(host, kind, 100 + len(rows), cls)
                    reply = exchange(request, transport, stream)
                    row = {'profile': profile, 'transport': transport, 'question': [host, kind, cls],
                           'request': request.hex(), 'response': reply.hex(), 'semantic': decoded(reply)}
                    assert reply[:2] == request[:2], 'transaction ID changed'
                    rows.append(row)
                    corpus = out / 'dns-corpus'
                    corpus.mkdir(exist_ok=True)
                    (corpus / f'{len(rows):04d}-query').write_bytes(request)
                    (corpus / f'{len(rows):04d}-reply').write_bytes(reply)
                if stream:
                    stream.close()
                    stream = None
        finally:
            if stream:
                stream.close()
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            forced = False
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                forced = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(3)
            log.close()
            if upstream:
                upstream.close()
                processes.append({'profile': profile, 'upstream_counts': [[host, kind, count] for (host, kind), count in sorted(upstream.counts.items())], 'upstream_failures': upstream.failures})
            remaining = []
            for candidate in Path('/proc').iterdir():
                if not candidate.name.isdigit() or int(candidate.name) == os.getpid():
                    continue
                try:
                    if (candidate / 'root').resolve() == root.resolve():
                        remaining.append(int(candidate.name))
                except (FileNotFoundError, PermissionError):
                    pass
            # Preserve the pre-cleanup observation even if forced recovery works.
            for pid in remaining:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            pid_path = image_path(root, 'var/run/dnsmasq.pid')
            processes.append({'profile': profile, 'exit': process.returncode, 'forced': forced,
                              'remaining_before_cleanup': remaining,
                              'pid_file_removed': not pid_path.exists()})
            if profile == 'lease-records':
                contents = (root / 'm2/leases').read_text()
                (work / 'output.leases').write_text(contents)
                processes.append({'profile': profile, 'leases': sorted(contents.splitlines())})
            (out / 'trace.json').write_text(json.dumps({'rows': rows, 'processes': processes}, indent=2) + '\n')
    assert all(p.get('exit', 0) == 0 and not p.get('forced', False) and not p.get('upstream_failures') and not p.get('remaining_before_cleanup') and p.get('pid_file_removed', True) for p in processes), processes
    result = {'rows': rows, 'processes': processes, 'parse_rows': parse_configs(root, side, out)}
    (out / 'trace.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def compare(left, right):
    fields = ['profile', 'transport', 'question', 'semantic']
    a = [{k: r[k] for k in fields} for r in left['rows']]
    b = [{k: r[k] for k in fields} for r in right['rows']]
    differences = [{'row': n, 'c': x, 'rust': y} for n, (x, y) in enumerate(zip(a, b)) if not same_row(x, y)]
    reference_differences = []
    parse_matches = 0
    for c_row, rust_row in zip(left.get('parse_rows', []), right.get('parse_rows', [])):
        if c_row == rust_row:
            parse_matches += 1
        elif (c_row['input'] == rust_row['input'] == 'dns-rr=raw.test,65401,gg'
              and c_row['exit'] == 4 and rust_row['exit'] == 1):
            # Confirmed twice before classifying: exact 64-bit C promotes -1
            # from parse_hex to size_t, then compares with 32-bit -1U. Rust
            # rejects the syntax normally; it never attempts that allocation.
            reference_differences.append({'case': c_row['input'], 'c': c_row, 'rust': rust_row,
                'source': 'option.c dns-rr parse_hex size_t/-1U error check',
                'behavior': 'C reports allocation failure; Rust reports invalid hexadecimal configuration'})
        else:
            differences.append({'parse_c': c_row, 'parse_rust': rust_row})
    if left['processes'] != right['processes']:
        differences.append({'processes_c': left['processes'], 'processes_rust': right['processes']})
    return {'compared': min(len(a), len(b)),
            'unexecuted': abs(len(a) - len(b)) + abs(len(left.get('parse_rows', [])) - len(right.get('parse_rows', []))),
            'differences': differences, 'parse_matches': parse_matches,
            'reference_differences': reference_differences}


def same_row(left, right):
    if left['profile'] != 'dynamic-additional' or right['profile'] != 'dynamic-additional':
        return left == right
    a, b = copy.deepcopy(left), copy.deepcopy(right)
    if len(a['semantic']['records']) != len(b['semantic']['records']):
        return False
    for x, y in zip(a['semantic']['records'], b['semantic']['records']):
        if x['section'] == y['section'] == 'additional':
            if abs(x['ttl'] - y['ttl']) > 1:
                return False
            x['ttl'] = y['ttl'] = 0
    return a == b


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--c-only', action='store_true')
    args = parser.parse_args()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or os.geteuid() != 0:
        parser.error('requires root in run_isolated.sh')
    if args.out.exists() or 'private' not in args.out.resolve().parts:
        parser.error('requires fresh private output path')
    args.out.mkdir(parents=True)
    def interrupted(signum, frame):
        raise TimeoutError(f'runner interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    report = {'c_sha256': STOCK_SHA256, 'rust_sha256': sha256(args.rust), 'failures': []}
    try:
        reference = run(args, 'c', args.out / 'c')
        if args.c_only:
            report['c_rows'] = len(reference['rows'])
        else:
            actual = run(args, 'rust', args.out / 'rust')
            report.update(compare(reference, actual))
            report['parse_compared'] = len(reference['parse_rows'])
            changed = copy.deepcopy(reference)
            changed['rows'][0]['semantic']['flags'] ^= 1
            omitted = copy.deepcopy(reference)
            omitted['rows'].pop()
            additional = copy.deepcopy(reference)
            row = next(r for r in additional['rows'] if any(x['section'] == 'additional' for x in r['semantic']['records']))
            row['semantic']['records'].pop()
            reordered = copy.deepcopy(reference)
            row = next(r for r in reordered['rows'] if r['profile'] == 'srv')
            row['semantic']['records'][:2] = reversed(row['semantic']['records'][:2])
            report['negative_controls'] = [bool(compare(reference, changed)['differences']),
                bool(compare(reference, omitted)['unexecuted']),
                bool(compare(reference, additional)['differences']),
                bool(compare(reference, reordered)['differences'])]
            report['passed'] = not report['differences'] and not report['unexecuted'] and all(report['negative_controls'])
    except Exception as error:
        report['failures'].append(repr(error))
        report['passed'] = False
    (args.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: len(v) if k == 'differences' else v for k, v in report.items()}))
    return 0 if not report['failures'] and report.get('passed', True) else 1


if __name__ == '__main__':
    raise SystemExit(main())
