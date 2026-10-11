#!/usr/bin/env python3
"""F03 real dhcp-script regression, including all five independent audit cases.

Run through run_isolated.sh. The exact C image and Rust both execute a Python
hook which records argv and every DNSMASQ_* value before the daemon stops.
Expiry/remaining timestamps are omitted from paired comparisons. RENEW T1/T2
are compared after validating their common bounded random offset.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time


def normalize_renewal_timers(event, reply):
    """Validate this fixture's independent C/Rust renewal fuzz before comparing."""
    if not (event['kind'] == 3 and event.get('wanted', True) is False
            and event.get('server') is None
            and event.get('ciaddr') not in (None, '0.0.0.0')):
        return
    # The fixture has a 1h range, no timer overrides. REQUEST can shorten it.
    lease = min(3600, max(120, event.get('lease_time', 3600)))
    if not reply or reply.get('message_type') != 5:
        raise ValueError('RENEW did not receive ACK')
    options = reply['options']
    if any(len(options.get(code, '')) != 8 for code in ['51', '58', '59']):
        raise ValueError('RENEW lease/T1/T2 must each contain four bytes')
    values = {code: int(options[code], 16) for code in ['51', '58', '59']}
    # rfc2131.c:1486,2776-2780: limit rand16() to T1/8 and subtract
    # that same value from T1 and T2. Keep the granted lease exact.
    fuzz = lease // 2 - values['58']
    if not (values['51'] == lease and 0 <= fuzz <= lease // 16
            and values['59'] == lease * 7 // 8 - fuzz):
        raise ValueError(f'invalid RENEW timer relation: {values}')
    options['58'] = (lease // 2).to_bytes(4, 'big').hex()
    options['59'] = (lease * 7 // 8).to_bytes(4, 'big').hex()


def scenarios():
    first = dict(kind=3, name='first', vendor='original')
    for mode in ['rapid', 'renew', 'selecting']:
        for wanted in ([False, True] if mode == 'rapid' else [mode == 'selecting']):
            event = dict(kind=1 if mode == 'rapid' else 3, rapid=mode == 'rapid',
                         wanted=wanted, mac=2, name='second', vendor='replacement',
                         server='127.0.0.1' if mode == 'selecting' else None,
                         ciaddr='127.0.0.30' if mode == 'renew' else None)
            yield dict(name=f'handoff-{mode}-{wanted}', events=[first, event],
                       callbacks=2, refreshed=mode == 'selecting')
    for wanted in [True, False]:
        yield dict(name='rapid-same-mac-' + ('requested' if wanted else 'no-requested'),
                   events=[first, dict(kind=1, rapid=True, wanted=wanted,
                                       name='second', vendor='replacement')], callbacks=1)
    yield dict(name='selecting-same-mac', events=[first, dict(kind=3, name='second',
               vendor='replacement')], callbacks=2, refreshed=True)
    for renewal in [False, True]:
        yield dict(name=f'renew-same-mac-script-on-renewal-{renewal}',
                   events=[first, dict(kind=3, wanted=False, server=None,
                                       ciaddr='127.0.0.30', name='second',
                                       vendor='replacement', lease_time=1800)],
                   config='script-on-renewal\n' if renewal else '',
                   callbacks=2 if renewal else 1, refreshed=False)
    yield dict(name='new-rapid-no-requested', callbacks=1,
               events=[dict(kind=1, rapid=True, wanted=False, name='first', vendor='original')])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        parser.error('run with sudo through run_isolated.sh')
    if 'private' not in args.out.resolve().parts:
        parser.error('raw evidence must stay under private/')
    sys.path.insert(0, str(args.source / 'tools/dnsmasq'))
    import audit_20261011_dhcp as base
    from m2_rootfs import image_elf_command

    original_packet = base.packet
    original_dns = base.dns_answer
    active = {}

    def packet(kind, xid, mac=1, rapid=False, wanted=True, name=None,
               ciaddr=None, server='127.0.0.1', vendor=None, lease_time=None):
        if xid != 0xabc000:
            deadline = time.monotonic() + 3
            while not active['done'].exists() or not active['done'].read_text().strip():
                if time.monotonic() > deadline:
                    raise RuntimeError('first lease helper did not complete')
                time.sleep(.01)
        wire = bytearray(original_packet(kind, xid, mac, rapid, False, None))
        if ciaddr:
            wire[12:16] = socket.inet_aton(ciaddr)
        head, pos = wire[:240], 240
        while pos < len(wire):
            code = wire[pos]
            pos += 1
            if code == 255:
                break
            length = wire[pos]
            value = wire[pos + 1:pos + 1 + length]
            pos += 1 + length
            if code != 54:
                head += base.option(code, value)
        if wanted:
            head += base.option(50, socket.inet_aton('127.0.0.30'))
        if kind == 3 and server:
            head += base.option(54, socket.inet_aton(server))
        if name is not None:
            head += base.option(12, name.encode())
        if vendor is not None:
            head += base.option(60, vendor.encode())
        if lease_time is not None:
            head += base.option(51, struct.pack('!I', lease_time))
        return bytes(head) + b'\xff'

    def after_helpers(name, kind):
        if not active['settled']:
            started = stable_since = time.monotonic()
            previous = None
            while time.monotonic() - started < 1 or time.monotonic() - stable_since < .3:
                current = active['done'].read_text() if active['done'].exists() else ''
                if current != previous:
                    previous, stable_since = current, time.monotonic()
                if time.monotonic() - started > 3:
                    raise RuntimeError('helper events did not settle')
                time.sleep(.01)
            active['captured'] = [json.loads(line) for line in active['full'].read_text().splitlines()]
            active['settled'] = True
        return original_dns(name, kind)

    base.packet, base.dns_answer = packet, after_helpers
    args.out.mkdir(parents=True, exist_ok=False)
    stock = args.image_root / 'usr/sbin/dnsmasq'
    assert base.sha(stock) == base.STOCK_SHA256
    commands = {'c': image_elf_command(args.image_root, stock),
                'rust': image_elf_command(args.image_root, args.rust)}
    report = dict(rust_sha256=base.sha(args.rust), c_sha256=base.sha(stock),
                  script_sha256=base.sha(__file__), cases=[], passed=False)

    def normalized(row):
        row = json.loads(json.dumps(row))
        for event in row['events']:
            normalize_renewal_timers(event['input'], event['reply'])
        for event in row['helper_events_full']:
            for key in ['DNSMASQ_LEASE_EXPIRES', 'DNSMASQ_TIME_REMAINING']:
                event['env'].pop(key, None)
        return row

    for case in scenarios():
        rows, errors = {}, []
        for side, command in commands.items():
            stem = args.out / f'{case["name"]}-{side}'
            hook = stem.with_suffix('.py')
            active.update(done=stem.with_suffix('.done'), full=stem.with_suffix('.jsonl'),
                          settled=False, captured=[])
            hook.write_text('#!/usr/bin/python3\nimport os,sys,json\n'
                + f'with open({str(active["full"])!r}, "a") as f: '
                + 'f.write(json.dumps({"argv":sys.argv[1:],"env":{k:v for k,v in os.environ.items() '
                + 'if k.startswith("DNSMASQ_")}},sort_keys=True)+"\\n")\n'
                + f'with open({str(active["done"])!r}, "a") as f: f.write("done\\n")\n')
            hook.chmod(0o755)
            config = (f'dhcp-script={hook}\n'
                      'dhcp-host=02:00:00:00:00:01,02:00:00:00:00:02,127.0.0.30,dual\n'
                      + case.get('config', ''))
            row = base.execute(command, dict(case, config=config), stem)
            row['helper_events_full'] = active['captured']
            rows[side] = row
            callbacks = row['helper_events_full']
            if len(callbacks) != case['callbacks']:
                errors.append(f'{side}: expected {case["callbacks"]} callbacks, got {len(callbacks)}')
            expected_actions = ['add'] + ['old'] * (case['callbacks'] - 1)
            if [event['argv'][0] for event in callbacks] != expected_actions:
                errors.append(f'{side}: incorrect callback actions')
            for index, event in enumerate(callbacks):
                fresh = index == 0 or case.get('refreshed', False)
                env = event['env']
                if fresh:
                    expected = ('original', 'first') if index == 0 else ('replacement', 'second')
                    if (env.get('DNSMASQ_VENDOR_CLASS'), env.get('DNSMASQ_SUPPLIED_HOSTNAME')) != expected:
                        errors.append(f'{side}: callback {index} lost refreshed metadata')
                    if 'DNSMASQ_DATA_MISSING' in env:
                        errors.append(f'{side}: callback {index} unexpectedly missing metadata')
                elif env.get('DNSMASQ_DATA_MISSING') != '1' or any(key in env for key in
                        ['DNSMASQ_VENDOR_CLASS', 'DNSMASQ_SUPPLIED_HOSTNAME', 'DNSMASQ_TAGS',
                         'DNSMASQ_REQUESTED_OPTIONS']):
                    errors.append(f'{side}: callback {index} rebuilt consumed one-shot metadata')
            if row['exit'] != 0 or any(not event['daemon_alive'] or not event['reply']
                    or event['reply']['message_type'] != 5 for event in row['events']):
                errors.append(f'{side}: missing ACK or unhealthy daemon')
        matched = normalized(rows['c']) == normalized(rows['rust'])
        if not matched:
            errors.append('C/Rust wire, lease, DNS, or full helper argv/environment differs')
        report['cases'].append(dict(name=case['name'], matched=matched, errors=errors, **rows))
    report['passed'] = all(not row['errors'] for row in report['cases'])
    (args.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(passed=report['passed'], cases=len(report['cases']),
                         failures={row['name']: row['errors'] for row in report['cases'] if row['errors']})))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
