#!/usr/bin/env python3
"""Frozen-clock extract_addresses/answer_request differential for DNS cache answers.

Build on Linux with --build-reference DIR. Run on the Rust host with
--oracle-command 'ssh BUILD_HOST /private/cache-answer-oracle -C /private/cache.conf'
--oracle-identity /private/copied-identity.json. All packets and output stay private.
The C oracle opens no sockets; the Rust driver calls the production cache caller
methods at the same explicit clock value. No physical device is accessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess

import local_answer_diff
import rust_lib_probe
from local_answer_diff import dns_semantics

ROOT = Path(__file__).resolve().parents[2]
DRIVER = Path(__file__).with_name('cache_answer_driver.c')
HASHES = {
    'rfc1035.c': '231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222',
    'cache.c': '51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c',
    'dnsmasq.h': '318942419598f037a97611efbdea5aebba1e384b9a1ba5f7eded091c86e0e228',
}
CONFIG = 'no-hosts\nno-resolv\ncache-size=150\nneg-ttl=30\n'
TEST = 'dns::daemon::cache_tests::exact_c_oracle_driver'


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def name(value: str) -> bytes:
    return b''.join(bytes([len(label)]) + label.encode() for label in value.split('.')) + b'\0'


def packet(host: str, qtype: int, flags: int = 0x100, answers=(), authority=(), qclass=1) -> bytes:
    result = struct.pack('!6H', 0x1234, flags, 1, len(answers), len(authority), 0)
    result += name(host) + struct.pack('!HH', qtype, qclass)
    for owner, rrtype, ttl, data in [*answers, *authority]:
        result += name(owner) + struct.pack('!HHIH', rrtype, 1, ttl, len(data)) + data
    return result


def corpus():
    rows = []
    def emit(label, op, wire=b'', now=100, limit=512):
        rows.append((label, 'RESET' if op == 'RESET' else f'{op} {now} {limit} {wire.hex()}'))
    def ask(label, host='alias.test', qtype=5, now=100, flags=0x100, **kwargs):
        emit(label, 'Q', packet(host, qtype, flags, qclass=kwargs.pop('qclass', 1)), now, **kwargs)
    # Independent calibration requires cache miss, successful insert, hit and
    # expiry to be visibly different before any differential claim is accepted.
    emit('calibration-reset', 'RESET')
    ask('calibration-miss', host='missing.test')
    emit('calibration-insert', 'P', packet('missing.test', 1, 0x8183))
    ask('calibration-hit', host='missing.test')
    ask('calibration-expired', host='missing.test', now=130)
    for negative in ['positive', 'nxdomain', 'nodata']:
        for depth in [1, 2, 5]:
            prefix = f'chain-{depth}-{negative}'
            emit(prefix + '-reset', 'RESET')
            hosts = ['alias.test'] + [f'hop{i}.test' for i in range(1, depth)] + ['target.test']
            answer = [(hosts[i], 5, 60-i, name(hosts[i+1])) for i in range(depth)]
            if negative == 'positive':
                answer.append(('target.test', 1, 40, bytes([192, 0, 2, 1])))
            emit(prefix + '-insert', 'P', packet('alias.test', 1, 0x8183 if negative == 'nxdomain' else 0x8180, answer))
            for moment in [100, 105, 129]:
                ask(prefix + f'-cname-{moment}', now=moment)
            ask(prefix + '-other-family', qtype=28)
            ask(prefix + '-own-family', qtype=1)
            ask(prefix + '-cd', flags=0x110)
            ask(prefix + '-no-rd', flags=0)
            ask(prefix + '-wrong-class', qclass=3)
            ask(prefix + '-truncated', limit=40)
            ask(prefix + '-terminal-expired', qtype=1, now=140)
            ask(prefix + '-expired', now=160)
    for flags in [0x8180, 0x8183]:
        for have_answer in [False, True]:
            prefix = f'cname-insert-{flags:x}-{int(have_answer)}'
            emit(prefix + '-reset', 'RESET')
            answers = [('alias.test', 5, 60, name('target.test'))] if have_answer else []
            emit(prefix + '-insert', 'P', packet('alias.test', 5, flags, answers))
            for qtype in [1, 5, 28]:
                ask(prefix + f'-query-{qtype}', qtype=qtype)
    long_owner = '.'.join(['a' * 60] * 3 + ['test'])
    long_target = '.'.join(['b' * 60] * 3 + ['test'])
    emit('long-name-reset', 'RESET')
    emit('long-name-insert', 'P', packet(long_owner, 1, 0x8180,
        [(long_owner, 5, 60, name(long_target)), (long_target, 1, 60, bytes([192, 0, 2, 1]))]))
    ask('long-name-cname-fits', host=long_owner)
    ask('long-name-address-fits', host=long_owner, qtype=1)
    soa = name('ns.test') + name('hostmaster.test') + struct.pack('!5I', 1, 2, 3, 4, 10)
    for source_type in [1, 5, 28]:
        prefix = f'soa-nxdomain-source-{source_type}'
        emit(prefix + '-reset', 'RESET')
        emit(prefix + '-insert', 'P', packet('missing.test', source_type, 0x8183, authority=[('test', 6, 40, soa)]))
        ask(prefix + '-hit', host='missing.test', now=105)
        ask(prefix + '-expired', host='missing.test', now=110)
    for qtype in [1, 5, 6, 15, 28, 33, 255, 65401]:
        emit(f'negative-any-{qtype}-reset', 'RESET')
        emit(f'negative-any-{qtype}-insert', 'P', packet('missing.test', 1, 0x8183))
        ask(f'negative-any-{qtype}-hit', host='missing.test', qtype=qtype)
        ask(f'negative-any-{qtype}-no-rd', host='missing.test', qtype=qtype, flags=0)
    emit('rrset-1-reset', 'RESET')
    emit('rrset-1-insert', 'P', packet('Service.Test', 1, 0x8180,
        [('Service.Test', 1, 60, bytes([192, 0, 2, last])) for last in [1, 2]]))
    for attempt in range(4):
        ask(f'rrset-1-hit-{attempt}', host='Service.Test', qtype=1)
    ask('rrset-1-unknown-type', host='Service.Test', qtype=65401)
    ask('rrset-1-expired', host='Service.Test', qtype=1, now=160)
    emit('generic-type-filter-reset', 'RESET')
    emit('generic-type-filter-soa-insert', 'P', packet('missing.test', 1, 0x8183, authority=[('test', 6, 40, soa)]))
    for qtype in [6, 33, 15, 255, 65401]:
        ask(f'generic-type-filter-{qtype}', host='test', qtype=qtype)
    return rows


def calibration(rows):
    rows = [row for row in rows if not row.startswith('M ')]
    assert rows[0:3] == ['RESET', 'NONE', 'P'], 'reset/miss/insert calibration failed'
    result = dns_semantics(rows[3])
    assert result == {'id': 0x1234, 'flags': 0x8183,
                      'questions': [['missing.test', 5, 1]],
                      'sections': [['answer', []], ['authority', []], ['additional', []]]}, 'negative hit calibration failed'
    assert rows[4] == 'NONE', 'negative expiry calibration failed'
    # Calibrate the comparison itself against a behavioral mutation.
    mutated = bytes.fromhex(rows[3])
    changed = mutated[:3] + bytes([mutated[3] ^ 1]) + mutated[4:]
    assert dns_semantics(rows[3]) != dns_semantics(changed.hex())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--build-reference', type=Path)
    parser.add_argument('--oracle-command')
    parser.add_argument('--oracle-identity', type=Path)
    parser.add_argument('--cargo', default='cargo')
    parser.add_argument('--with-metrics', action='store_true')
    parser.add_argument('--inject-counter-mismatch', action='store_true')
    rust_lib_probe.add_arguments(parser)
    args = parser.parse_args()
    out = args.output.resolve()
    probe = binding = None
    source_root = ROOT
    if not args.build_reference:
        try:
            probe, source_root, binding = rust_lib_probe.selection(args, ROOT, out)
        except ValueError as error:
            parser.error(str(error))
    if not out.is_relative_to((ROOT / 'private').resolve()):
        parser.error('raw packets, logs and binaries must stay under ignored private/')
    if out.exists():
        parser.error('choose a new output directory to preserve prior evidence')
    out.mkdir(parents=True)
    if args.build_reference:
        build = args.build_reference / 'dnsmasq'
        actual = {file: digest(build / file) for file in HASHES}
        if actual != HASHES:
            raise RuntimeError(f'exact C build source identity differs: {actual}')
        local_answer_diff.DRIVER = DRIVER
        binary = local_answer_diff.build_oracle(args.build_reference, out)
        (out / 'cache.conf').write_text(CONFIG)
        identity = {'source_sha256': actual, 'copts': local_answer_diff.REFERENCE_COPTS, 'driver_sha256': digest(DRIVER),
                    'binary_sha256': digest(binary), 'config_sha256': digest(out / 'cache.conf'),
                    'binary': str(binary), 'reference_build': str(args.build_reference)}
        (out / 'identity.json').write_text(json.dumps(identity, indent=2) + '\n')
        print(json.dumps(identity, indent=2))
        return 0
    if not args.oracle_command or not args.oracle_identity:
        parser.error('run requires --oracle-command and --oracle-identity')
    identity = json.loads(args.oracle_identity.read_text())
    assert identity['source_sha256'] == HASHES
    assert identity['driver_sha256'] == digest(DRIVER)
    assert identity['config_sha256'] == hashlib.sha256(CONFIG.encode()).hexdigest()
    rows = corpus()
    if args.with_metrics:
        rows.append(('pressure-reset', 'RESET'))
        for index in range(160):
            host = f'pressure{index}.test'
            wire = packet(host, 1, 0x8180, [(host, 1, 120, bytes([192, 0, 2, 1]))])
            rows.append((f'pressure-insert-{index}', f'P 100 512 {wire.hex()}'))
        for index in range(145, 160):
            rows.append((f'pressure-hit-{index}', f'Q 100 512 {packet(f"pressure{index}.test", 1).hex()}'))
        rows.append(('pressure-reload', 'RESET'))
        rows = [entry for label, command in rows for entry in ((label, command), (label + '-metrics', 'M'))]
    elif args.inject_counter_mismatch:
        parser.error('--inject-counter-mismatch requires --with-metrics')
    text = ''.join(row + '\n' for _, row in rows)
    source = out / 'commands.txt'
    source.write_text(text)
    (out / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
    commands = {
        'c': shlex.split(args.oracle_command),
        'rust': (rust_lib_probe.argv(probe, TEST) if probe else
                 [args.cargo, '+1.98.1', 'test', '--manifest-path', str(source_root / 'components/dnsmasq/Cargo.toml'),
                  '--lib', TEST, '--', '--ignored', '--exact', '--nocapture', '--test-threads=1']),
    }
    observed = {}
    for label, command in commands.items():
        rust_lib_probe.recheck(binding)
        env = {**os.environ, 'DNSMASQ_CACHE_ORACLE_INPUT': str(source)}
        run = subprocess.run(command, input=text, text=True, capture_output=True, env=env)
        (out / f'{label}.stdout').write_text(run.stdout)
        (out / f'{label}.stderr').write_text(run.stderr)
        if run.returncode:
            raise RuntimeError(f'{label} exited {run.returncode}; see {out}/{label}.stderr')
        if label == 'rust':
            rust_lib_probe.require_one_test(run.stdout, TEST)
        observed[label] = run.stdout.splitlines() if label == 'c' else [line.removeprefix('CACHE_ORACLE ')
            for line in rust_lib_probe.records(run.stdout, TEST, 'CACHE_ORACLE ')]
        assert len(observed[label]) == len(rows), f'{label} output count differs'
        calibration(observed[label])
        rust_lib_probe.recheck(binding)
    if args.with_metrics:
        assert observed['c'][1] == 'M 0 0', 'initial counter reset failed'
        assert observed['c'][5] == 'M 1 0', 'committed record counter calibration failed'
        assert observed['c'][-3] == 'M 160 10', 'capacity eviction counter calibration failed'
        assert observed['c'][-1] == 'M 0 0', 'reload counter calibration failed'
        mutated = observed['c'][5].split(); mutated[1] = str(int(mutated[1]) + 1)
        assert ' '.join(mutated) != observed['c'][5]
        if args.inject_counter_mismatch:
            observed['rust'][5] = ' '.join(mutated)
            (out / 'injected-rust.stdout').write_text('\n'.join(observed['rust']) + '\n')
    errors = []
    for (case, command), c, rust in zip(rows, observed['c'], observed['rust']):
        metadata = command.startswith(('P ', 'RESET', 'M'))
        equal = c == rust if metadata else dns_semantics(c) == dns_semantics(rust)
        if not equal:
            errors.append({'case': case, 'command': command, 'c': c, 'rust': rust,
                           'c_semantics': c if metadata else dns_semantics(c),
                           'rust_semantics': rust if metadata else dns_semantics(rust)})
    (out / 'mismatches.json').write_text(json.dumps(errors, indent=2) + '\n')
    summary = {'commands': len(rows), 'queries': sum(row.startswith('Q ') for _, row in rows),
               'metric_snapshots': sum(row == 'M' for _, row in rows),
               'mismatches': len(errors), 'calibration': 'reset/miss/insert/NXDOMAIN/expiry and RCODE mutation passed',
               'oracle': identity, 'corpus_sha256': digest(source),
               'results': {side: {'hits': sum(row not in ('NONE', 'P', 'RESET') and not row.startswith('M ') for row in values),
                                  'misses': values.count('NONE'), 'insert_events': values.count('P'),
                                  'reset_events': values.count('RESET')} for side, values in observed.items()},
               'tool_sha256': digest(Path(__file__)),
               'rust_source_sha256': {name: digest(source_root / 'components/dnsmasq/src/dns' / name) for name in ['daemon.rs', 'daemon_cache_tests.rs', 'cache_engine.rs', 'cache.rs', 'cache_reply.rs', 'wire.rs']},
               'rust_probe': binding, 'rust_command': commands['rust'], 'rust_test': TEST,
               'c_reference_scope': 'socket-free exact-source C driver; not stock image 097a9e21 ELF',
               'normalization': 'DNS compression and ASCII name case only; exact IDs, flags, TTLs, RDATA, section/record order, hit/miss and event order',
               'scope': 'socket-free extract_addresses/answer_request CNAME/SOA/negative cache subset; not daemon transport or performance acceptance'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())
