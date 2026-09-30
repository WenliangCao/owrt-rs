#!/usr/bin/env python3
"""Check exact-C generic NODATA cache reads with Valgrind and defined controls.

This reproducer does not compare against Rust or start network listeners. A
successful run means the reference defect was reproduced, not that a DNS
correctness gate passed. Keep generated packets, logs and binaries in private/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from cache_answer_diff import CONFIG, DRIVER, HASHES, ROOT, digest, name, packet
from local_answer_diff import dns_semantics


def cases():
    soa = name('ns.test') + name('hostmaster.test') + struct.pack('!5I', 1, 2, 3, 4, 10)
    for case in ['positive', 'nxdomain', 'nodata-soa', 'nodata-no-soa']:
        answers = [('alias.test', 5, 60, name('target.test'))]
        if case == 'positive':
            answers.append(('target.test', 33, 40, struct.pack('!3H', 1, 2, 53) + name('server.test')))
        authorities = [('test', 6, 40, soa)] if case == 'nodata-soa' else []
        reply = packet('alias.test', 33, 0x8183 if case == 'nxdomain' else 0x8180, answers, authorities)
        yield case, ['RESET', f'P 100 512 {reply.hex()}',
                     f'Q 100 512 {packet("alias.test", 33).hex()}',
                     f'Q 100 512 {packet("alias.test", 5).hex()}']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle', required=True, type=Path)
    parser.add_argument('--identity', required=True, type=Path)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--valgrind', default='valgrind')
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to((ROOT / 'private').resolve()) or out.exists():
        parser.error('choose a new directory under ignored private/')
    out.mkdir(parents=True)
    identity = json.loads(args.identity.read_text())
    assert identity['source_sha256'] == HASHES
    assert identity['driver_sha256'] == digest(DRIVER)
    assert identity['binary_sha256'] == digest(args.oracle)
    assert identity['config_sha256'] == digest(args.config) == hashlib.sha256(CONFIG.encode()).hexdigest()
    version = subprocess.check_output([args.valgrind, '--version'], text=True).strip()
    observed = []
    for case, lines in cases():
        source = '\n'.join(lines) + '\n'
        (out / f'{case}.input').write_text(source)
        log_path = out / f'{case}.valgrind.log'
        command = [args.valgrind, '--track-origins=yes', '--error-exitcode=99', '--leak-check=no',
                   f'--log-file={log_path}', str(args.oracle.resolve()), '-C', str(args.config.resolve())]
        run = subprocess.run(command, input=source, text=True, capture_output=True)
        (out / f'{case}.stdout').write_text(run.stdout)
        (out / f'{case}.stderr').write_text(run.stderr)
        output = run.stdout.splitlines()
        assert len(output) == len(lines) and output[:2] == ['RESET', 'P'], f'{case}: output count/calibration'
        assert dns_semantics(output[3])['flags'] == 0x8580, f'{case}: alias control'
        log = log_path.read_text()
        count = re.search(r'ERROR SUMMARY: (\d+) errors', log)
        assert count, f'{case}: checker did not finish'
        errors = int(count[1])
        if case == 'nodata-no-soa':
            assert run.returncode == 99 and errors > 0, 'expected reference error was not reproduced'
            assert 'Conditional jump or move depends on uninitialised value(s)' in log
            assert 'answer_request (rfc1035.c:2294)' in log
            assert 'extract_addresses (rfc1035.c:771)' in log
        else:
            assert run.returncode == 0 and errors == 0, f'{case}: defined control failed'
            response = dns_semantics(output[2])
            assert response is not None, f'{case}: expected cache hit'
            assert response['flags'] == (0x8183 if case == 'nxdomain' else 0x8180)
        observed.append({'case': case, 'returncode': run.returncode, 'checker_errors': errors,
                         'query_result': dns_semantics(output[2]),
                         'input_sha256': hashlib.sha256(source.encode()).hexdigest()})
    summary = {'result': 'confirmed_reference_uninitialized_read', 'valgrind': version,
               'oracle': identity, 'controls': 3, 'reproductions': 1, 'cases': observed,
               'scope': 'unmodified exact C extract_addresses/answer_request caller; no Rust equivalence, network exploitability, production exposure, leak or performance claim'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
