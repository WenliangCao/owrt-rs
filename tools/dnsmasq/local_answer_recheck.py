#!/usr/bin/env python3
"""Requalify local-answer contracts with the verified Linux C variant macros.

The previous private reports omitted original queries. Reconstruct named cases
from their C question rows and retain explicit unknown-name probes for entirely
unanswered groups. This is a new archived corpus, not a byte-identical old run.
No expected answer is read from Rust or from the historical result files.
"""
import argparse
import json
from pathlib import Path
import shutil
import struct

import local_answer_diff as diff


def query(name, qtype, qclass=1):
    wire = b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0'
    return (struct.pack('!6H', 0x1001, 0x100, 1, 0, 0, 0) + wire + struct.pack('!HH', qtype, qclass)).hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-build', required=True, type=Path)
    parser.add_argument('--rust', required=True, type=Path)
    parser.add_argument('--fixtures', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if 'private' not in output.parts:
        parser.error('output must be under private/')
    output.mkdir(parents=True, exist_ok=False)
    binary = diff.build_oracle(args.reference_build.resolve(), output)
    regular = [(kind, 1) for kind in (1, 5, 12, 15, 16, 28, 33, 35, 99, 255)] + [(1, 3), (1, 255)]
    suites = [('answer', 'answer.conf', [query(name, kind, cls)
                for name in ('only4.test', 'alias.test', 'target.test', 'local.test', 'child.local.test',
                             'v4.test', 'zero.test', 'v6.test', 'unowned.test') for kind, cls in regular]),
              ('class', 'answer.conf', [query(name, 1, cls)
                for name in ('local.test', 'child.local.test', 'unowned.test') for cls in (1, 3, 255)])]
    for fixture in sorted((args.fixtures / 'routing-review/rust-results').glob('*.json')):
        suites.append(('routing-' + fixture.stem, 'routing-review/' + fixture.stem + '.conf',
                       [query(name, kind) for name in ('foo.example.test', 'badexample.test', 'example.test',
                                                       'x.test', 'foo.test', 'unowned.test')
                        for kind in (1, 28, 255, 65400)]))
    assert len(suites) == 12 and sum(len(rows) for _, _, rows in suites) == 357
    summary = {'scope': 'New reconstructed corpus; historical unowned-name inputs were not retained',
               'checks_passed': 0, 'checks_failed': 0, 'calibration': None,
               'identity': diff.manifest(args.reference_build.resolve()), 'suites': []}
    try:
        for label, source_config, queries in suites:
            work = output / label
            work.mkdir()
            config = work / 'dnsmasq.conf'
            shutil.copyfile(args.fixtures / source_config, config)
            (work / 'queries.txt').write_text('\n'.join(queries) + '\n')
            c_rows = diff.run_probe(binary, config, queries)
            rust_rows = diff.run_command([str(args.rust.resolve())], config, queries)
            if summary['calibration'] is None:
                valid = next(row for row in c_rows if row != 'NONE')
                corrupt = bytearray.fromhex(valid)
                corrupt[3] ^= 1
                assert diff.semantic_equal(valid, valid)
                assert not diff.semantic_equal(valid, corrupt.hex())
                assert not diff.semantic_equal(valid, 'NONE')
                summary['calibration'] = {'equal_passed': 1, 'controlled_failures_detected': 2}
            failed = [{'index': index, 'query': queries[index], 'c': c, 'rust': rust}
                      for index, (c, rust) in enumerate(zip(c_rows, rust_rows))
                      if not diff.semantic_equal(c, rust)]
            report = {'queries': len(queries), 'c_rows': c_rows, 'rust_rows': rust_rows, 'mismatches': failed}
            (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
            summary['checks_failed'] += len(failed)
            summary['checks_passed'] += len(queries) - len(failed)
            summary['suites'].append({'name': label, 'queries': len(queries), 'mismatches': len(failed)})
        summary['status'] = 'passed' if summary['checks_failed'] == 0 else 'failed'
    except Exception as error:
        summary['status'] = 'failed'
        summary['error'] = repr(error)
        summary['checks_failed'] += 1
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key: summary[key] for key in ('status', 'checks_passed', 'checks_failed', 'calibration')}))
    return int(summary['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
