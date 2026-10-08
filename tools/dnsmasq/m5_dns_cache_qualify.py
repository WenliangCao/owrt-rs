#!/usr/bin/env python3
"""Full final cache schedule, including supplemental callers and fresh C order proof."""
import argparse
import json
from pathlib import Path

import m5_dns_cache as family
from m2_rootfs import STOCK_SHA256, sha256


def qualify(c_runs, candidate_run, elf):
    if len(c_runs) < 2 or len({path.resolve() for path in c_runs}) != len(c_runs):
        raise ValueError('independent fresh C invocations required for PTR variation guards')
    expected = {row['case'] for row in family.SYNTAX + family.SCENARIOS}
    if len(expected) != len(family.SYNTAX) + len(family.SCENARIOS):
        raise ValueError('duplicate final cache schedule')
    reference = {}; versions = {}; inputs = []; primary = None
    for index, path in enumerate(c_runs):
        report, rows = family.comparison_rows(path, 'c')
        labels = expected if index == 0 else family.REVERSE_ORDER_CASES
        if set(rows) != labels or sorted(report['executed_cases']) != sorted(labels) or report['failures']:
            raise ValueError('partial reference schedule: ' + str(path))
        if report['rust_sha256'] != elf:
            raise ValueError('reference fixture copied a different candidate')
        if index == 0: primary = report
        for label, row in rows.items():
            reference.setdefault(label, row); versions.setdefault(label, []).append(row)
        inputs.append({'side': 'c', 'path': str(path), 'sha256': sha256(path / 'result.json')})
    report, candidate = family.comparison_rows(candidate_run, 'rust')
    if (set(candidate) != expected or sorted(report['executed_cases']) != sorted(expected)
            or report['rust_sha256'] != elf or report['failures']):
        raise ValueError('partial or different candidate schedule')
    inputs.append({'side': 'rust', 'path': str(candidate_run), 'sha256': sha256(candidate_run / 'result.json')})
    lease_okay = family.dhcp_caller_guard(primary, report)
    for path, values in [(c_runs[0], reference), (candidate_run, candidate)]:
        for label in family.DHCP_CALLERS:
            if json.loads((path / label / 'lease-witness.json').read_text()) != values[label].get('lease_witness'):
                raise ValueError('actual lease observation receipt differs')
    passed = []; differences = []; controls = []; variations = []; intentional = []
    for label in sorted(expected):
        left, right = reference[label], candidate[label]
        for side, row in [('c', left), ('rust', right)]:
            if 'identity' in row and row['identity']['sha256'] != (STOCK_SHA256 if side == 'c' else elf):
                raise ValueError('actual cache process identity differs')
        varied = False
        if label in family.REVERSE_ORDER_CASES:
            values = versions[label]
            varied = any(family.case_equal(a, b, True)
                         and family.canonical_observations(a) != family.canonical_observations(b)
                         for n, a in enumerate(values) for b in values[n + 1:])
        if label in family.DHCP_CALLERS:
            okay = lease_okay
        elif label == 'generic-expanded-u16-overflow':
            okay = family.giant_canonical_guard(left, right)
            intentional.append({'case': label, 'guarded': okay, 'source': 'dnsmasq.h:350;rfc1035.c:1016,1038,1052,2326-2327'})
        elif label in family.REVERSE_CNAME_CASES:
            okay = family.case_equal(left, right) and family.reverse_cname_caller_guard(left, right)
        else:
            okay = family.case_equal(left, right, varied)
        if okay:
            passed.append(label)
            if label not in family.DHCP_CALLERS:
                controls.extend(family.corruption_controls(left, right, varied))
            if varied: variations.append(label)
        else:
            differences.append(label)
    required = {label for row in json.loads(Path(family.__file__).with_suffix('.json').read_text())['boundaries']
                for label in row['required_cases']}
    return {'qualified': not differences and all(row['rejected'] for row in controls),
            'full_cache_family_qualified': not differences and all(row['rejected'] for row in controls),
            'candidate_sha256': elf, 'c_sha256': STOCK_SHA256, 'required_count': len(required),
            'executed_count': len(expected), 'passed_count': len(passed), 'passed_cases': passed,
            'missing_required_cases': [], 'differences': differences, 'deferred_extreme_cases': [],
            'intentional_differences': intentional, 'reference_reverse_order_variation': variations,
            'lease_tcp_caller_guard': lease_okay,
            'reverse_cname_caller_guard': all(label in passed for label in family.REVERSE_CNAME_CASES),
            'negative_controls': controls, 'reports': inputs, 'comparator_sha256': sha256(__file__)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c', type=Path, action='append', required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--rust-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.c, args.candidate, args.rust_sha256)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({name: result[name] for name in ['qualified', 'required_count', 'executed_count', 'passed_count']}))
    return int(not result['qualified'])


if __name__ == '__main__': raise SystemExit(main())
