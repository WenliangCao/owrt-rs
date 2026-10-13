#!/usr/bin/env python3
"""Reuse the 49-command SDK validation with an exact-packet N1 assertion.

Accepts the retained types_validation_driver.py CLI unchanged. Its explicit
historical differences remain bounded by that driver's original checks.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def exact_n1(result):
    assert len(result['runs']) == 72
    failures = []
    for row in result['runs']:
        c, rust = row['sides']['c'], row['sides']['fix']
        checks = {'response_dictionary': c['response'] == rust['response'],
                  'both_reply': c['response']['status'] == rust['response']['status'] == 'reply',
                  'upstream_count': len(c['upstream']) == len(rust['upstream']),
                  'health': all(side['alive'] and side['exit'] == 0 for side in (c, rust))}
        if row['warmth'] != 'cold':
            checks['warm_response_dictionary'] = c['warm_response'] == rust['warm_response']
            checks['warm_upstream_count'] = len(c['warm_upstream']) == len(rust['warm_upstream'])
        if not all(checks.values()):
            failures.append({'case': row['name'], 'checks': checks})
    return {'passed': not failures, 'cases': 72, 'failures': failures,
            'comparison': 'Full response dictionary including packet hex and TTL; no normalization'}


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('action', choices=('prepare', 'run'))
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    args, _ = parser.parse_known_args()
    source = args.source if args.action == 'prepare' else Path(json.loads(args.plan.read_text())['source'])
    assert source is not None
    inherited = source / 'docs/dnsmasq/audits/20261012/fix3_repairs/functional'
    sys.path.insert(0, str(inherited))
    import result_checks
    result_checks.check_n1 = exact_n1
    spec = importlib.util.spec_from_file_location('retained_validation', inherited / 'types_validation_driver.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()
    if args.action == 'prepare':
        plan = json.loads(args.plan.read_text())
        plan['schema'] = 'dnsmasq-fix4-functional-v1'
        plan['assets'][str(Path(__file__).resolve())] = sha(__file__)
        plan['N1_comparison'] = 'Full response dictionary including hex and TTL; no normalization'
        args.plan.write_text(json.dumps(plan, indent=2) + '\n')
        print(json.dumps({'final_plan_sha256': sha(args.plan), 'exact_N1': True}))


if __name__ == '__main__':
    main()
