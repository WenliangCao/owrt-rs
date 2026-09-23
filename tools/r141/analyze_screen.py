#!/usr/bin/env python3
"""Reuse the complete R136 verifier; add the frozen single-profile PGO gate."""
import argparse
from decimal import Decimal, localcontext
from fractions import Fraction
import itertools
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from r136 import analyze_batch as base
from r136.oracle_batch import METRICS

C = 'cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88'
R136 = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
BENCHMARK = '85dd537a070e39373a4a21a6bf982da9359bc70e61e53cdf93516b9c34684b1d'
POLICY_PATH = Path(__file__).with_name('screen-policy.json')


def contrast(values, controls):
    ratios = [value / control for value, control in zip(values, controls)]
    median = statistics.median(ratios)
    return {'ratios_by_block': list(map(float, ratios)),
            'delta_pct_by_block': [float((value - 1) * 100) for value in ratios],
            'median_delta_pct': float((median - 1) * 100),
            'lower_blocks': sum(value < 1 for value in ratios), 'higher_blocks': sum(value > 1 for value in ratios),
            'direction': 'unresolved_within_1pct' if abs(median - 1) <= Fraction(1, 100) else 'descriptive_lower' if median < 1 else 'descriptive_higher',
            'above_3pct_in_all_four': median > Fraction(103, 100) and all(value > 1 for value in ratios)}


def decisions(indexed, policy):
    groups, primary, vetoes = [], [], []
    for pair, affinity, lane in itertools.product(policy['pairs'], policy['affinities'], policy['lanes']):
        prefix = tuple(pair), affinity, lane
        vs = {control: {metric: contrast(
            [indexed[*prefix, 'pgo', block][metric] for block in range(4)],
            [indexed[*prefix, control, block][metric] for block in range(4)])
            for metric in METRICS} for control in ('r136', 'c')}
        groups.append({'pair': pair, 'affinity': affinity, 'lane': lane, 'vs': vs})
        for metric in policy['latency_veto_metrics']:
            if vs['r136'][metric]['above_3pct_in_all_four']:
                vetoes.append({'pair': pair, 'affinity': affinity, 'lane': lane, 'metric': metric, **vs['r136'][metric]})
    with localcontext() as context:
        context.prec = 60
        for pair in policy['pairs']:
            values = []
            for block in range(4):
                product = Fraction(1)
                for lane in policy['lanes']:
                    prefix = tuple(pair), policy['primary_affinity'], lane
                    product *= indexed[*prefix, 'pgo', block]['mean_us'] / indexed[*prefix, 'r136', block]['mean_us']
                value = (Decimal(product.numerator) / Decimal(product.denominator)) ** (Decimal(1) / 5)
                values.append(value.quantize(Decimal('1e-30')))
            median = statistics.median(values)
            lower = sum(value < 1 for value in values)
            primary.append({'pair': pair, 'geometric_ratio_by_block': list(map(str, values)),
                            'median_geometric_ratio': str(median), 'median_delta_pct': float((median - 1) * 100),
                            'lower_blocks': lower, 'passed': median < Decimal(policy['primary_ratio_below'])
                            and lower >= policy['primary_min_lower_blocks']})
    return {'groups': groups, 'primary': primary, 'latency_vetoes': vetoes,
            'latency_checks': 60, 'screen_passed': all(row['passed'] for row in primary) and not vetoes,
            'router_acceptance': False}


def analyze(root):
    report = base.analyze(root)
    check, read, sha = base.r135.require, base.r135.read, base.r135.sha
    plan, identity, policy = report['plan'], read(root / 'manifest-identity.json'), read(POLICY_PATH)
    check(list(plan['subjects']) == ['c', 'r136', 'pgo']
          and plan['subjects']['c']['sha256'] == C and plan['subjects']['r136']['sha256'] == R136
          and plan['benchmark']['sha256'] == BENCHMARK, 'expected exact C/R136/original R135 caller')
    check(plan['pairs'] == policy['pairs'] == [[0, 1], [2, 3]] and plan['repeats'] == policy['blocks'] == 4
          and plan['iterations'] == policy['iterations'] == 10000 and plan['warmup'] == policy['warmup'] == 20,
          'frozen 240-case dimensions differ')
    check(identity['r141_policy'] == policy and identity['provenance']['policy_sha256'] == sha(POLICY_PATH), 'pre-screen policy changed')
    for name, expected in identity['provenance']['tool_sha256'].items():
        check(sha(ROOT / name) == expected, f'screen tool changed: {name}')
    check(plan['runner_sha256'] == identity['provenance']['tool_sha256']['tools/r136/oracle_batch.py'], 'collector identity differs')
    check(identity['provenance']['profile_use_sha256'] == plan['subjects']['pgo']['sha256'], 'profile-use ELF differs')
    expected_schedules = [[[block, label] for block in range(4)
        for label in (['c', 'r136', 'pgo'] if (block + pair[0] // 2) % 2 == 0 else ['pgo', 'r136', 'c'])]
        for pair in policy['pairs']]
    check(plan['schedules'] == expected_schedules, 'frozen forward/reverse schedules differ')
    hashes = read(root / 'hashes.json')
    check({str(path.relative_to(root)) for path in root.rglob('*') if path.is_file()}
          == set(hashes) | {'hashes.json'}, 'unlisted evidence files present')
    indexed, records = {}, []
    for row in report['records']:
        data = read(root / row['file'])
        samples = sorted(data['latency_ns'])
        n = len(samples)
        metrics = {'mean_us': Fraction(sum(samples), n * 1000)}
        for name, percentile in (('p50_us', 50), ('p95_us', 95), ('p99_us', 99)):
            metrics[name] = Fraction(samples[((n - 1) * percentile + 50) // 100], 1000)
        metrics['daemon_cpu_us_per_op'] = Fraction(data['daemon_cpu'][0]['cpu_clock_ns'], n * 1000)
        metrics['caller_cpu_us_per_op'] = Fraction(data['client_cpu_clock_ns'], n * 1000)
        indexed[tuple(row['pair']), row['affinity'], row['lane'], row['label'], row['block']] = metrics
        records.append({key: row[key] for key in ('pair', 'affinity', 'lane', 'label', 'block', 'file', 'sha256')}
                       | {'metrics': {key: float(value) for key, value in metrics.items()}})
    check(len(indexed) == len(records) == 240, 'expected all 240 cases')
    return {'schema': 1, 'scope': 'R141 frozen generic PGO Oracle screen; no router decision',
            'verified': True, 'cases': 240, 'verified_file_count': report['verified_file_count'],
            'hash_manifest_sha256': report['hash_manifest_sha256'], 'collector_plan_sha256': sha(root / 'plan.json'),
            'analyzer_sha256': sha(Path(__file__)), 'policy': policy, 'policy_sha256': sha(POLICY_PATH),
            'subjects': {key: value['sha256'] for key, value in plan['subjects'].items()},
            'benchmark_sha256': BENCHMARK, 'provenance': identity['provenance'], 'records': records,
            **decisions(indexed, policy), 'limitations': report['limitations'] + [
                'The fixed generic profile-use candidate is measured once; no profile reselection, training retries or extra variants based on screen results.',
                'Five-lane equal weighting is an engineering choice. Primary eligibility must hold separately on both CPU pairs; neither pair is pooled away.',
                'Every mean/p95/p99 lane on both affinities and both CPU pairs is guarded. CPU is fully reported, with no CPU hard gate.',
                'A failed screen stops this PGO direction. A passed screen does not transfer R140 evidence or authorize adoption; independent exact-PGO router correctness, seven-lane timing and resource evidence are required.',
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.root.resolve())
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'verified': True, 'cases': 240, 'primary': report['primary'],
                      'latency_veto_count': len(report['latency_vetoes']), 'screen_passed': report['screen_passed']}))


if __name__ == '__main__':
    main()
