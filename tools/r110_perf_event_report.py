#!/usr/bin/env python3
"""Validate and summarize synchronized Oracle counter samples (descriptive).

Usage: PLAN RAW_SERIES OUTPUT --compare CANDIDATE:CONTROL [--compare ...]
Balanced permutations are not treated as independent confirmation blocks.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(pairs):
    result = {}
    for key in pairs[0][0]:
        if any(before[key] <= 0 for after, before in pairs):
            continue
        values = [100 * (after[key] / before[key] - 1) for after, before in pairs]
        result[key] = {'median_delta_pct': statistics.median(values),
                       'paired_delta_pct': values,
                       'range_delta_pct': [min(values), max(values)]}
    return result


def report(plan_path, raw, comparisons):
    plan = json.loads(plan_path.read_text())
    assert (raw / 'COMPLETE').is_file()
    assert (raw / 'plan.json').read_bytes() == plan_path.read_bytes()
    samples = []
    for index, item in enumerate(plan['runs'], 1):
        directory = raw / f'{index:03d}-{item["subject"]}-{item["held_clients"]}'
        assert (directory / 'COMPLETE').is_file()
        meta = json.loads((directory / 'meta.json').read_text())
        client = json.loads((directory / 'client.json').read_text())
        assert meta['binary_sha256'] == plan['subjects'][item['subject']]
        assert meta['client_sha256'] == plan['client_sha256']
        assert meta['label'] == item['subject']
        assert meta['held_clients'] == client['held_clients'] == item['held_clients']
        assert meta['daemon_pid'] == client['subject_pid']
        assert client['perf_controlled'] and client['payload_checked'] and client['handlers_removed']
        assert client['matched'] and client['listeners'] == 1
        assert client['received'] == client['n'] == plan['iterations']
        assert client['warmup_received'] == client['warmup'] == plan['warmup']
        assert client['held_fds'] == client['base_fds'] + item['held_clients']
        assert client['subject_cpu'] == 1 and client['client_cpu'] == 0
        before = (directory / 'stat-before.txt').read_text().rsplit(')', 1)[1].split()
        after = (directory / 'stat-after.txt').read_text().rsplit(')', 1)[1].split()
        assert before[19] == after[19], 'process starttime changed'
        counters = {}
        for line in (directory / 'perf.csv').read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            fields = line.split(';')
            if len(fields) < 5:
                continue
            event = fields[2].strip()
            assert event not in counters
            assert float(fields[3]) > 0 and float(fields[4]) == 100.0
            counters[event] = float(fields[0])
        assert counters == meta['counters']
        assert set(counters) == set(plan['counter_names'])
        assert counters['cpu-migrations'] == 0
        values = {key: value / client['n'] for key, value in counters.items()}
        for name in ('subject', 'client', 'wall'):
            delta = client[f'{name}_after_ns'] - client[f'{name}_before_ns']
            assert delta > 0
            values[f'{name}_ns_per_send'] = delta / client['n']
        values['total_ns_per_send'] = values['subject_ns_per_send'] + values['client_ns_per_send']
        samples.append({**item, 'sample': index, 'values': values,
                        'raw_sha256': {name: digest(directory / name) for name in
                                       ('meta.json', 'client.json', 'perf.csv',
                                        'stat-before.txt', 'stat-after.txt')}})
    aa_pairs = []
    for block in sorted({s['block'] for s in samples if s['stage'] == 'aa'}):
        pair = [s for s in samples if s['stage'] == 'aa' and s['block'] == block]
        assert len(pair) == 2 and [s['slot'] for s in pair] == ['a', 'b']
        assert pair[0]['subject'] == pair[1]['subject']
        assert pair[0]['held_clients'] == pair[1]['held_clients']
        aa_pairs.append((pair[1]['values'], pair[0]['values']))
    summary = []
    for held in sorted({s['held_clients'] for s in samples if s['stage'] == 'comparison'}):
        selected = [s for s in samples if s['stage'] == 'comparison' and s['held_clients'] == held]
        for candidate, control in comparisons:
            pairs = []
            for block in sorted({s['block'] for s in selected}):
                group = {s['subject']: s['values'] for s in selected if s['block'] == block}
                assert len(group) == len(plan['subjects'])
                pairs.append((group[candidate], group[control]))
            summary.append({'held_clients': held, 'candidate': candidate,
                            'control': control, 'metrics': summarize(pairs)})
    return {'schema_version': 1, 'scope': 'Oracle user-mode counter diagnosis only',
            'plan_sha256': digest(plan_path), 'reporter_sha256': digest(Path(__file__)),
            'complete_samples': len(samples), 'all_pmu_running_pct': 100,
            'migrations_in_all_samples': 0, 'aa': summarize(aa_pairs),
            'comparisons': summary, 'samples': samples,
            'limits': ['Descriptive balanced permutation cycle; no IID confidence claim.',
                       'A/A spread is an observation, not a guaranteed noise bound.',
                       'User-mode Oracle PMU counts do not establish router CPU performance.',
                       'Final callback/CPU-clock/disable boundaries can include residual work.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path)
    parser.add_argument('raw', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--compare', action='append', required=True)
    args = parser.parse_args()
    comparisons = [tuple(pair.split(':')) for pair in args.compare]
    assert all(len(pair) == 2 and pair[0] != pair[1] for pair in comparisons)
    result = report(args.plan, args.raw, comparisons)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    for row in result['comparisons']:
        print(row['held_clients'], row['candidate'], '/', row['control'],
              {key: round(value['median_delta_pct'], 3)
               for key, value in row['metrics'].items()})


if __name__ == '__main__':
    main()
