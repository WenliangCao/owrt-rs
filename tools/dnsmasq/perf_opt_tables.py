#!/usr/bin/env python3
"""Render frozen analyzer summaries without pooling rounds or environments.

Omit --candidate for a baseline-only report. --failed shows excluded attempts
separately; it never makes an incomplete input eligible for acceptance.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re

from perf_opt_analyze import compare, spread


DEPLOYED = '8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7'
EXACT_C = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
SCENES = ('udp-hit', 'udp-miss', 'udp-mixed', 'tcp-hit', 'tcp-miss',
          'dhcp-home6', 'dhcp', 'startup-small', 'config-small', 'hup-small', 'hup-large')
RESOURCES = ('rss_median_kib', 'rss_peak_kib', 'anon_peak_kib', 'file_peak_kib',
             'shmem_peak_kib', 'tree_fd_peak', 'parent_fd_peak')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def validate(data, role, candidate_baseline=DEPLOYED):
    require(data.get('schema') == 1, 'unsupported analyzer schema')
    require(data.get('complete') is True and data.get('window_count') == 110
            and data.get('valid_windows') == 110 and data.get('parse_failures') == [],
            'incomplete/invalid attempt; use --failed to show it as excluded')
    identity = data['identity']
    hashes = identity['comparison']
    require(set(hashes) == {'c', 'rust'} and all(re.fullmatch('[0-9a-f]{64}', x)
            for x in hashes.values()), 'invalid ELF identities')
    if role == 'oracle':
        require(identity.get('environment', '').startswith('Oracle')
                and identity.get('smoke_only') is False, 'not a complete Oracle screen')
    else:
        require('Oracle' not in identity.get('environment', '')
                and identity.get('production_sha256') == DEPLOYED, 'not the frozen device environment')
        require([x[0] for x in identity['scenes']] == list(SCENES), 'wrong device scene matrix')
        require(hashes['c'] == (EXACT_C if role == 'baseline' else candidate_baseline), 'wrong left comparator')
        require(hashes['rust'] == DEPLOYED if role == 'baseline' else hashes['rust'] != EXACT_C,
                'wrong right comparator')
    windows = data['windows']
    expected_order = [(scene, number, side) for scene in SCENES for number in range(1, 6)
                      for side in (('c', 'rust') if number % 2 else ('rust', 'c'))]
    require([(w['scene'], w['round'], w['side']) for w in windows] == expected_order,
            'missing, duplicate, reordered or pooled rounds')
    require(len({w['label'] for w in windows}) == 110, 'duplicate window labels')
    require(set(data['comparisons']) == set(SCENES), 'missing/extra comparison scenes')
    for window in windows:
        require(window['valid'] is True and not window['errors'] and window['raw_verified_files'] > 0
                and window['elf_sha256'] == hashes[window['side']], 'invalid/unverified window')
    for scene in SCENES:
        sides = [[w for w in windows if w['scene'] == scene and w['side'] == side]
                 for side in ('c', 'rust')]
        metrics = data['comparisons'][scene]
        sources = {'p50_ms': ('latency_ms', 'p50'), 'p95_ms': ('latency_ms', 'p95'),
                   'cpu_us': ('cpu_us_per_operation',), **{k: (k,) for k in RESOURCES}}
        if scene in ('dhcp', 'dhcp-home6'):
            sources.update({f'dora_{q}_ms': ('dora_latency_ms', q) for q in ('p50', 'p95')})
        for metric, keys in sources.items():
            values = []
            for rows in sides:
                group = []
                for row in rows:
                    value = row
                    for key in keys:
                        value = value[key]
                    require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                            f'invalid {scene}/{metric} number')
                    group.append(value)
                values.append(group)
            result = metrics[metric]
            for name, group in zip(('left', 'right'), values):
                require(result[name] == spread(group), f'inconsistent {scene}/{metric}/{name}')
            if metric not in RESOURCES and not (scene == 'dhcp-home6' and metric.startswith('dora_')):
                ticks = [[r['cpu_ticks'] for r in rows] for rows in sides] if metric == 'cpu_us' else None
                resolution = 1 if scene.endswith(('small', 'large')) and metric != 'cpu_us' else 0
                require(result == compare(*values, cpu=ticks, resolution=resolution),
                        f'inconsistent decision for {scene}/{metric}')
            elif metric.startswith('dora_'):
                require(result.get('ranked') is False, 'home6 DORA must remain descriptive')


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def number(value):
    return f'{value:.6g}'


def interval(value):
    return f"{number(value['median'])} [{number(value['min'])}, {number(value['max'])}]"


def table(lines, headings, rows):
    lines.extend(['', '| ' + ' | '.join(headings) + ' |', '| ' + ' | '.join(['---'] * len(headings)) + ' |'])
    lines.extend('| ' + ' | '.join(cell(x) for x in row) + ' |' for row in rows)


def render(lines, path, data, digest, title, labels, elf_sizes):
    lines.extend(['', '## ' + title, '', f'Input: `{path.name}`; SHA256 `{digest}`.',
                  'Complete: 11 scenes, five alternating pairs each, 110 valid verified windows.'])
    table(lines, ['Side', 'ELF SHA256', 'ELF bytes'],
          [[labels[i], data['identity']['comparison'][side],
            elf_sizes.get(data['identity']['comparison'][side], 'not supplied')]
           for i, side in enumerate(('c', 'rust'))])
    lines.extend(['', 'All intervals are median [minimum, maximum] of the five per-round statistics; '
                  'individual operations and historical rounds are never pooled. Δ is right relative to left. '
                  'Pairs count agreement with the median direction. “Inconclusive” is not proof of equivalence.'])
    rows = []
    for scene in SCENES:
        metrics = data['comparisons'][scene]
        for metric in ('p50_ms', 'p95_ms', 'cpu_us', 'dora_p50_ms', 'dora_p95_ms'):
            if metric not in metrics:
                continue
            result = metrics[metric]
            descriptive = result.get('ranked') is False
            rows.append([scene, metric, interval(result['left']), interval(result['right']),
                         '—' if descriptive else f"{result['relative_change_pct']:+.3f}%",
                         '—' if descriptive else f"{result['W_pct']:.3f}%",
                         '—' if descriptive else f"{result['same_direction_pairs']}/5",
                         ('yes' if result['precision_ok'] else 'no') if metric == 'cpu_us' else '—',
                         'descriptive only' if descriptive else result['direction'].replace('within_variation_or_resolution', 'inconclusive')])
    table(lines, ['Scene', 'Metric', labels[0], labels[1], 'Δ', 'W', 'Pairs', 'CPU precision', 'Result'], rows)
    lines.extend(['', 'CPU is µs/operation; all CPU rounds need ≥10 ticks and the median difference must exceed '
                  '8 ticks. Lifecycle latency uses a 1 ms observation floor; lifecycle CPU includes startup, '
                  'idle and shutdown for the whole round. Home6 DORA has only six samples per round and is not ranked.'])
    rows = [[scene, labels[i], *[interval(data['comparisons'][scene][key][side]) for key in RESOURCES]]
            for scene in SCENES for i, side in enumerate(('left', 'right'))]
    table(lines, ['Scene', 'Side', 'RSS median KiB', 'RSS peak KiB', 'Anon peak KiB', 'File peak KiB',
                  'Shmem peak KiB', 'Tree FD peak', 'Parent FD peak'], rows)
    lines.extend(['', 'Lifecycle memory/FD values are readiness snapshots, not transient peaks. '
                  'RSS and RssAnon are not private memory; device PSS/USS are unavailable. '
                  'ELF byte sizes are measured only when matching local files are supplied with `--elf`.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--candidate', type=Path, help='fresh device pairs: c=comparison baseline, rust=candidate')
    parser.add_argument('--candidate-baseline-sha256', help='explicit left comparator; defaults to deployed v0.2.0')
    parser.add_argument('--candidate-baseline-label', help='required with an explicit comparator SHA256')
    parser.add_argument('--oracle', type=Path, help='complete Oracle analyzer summary; never device evidence')
    parser.add_argument('--failed', action='append', default=[], type=Path, help='excluded attempt, shown separately')
    parser.add_argument('--elf', action='append', default=[], type=Path, help='local ELF to measure bytes and match SHA256')
    parser.add_argument('--compatibility-fix', help='separate description of authorized behavior correction(s)')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        explicit_baseline = args.candidate_baseline_sha256 is not None
        require(explicit_baseline == (args.candidate_baseline_label is not None),
                'explicit candidate baseline requires both SHA256 and label')
        if explicit_baseline:
            require(args.candidate is not None
                    and re.fullmatch('[0-9a-f]{64}', args.candidate_baseline_sha256)
                    and args.candidate_baseline_label.strip(), 'invalid explicit candidate baseline')
        candidate_baseline = args.candidate_baseline_sha256 or DEPLOYED
        candidate_baseline_label = args.candidate_baseline_label or 'Deployed v0.2.0'
        inputs = {}
        for role in ('baseline', 'candidate', 'oracle'):
            path = getattr(args, role)
            if path:
                data, digest = load(path)
                validate(data, role, candidate_baseline)
                inputs[role] = path, data, digest
        require(args.output.resolve() not in {p.resolve() for p, _, _ in inputs.values()}
                | {p.resolve() for p in args.failed + args.elf}, 'output would overwrite an input')
        known_hashes = {sha for _, d, _ in inputs.values() for sha in d['identity']['comparison'].values()}
        elf_sizes = {}
        for path in args.elf:
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            require(raw.startswith(b'\x7fELF') and digest in known_hashes, f'ELF does not match a reported identity: {path}')
            elf_sizes[digest] = len(raw)
        lines = ['# Frozen performance report tables', '',
                 'These tables report analyzer results, not final candidate acceptance. Correctness, client health '
                 'and justification of memory/ELF growth remain separate gates. Summary consistency is checked here; '
                 'raw-file verification is performed by the analyzer.']
        if args.compatibility_fix:
            lines.extend(['', 'Separate compatibility correction: ' + cell(args.compatibility_fix),
                          'It is not classified as a performance optimization; whole-artifact timing cannot attribute its individual effect.'])
        if 'candidate' in inputs:
            render(lines, *inputs['candidate'], 'Primary — fresh paired DEVICE comparison',
                   (candidate_baseline_label, 'Candidate'), elf_sizes)
        else:
            lines.extend(['', '**Baseline-only: no fresh deployed/candidate device comparison is supplied; candidate acceptance is unavailable.**'])
        render(lines, *inputs['baseline'], 'Context only — earlier exact-C / deployed DEVICE baseline',
               ('Exact-image C', 'Deployed v0.2.0'), elf_sizes)
        if 'oracle' in inputs:
            render(lines, *inputs['oracle'], 'ORACLE screen only — not device measurements or acceptance',
                   ('Oracle baseline', 'Oracle candidate'), elf_sizes)
        for path in args.failed:
            data, digest = load(path)
            lines.extend(['', '## Excluded attempt — ' + cell(path.name), '',
                          f'SHA256 `{digest}`. Excluded regardless of any favorable individual windows.'])
            table(lines, ['Window count', 'Valid windows', 'Complete marker', 'Parse failures'],
                  [[data.get('window_count', 'unknown'), data.get('valid_windows', 'unknown'),
                    data.get('complete', 'unknown'), len(data.get('parse_failures', []))]])
            lines.append('')
            for failure in data.get('parse_failures', []):
                lines.append('- ' + cell(failure))
            for window in data.get('windows', []):
                if not window.get('valid', False) or window.get('errors'):
                    lines.append('- ' + cell(window.get('label', '?')) + ': ' + cell(window.get('errors', [])))
        args.output.write_text('\n'.join(lines) + '\n')
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f'refused report: {error}\n')


if __name__ == '__main__':
    main()
