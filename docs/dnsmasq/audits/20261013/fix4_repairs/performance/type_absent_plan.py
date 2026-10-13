#!/usr/bin/env python3
"""Freeze the original TYPE65401/abcd N4 controls with exact C included."""
import argparse
import json
from pathlib import Path
import three_way

parser = argparse.ArgumentParser()
parser.add_argument('--output', required=True, type=Path)
parser.add_argument('--candidate', required=True, type=Path)
parser.add_argument('--candidate-commit', required=True)
args = parser.parse_args()
args.suite = 'ordinary'
args.warmup, args.duration = 3, 15
three_way.prepare(args)
plan_path = args.output / 'plan.json'
plan = json.loads(plan_path.read_text())
plan['windows'] = [window for window in plan['windows'] if window['profile'].startswith('tcp-absent-')]
wrapper = Path(__file__).with_name('type_absent_window.py').resolve()
for window in plan['windows']:
    assert Path(window['argv'][3]).name == 'raw_window.py'
    window['argv'][3] = str(wrapper)
plan['suite'] = 'original-type-absent-short'
plan['scope'] = 'Original N4 TYPE65401/abcd configuration, A cache hits; exact-image C/main/scan'
plan['method'] += ' Original raw payload abcd; this short control does not reproduce the prior 120-second duration.'
for path in (Path(__file__).resolve(), wrapper):
    plan['assets'][str(path)] = three_way.sha(path)
three_way.save(plan_path, plan)
print('frozen type-absent windows', len(plan['windows']))
