#!/usr/bin/env python3
"""Prepare the no-raw ordinary TCP confirmation from the same three-way runner.

Keeps the generator/reader unchanged, but explicitly freezes only the ordinary
profile and records this selector's identity before any window is run.
"""
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
args.warmup, args.duration = 30, 120
three_way.prepare(args)
plan_path = args.output / 'plan.json'
plan = json.loads(plan_path.read_text())
plan['windows'] = [window for window in plan['windows'] if window['profile'] == 'tcp-ordinary']
plan['suite'] = 'ordinary-no-raw-long'
plan['method'] = plan['method'].replace('3s warmup/15s measure', '30s warmup/120s measure')
plan['assets'][str(Path(__file__).resolve())] = three_way.sha(__file__)
three_way.save(plan_path, plan)
print('frozen ordinary windows', len(plan['windows']))
