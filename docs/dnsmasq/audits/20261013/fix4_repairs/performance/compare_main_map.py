#!/usr/bin/env python3
"""Bind an optional map rebuild to the original measured main ELF, or reject it."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--source', required=True, type=Path)
parser.add_argument('--baseline-plan', required=True, type=Path)
parser.add_argument('--mapped-build', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
sys.path.insert(0, str(args.source / 'tools/dnsmasq'))
from elf_size_report import Elf


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


baseline = json.loads(args.baseline_plan.read_text())['groups']['main']
build = json.loads(args.mapped_build.read_text())
original_path = Path(baseline['elf'])
mapped_path = args.mapped_build.parent / 'dnsmasq-rs'
assert sha(original_path) == baseline['sha256']
assert build['artifacts'] == [dict(path=mapped_path.name, bytes=mapped_path.stat().st_size, sha256=sha(mapped_path))]
assert Path(build['source']) == Path(baseline['build']['source'])
assert build['features'] == '' and build['opt_level'] == '3'
for name, expected in baseline['source_files'].items():
    assert sha(Path(build['source']) / name) == expected, name
link_map = args.mapped_build.parent / build['link_map']['path']
assert sha(link_map) == build['link_map']['sha256']
original, mapped = Elf(original_path), Elf(mapped_path)
report = dict(scope='Same-source map attempt; exact original ELF identity remains authoritative',
              baseline_plan_sha256=sha(args.baseline_plan), original_elf_sha256=sha(original_path),
              mapped_elf_sha256=sha(mapped_path), mapped_build_sha256=sha(args.mapped_build),
              mapped_link_map_sha256=sha(link_map), source_inputs_verified=len(baseline['source_files']),
              original_rustflags=baseline['build']['rustflags'], mapped_rustflags=build['rustflags'],
              full_elf_identical=original.data == mapped.data,
              text_identical=next(s for s in original.sections if s['name'] == '.text')['sha256'] ==
                             next(s for s in mapped.sections if s['name'] == '.text')['sha256'])
try:
    report['allocated_comparison'] = original.verify_companion(mapped)
except ValueError as error:
    report['allocated_comparison'] = dict(status='rejected', reason=str(error))
report['use_map_for_original'] = report['full_elf_identical']
report['decision'] = ('Map accepted for original ELF: complete bytes match.' if report['use_map_for_original'] else
                      'Map rejected for original ELF: retain original main with unattributed user samples.')
assert not args.output.exists()
args.output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
