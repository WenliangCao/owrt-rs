#!/usr/bin/env python3
"""Attribute perf self samples to the exact stripped ELF and its build's map.

Decode an excluded diagnostic after recording (never during timed windows):
  perf script -i RUN/perf.data --hide-call-graph \
    -F pid,tid,misc,period,event,ip,sym,dso > RUN/perf-samples.txt
  perf report -i RUN/perf.data --stdio --no-children --sort dso,symbol \
    --show-nr-samples --show-total-period --percent-limit 0 -g none \
    --field-separator ';' --no-demangle > RUN/perf-self.txt

Pass --process-identity RUN/process-identity.json and --maps-after
RUN/proc-snapshots/load-finished.PID.maps from m6a_window. The running ELF hash,
build receipt, expected hash and optional map hash must agree. Without a map,
user IPs remain unattributed; no nearby-symbol or replacement-ELF guesses.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys

from elf_link_map_report import input_sections
from elf_size_report import Elf, demangle

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r121_symbolize import parse_proc_maps


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class Sample:
    pid: int
    tid: int
    mode: str
    period: int
    event: str
    ip: int
    symbol: str
    dso: str


def samples_from_text(text):
    rows = []
    pattern = re.compile(r'\s*(\d+)/(\d+)\s+([KUHGg][MESp]*)\s+(\d+)\s+'
                         r'(\S+):\s+([0-9a-fA-F]+)\s+(.+?)\s+\((.*)\)\s*')
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = pattern.fullmatch(line)
        if not match:
            raise ValueError(f'sample line {number}: expected documented perf script fields, no callgraph')
        pid, tid, mode, period, event, ip, symbol, dso = match.groups()
        if int(period) <= 0:
            raise ValueError(f'sample line {number}: nonpositive period')
        rows.append(Sample(int(pid), int(tid), mode[0], int(period), event,
                           int(ip, 16), symbol, dso))
    if not rows or len({row.event for row in rows}) != 1:
        raise ValueError('expected nonempty samples from exactly one perf event')
    return rows


def check_report(text, samples):
    lost = re.findall(r'^# Total Lost Samples:\s*([\d,]+)\s*$', text, re.M)
    if lost != ['0']:
        raise ValueError('perf report must explicitly show zero lost samples')
    count = period = 0
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        fields = [part.strip() for part in line.split(';')]
        if len(fields) < 5 or not re.fullmatch(r'\d+(?:\.\d+)?%', fields[0]):
            raise ValueError('expected documented semicolon-separated perf self report')
        count += int(fields[1])
        period += int(fields[2])
    if count != len(samples) or period != sum(row.period for row in samples):
        raise ValueError('raw sample count/period does not exactly match perf report')
    return {'samples': count, 'period': period, 'lost_samples': 0}


def elf_address(elf, mapping, ip):
    # Mapping pgoff is a file offset, not an ELF VMA or a PIE load bias.
    offset = ip - mapping.start + mapping.offset
    matches = {vaddr + offset - file_offset
               for flags, file_offset, vaddr, _, size, _, _ in elf.loads
               if flags & 1 and file_offset <= offset < file_offset + size}
    if len(matches) != 1:
        raise ValueError('sample is outside one unique executable file-backed PT_LOAD')
    return matches.pop()


def analyze(samples, elf, mappings, identity, ranges, names):
    total_period = sum(row.period for row in samples)
    counts, periods = Counter(), Counter()
    groups = defaultdict(lambda: {'samples': 0, 'period': 0, 'ips': Counter()})
    starts = [row[1] for row in ranges]
    target = identity['exe'].removesuffix(' (deleted)')
    for row in samples:
        if row.pid != identity['pid']:
            raise ValueError(f'sample PID {row.pid} differs from recorded process identity')
        category = 'kernel' if row.mode == 'K' else 'user' if row.mode == 'U' else row.mode
        counts[category] += 1
        periods[category] += row.period
        address = None
        if row.mode != 'U':
            key = (category, row.dso, row.symbol, None, None)
        else:
            matching = [m for m in mappings if 'x' in m.permissions and m.start <= row.ip < m.end]
            reason = 'no_unique_executable_mapping'
            if len(matching) == 1:
                mapping = matching[0]
                path = mapping.path.removesuffix(' (deleted)')
                reason = 'other_image'
                if path == target:
                    reported = row.dso.removesuffix(' (deleted)')
                    if reported not in ('[unknown]', target, Path(target).name):
                        raise ValueError('perf DSO conflicts with the exact process mapping')
                    address = elf_address(elf, mapping, row.ip)
                    reason = 'no_link_map' if not ranges else 'link_map_gap'
                    index = bisect_right(starts, address) - 1
                    if index >= 0:
                        _, start, size, raw = ranges[index]
                        if start <= address < start + size:
                            key = ('user_attributed', path, names[raw], start, start + size)
                            reason = None
            if reason:
                key = ('user_unmapped', row.dso, reason, None, None)
        group = groups[key]
        group['samples'] += 1
        group['period'] += row.period
        group['ips'][(row.ip, address)] += row.period
    result = []
    for (category, dso, label, start, end), values in sorted(
            groups.items(), key=lambda item: (-item[1]['period'], item[0][:3])):
        result.append({'category': category, 'dso': dso, 'label': label,
                       'elf_range': [hex(start), hex(end)] if start is not None else None,
                       'samples': values['samples'], 'period': values['period'],
                       'percent_all_period': 100 * values['period'] / total_period,
                       'ips': [{'runtime_ip': hex(ip), 'elf_vma': hex(vma) if vma is not None else None,
                                'period': period}
                               for (ip, vma), period in values['ips'].most_common()]})
    assert sum(row['samples'] for row in result) == len(samples)
    assert sum(row['period'] for row in result) == total_period
    return {'samples_by_mode': dict(counts), 'period_by_mode': dict(periods), 'ranges': result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('samples', 'report', 'elf', 'build-json', 'process-identity', 'maps-after', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--map', dest='link_map', type=Path)
    parser.add_argument('--expected-elf-sha256', required=True)
    parser.add_argument('--demangler')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output must be fresh')
    elf = Elf(args.elf)
    identity = json.loads(args.process_identity.read_text())
    build = json.loads(args.build_json.read_text())
    artifacts = [row for row in build['artifacts'] if Path(row['path']).name == args.elf.name]
    actual_sha = sha(args.elf)
    if (len(artifacts) != 1 or artifacts[0]['sha256'] != actual_sha
            or artifacts[0]['bytes'] != len(elf.data)
            or actual_sha != args.expected_elf_sha256 or identity['sha256'] != actual_sha):
        raise ValueError('ELF, expected identity, running process and build receipt disagree')
    mappings = parse_proc_maps(identity['maps'])
    after = parse_proc_maps(args.maps_after.read_text())
    target = identity['exe'].removesuffix(' (deleted)')
    executable = lambda rows: [m for m in rows if 'x' in m.permissions
                               and m.path.removesuffix(' (deleted)') == target]
    if not executable(mappings) or executable(mappings) != executable(after):
        raise ValueError('target executable mappings are absent or changed during the window')
    ranges, names, demangler = [], {}, None
    if args.link_map:
        if sha(args.link_map) != build.get('link_map', {}).get('sha256'):
            raise ValueError('map does not match this exact ELF build receipt')
        ranges = sorted(input_sections(args.link_map.read_text(), elf), key=lambda row: row[1])
        if any(a[1] + a[2] > b[1] for a, b in zip(ranges, ranges[1:])):
            raise ValueError('overlapping linker input sections cannot be assigned uniquely')
        names, demangler = demangle(sorted({row[3] for row in ranges}), args.demangler)
    samples = samples_from_text(args.samples.read_text())
    totals = check_report(args.report.read_text(), samples)
    result = analyze(samples, elf, mappings, identity, ranges, names)
    inputs = {name: {'path': str(path), 'sha256': sha(path)} for name in (
        'samples', 'report', 'elf', 'build_json', 'process_identity', 'maps_after', 'link_map')
        if (path := getattr(args, name)) is not None}
    output = {'schema': 1, 'scope': 'excluded diagnostic; self IPs, not inclusive call stacks',
              'inputs': inputs, 'elf_sha256': actual_sha, 'demangler': demangler,
              'event': samples[0].event, 'totals': totals, **result,
              'limitations': [
                  'Map ranges are emitted input sections, not inlined callees or source-line costs.',
                  'Kernel symbols are perf-reported; only the selected user ELF is map-attributed.',
                  'No map, gaps and other images remain unmapped; every sample and period is retained.',
                  'The process identity and unchanged executable mappings bind ASLR; no exec during recording.',
                  'Sample proportions do not establish the cause or absolute per-query size of a performance delta.']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'totals': totals,
                      'samples_by_mode': result['samples_by_mode'], 'period_by_mode': result['period_by_mode']}))


if __name__ == '__main__':
    main()
