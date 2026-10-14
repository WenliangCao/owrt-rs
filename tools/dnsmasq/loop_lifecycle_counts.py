#!/usr/bin/env python3
"""Count syscall phases from lifecycle strace; deliberately discard all timings."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from statistics import median


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--elf-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = [json.loads(line) for line in (args.input / 'output.jsonl').read_text().splitlines()]
    assert len(rows) == 20 and all(row['ok'] for row in rows)
    runs = []
    raw = {}
    for row in rows:
        trace = args.input / f"trace.{row['pid']}"
        raw[trace.name] = hashlib.sha256(trace.read_bytes()).hexdigest()
        lines = trace.read_text().splitlines()
        # C is launched through its image loader. Exclude the shell wrapper
        # before the final successful exec; no wrapper CPU is called C cost.
        start = max(i for i, line in enumerate(lines) if ' execve(' in line and ') = 0 ' in line)
        query = next(i for i, line in enumerate(lines) if i > start and ' recvmsg(' in line and ':15353]' in line)
        stop = next(i for i, line in enumerate(lines) if '--- SIGTERM ' in line)
        phases = {}
        for name, selected in [('startup_before_dns_receive', lines[start:query]),
                               ('shutdown_after_sigterm', lines[stop:]),
                               ('whole_service', lines[start:])]:
            counts = Counter()
            for line in selected:
                match = re.match(r'[\d.]+ ([A-Za-z0-9_]+)\(', line)
                if match:
                    counts[match[1]] += 1
            phases[name] = dict(counts)
        runs.append(phases)
    summary = {}
    for phase in runs[0]:
        fields = set().union(*(row[phase] for row in runs))
        summary[phase] = {}
        for name in sorted(fields | {'TOTAL'}):
            values = [sum(row[phase].values()) if name == 'TOTAL' else row[phase].get(name, 0) for row in runs]
            summary[phase][name] = {'median': median(values), 'min': min(values), 'max': max(values)}
    report = {'elf_sha256': args.elf_sha256, 'runs': 20,
              'scope': 'Oracle strace counts, 8 hosts/6 leases, startup plus normal stop; no timing claims; driver and wrapper excluded; service child only',
              'summary': summary, 'per_run': runs, 'trace_sha256': raw}
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
