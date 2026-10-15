#!/usr/bin/env python3
"""Summarize excluded actual-owner allocation/syscall evidence without raw logs."""
import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(path):
    text = path.read_text()
    assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in text
    return [(kind, json.loads(value)) for kind, value in re.findall(
        r'OWNER_(LAYOUT|COUNTS|RESOURCES|FD_CLEANUP) (\{[^\n]+\})', text)]


def syscall_stages(path):
    stages = {}
    pending = {}
    active = None
    for line in path.read_text().splitlines():
        message = re.match(r'(\d+)\s+write\(2, ("(?:\\.|[^"\\])*"),', line)
        if message:
            pid, literal = message.groups()
            pending[pid] = pending.get(pid, '') + ast.literal_eval(literal)
            while '\n' in pending[pid]:
                marker, pending[pid] = pending[pid].split('\n', 1)
                if marker.startswith('OWNER_STAGE_BEGIN '):
                    assert active is None
                    stage = marker.removeprefix('OWNER_STAGE_BEGIN ')
                    assert stage not in stages
                    stages[stage] = Counter()
                    active = (pid, stage)
                elif marker.startswith('OWNER_STAGE_END '):
                    assert active == (pid, marker.removeprefix('OWNER_STAGE_END '))
                    active = None
            continue
        call = re.match(r'(\d+)\s+(\w+)\(', line)
        if not call or not active or call[1] != active[0] or call[2] == 'write':
            continue
        key = call[2]
        if key == 'epoll_ctl':
            key += ':' + re.search(r'EPOLL_CTL_\w+', line)[0]
        failed = re.search(r'= -1 (\w+)', line)
        if failed:
            key += ':' + failed[1]
        stages[active[1]][key] += 1
    assert active is None and len(stages) > 10
    return {stage: dict(counts) for stage, counts in stages.items()}


def variant(path):
    build = json.loads((path / 'build.json').read_text())
    for name, expected in build['instrumented_files'].items():
        assert sha(path / 'input' / name) == expected, name
    assert sha(path / 'owner-allocation') == build['elf_sha256']
    observed = records(path / 'run.stdout')
    # Allocation data are from the ordinary count run. The independent trace
    # must reproduce them, but its elapsed time is never used.
    traced = records(path / 'trace-r2.stdout')
    for kind in ('LAYOUT', 'COUNTS', 'FD_CLEANUP'):
        assert [row for tag, row in observed if tag == kind] == [
            row for tag, row in traced if tag == kind], kind
    stages = syscall_stages(path / 'syscalls-complete.txt')
    counts = [row for kind, row in observed if kind == 'COUNTS']
    assert set(stages) == {row['stage'] for row in counts}
    keys = ('source_commit', 'source_digest', 'instrumented_digest',
            'driver_sha256', 'harness_sha256', 'elf_sha256', 'argv', 'owner_readiness')
    return {'private_directory': str(path), 'build': {k: build[k] for k in keys},
            'layout': next(row for kind, row in observed if kind == 'LAYOUT'),
            'allocations': counts, 'syscalls': stages,
            'resources': [row for kind, row in observed if kind == 'RESOURCES'],
            'fd_cleanup': next(row for kind, row in observed if kind == 'FD_CLEANUP'),
            'raw_artifacts': {name: {'bytes': (path / name).stat().st_size,
                                    'sha256': sha(path / name)}
                              for name in ('build.json', 'run.stdout', 'run.stderr',
                                           'syscalls.txt', 'syscalls-complete.txt',
                                           'trace-r2.stdout', 'trace-r2.stderr')}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = {'scope': 'Native allocation and syscall diagnostic, not SDK qualification or timing.',
              'summary_tool_sha256': sha(Path(__file__)),
              'allocation_fields': ['alloc_calls', 'realloc_calls', 'requested_bytes',
                                    'dealloc_calls', 'freed_bytes', 'realloc_old_bytes'],
              'resource_fields': ['backend_size', 'key_size', 'registration_size', 'event_size',
                                  'tags_capacity_bytes', 'desired_capacity_bytes',
                                  'registered_capacity_bytes', 'direct_capacity_bytes',
                                  'events_capacity_bytes'],
              'limitations': ['Single deterministic fixture per artifact, no statistical inference.',
                              'Normal waits use queued UDP or zero runnable timeout; no blocking cost claim.',
                              'Probe counts include existing probe Vec and caller dispatch.',
                              'Initial syscall trace omitted native epoll_pwait; retained, not used for totals.',
                              'Global allocator instrumentation is unsuitable for instruction/timing comparisons.',
                              'Capacity excludes allocator metadata and kernel epoll memory.'],
              'baseline': variant(args.baseline), 'candidate': variant(args.candidate)}
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'bytes': args.out.stat().st_size, 'sha256': sha(args.out)}))


if __name__ == '__main__':
    main()
