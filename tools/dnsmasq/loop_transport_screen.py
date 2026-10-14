#!/usr/bin/env python3
"""Build an untimed TCP framing/allocation probe from the actual service source.

Outputs belong in private. The probe is never linked into the shipped daemon.
Builds a separate uninstrumented ELF for perf-stat instruction/cycle screening.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rustc', default='rustc')
    args = parser.parse_args()
    out = args.out.resolve()
    assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    source = args.source / 'components/dnsmasq/src/dns/service.rs'
    text = source.read_text()
    begin = text.index('#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum FrameError')
    end = text.index('#[derive(Debug)]\npub enum ServiceError')
    frame_source = text[begin:end]
    harness = Path(__file__).with_suffix('.rs')
    driver = out / 'probe.rs'
    driver.write_text('use std::io::{self, Write};\n' + frame_source + harness.read_text())
    report = {
        'source_sha256': sha(source), 'harness_sha256': sha(harness),
        'driver_sha256': sha(driver), 'binaries': {}, 'runs': [],
        'scope': 'source-extracted framing only; allocation counts are untimed; no network claims',
    }
    new_frame = 'pub struct TcpWriteFrame' in frame_source
    for tracking in (True, False):
        name = 'allocation' if tracking else 'instructions'
        binary = out / name
        argv = [args.rustc, '+1.98.1', '--edition=2021', '-O', '-A', 'dead_code',
                '--cfg', 'allocation_tracking' if tracking else 'counter_only',
                str(driver), '-o', str(binary)]
        if new_frame:
            argv += ['--cfg', 'vectored_frame']
        result = subprocess.run(argv, capture_output=True, text=True)
        (out / f'{name}.build.stderr').write_text(result.stderr)
        if result.returncode:
            raise RuntimeError(result.stderr)
        report['binaries'][name] = {'argv': argv, 'sha256': sha(binary)}
    for direction in ('receive', 'send'):
        for length in (32, 1232, 65535):
            for split in (0, 1, 2, 17):
                if direction == 'send' and split:
                    continue
                argv = [str(out / 'allocation'), direction, str(length), str(split), '1000']
                result = subprocess.run(argv, capture_output=True, text=True, check=True)
                report['runs'].append(json.loads(result.stdout))
    for length, capacity in ((32, 128), (60, 128), (1232, 2048), (65535, 65535)):
        argv = [str(out / 'allocation'), 'retained', str(length), str(capacity), '1']
        result = subprocess.run(argv, capture_output=True, text=True, check=True)
        report['runs'].append(json.loads(result.stdout))
    (out / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
