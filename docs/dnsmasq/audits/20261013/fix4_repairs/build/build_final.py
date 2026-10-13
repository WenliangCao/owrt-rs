#!/usr/bin/env python3
"""Run the retained source/SDK build sequence against a new frozen phase.

The reused sequence performs ordinary units and two clean SDK source builds.
It never supplies a frozen ELF; the unchanged size budget remains authoritative.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--phase', default='final')
    args = parser.parse_args()
    root = args.root.resolve()
    source = root / ('source-' + args.phase)
    private = root / 'private'
    inherited = source / 'docs/dnsmasq/audits/20261012/fix3_repairs/build'
    invocation = private / ('build-' + args.phase + '-invocation.json')
    assert not invocation.exists(), 'fresh invocation path required'
    driver = private / 'sdk_source_build.py'
    if driver.exists():
        assert sha(driver) == sha(inherited / driver.name)
    else:
        shutil.copy2(inherited / driver.name, driver)
    receipt = {'argv': sys.argv, 'wrapper': str(Path(__file__).resolve()),
               'wrapper_sha256': sha(__file__), 'root': str(root), 'phase': args.phase,
               'sequence': str(inherited / 'build_phase.py'),
               'sequence_sha256': sha(inherited / 'build_phase.py'),
               'sdk_driver_sha256': sha(driver), 'started': time.time(), 'passed': False}
    invocation.write_text(json.dumps(receipt, indent=2) + '\n')
    try:
        spec = importlib.util.spec_from_file_location('retained_build_sequence', inherited / 'build_phase.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.ROOT = root
        sys.argv = [str(inherited / 'build_phase.py'), '--phase', args.phase]
        module.main()
        receipt['passed'] = True
    finally:
        receipt['ended'] = time.time()
        invocation.write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
