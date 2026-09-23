#!/usr/bin/env python3
"""Oracle-only, two independent build roots; never concurrent with timing."""
import concurrent.futures
import json
from pathlib import Path
import subprocess

ROOT = Path('/home/ubuntu/r135')


def build(label):
    out = ROOT / 'build-01' / label
    if label == 's1b1k1':
        assert (out / 'binary.sha256').read_text().split()[0] == '98d7ff9ddd04db45d9d71b8f7a4f317f193c3539752532c30f01075e0e7197c0'
        return
    with (ROOT / f'build-{label}.log').open('wb') as log:
        subprocess.run(['bash', str(ROOT / 'tools/build_variant.sh'),
                        str(ROOT / 'variants-01' / label / 'components'), str(out),
                        f'/tmp/owrt-build/r135/build-01-{label}'], stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    print(f'BUILT {label}', flush=True)


if __name__ == '__main__':
    labels = [v['label'] for v in json.loads((ROOT / 'variants-01/variants.json').read_text())['variants']]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(build, labels))
