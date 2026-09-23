#!/usr/bin/env python3
"""Reproduce exact R136 twice, adding only a linker map to the second build."""
import argparse
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'r137'))
import build_batch as fixed

EXPECTED = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--reference-plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if pwd.getpwuid(os.geteuid()).pw_name != 'ubuntu':
        parser.error('run as ubuntu; only private namespace setup uses sudo')
    source, output = fixed.outside_mount(args.components), fixed.outside_mount(args.output)
    root = Path(__file__).resolve().parents[2]
    builder, runner = root / 'tools/r135/build_variant.sh', root / 'tools/r137/namespace_build.sh'
    reference = json.loads(args.reference_plan.read_text())
    control = next(x for x in reference['variants'] if x['label'] == 'control')
    hashes = fixed.source_hashes(source)
    if len(hashes) != 30 or hashes != control['source_sha256']:
        parser.error('source differs from the 30 frozen R140 control inputs')
    if output.exists() or fixed.sha256(builder) != fixed.BUILDER_SHA256:
        parser.error('output must be new and original build recipe must match')
    old = 'cargo build --release --locked --manifest-path "$fixed/ubusd/Cargo.toml" --target-dir "$out/target"'
    new = ('cargo rustc --release --locked --bin ubusd-rs --manifest-path "$fixed/ubusd/Cargo.toml" '
           '--target-dir "$out/target" -- -Clink-arg=-Wl,-Map="$out/r136.map",--print-map-locals')
    recipe = builder.read_text()
    if recipe.count(old) != 1:
        parser.error('original cargo command is not unique')
    subprocess.run(['sudo', '-n', 'true'], check=True)
    output.mkdir(parents=True, exist_ok=False)
    map_builder = output / 'map-recipe.sh'
    map_builder.write_text(recipe.replace(old, new))
    subprocess.run(['bash', '-n', str(map_builder)], check=True)
    manifest = output / 'input-manifest.json'
    fixed.write_json(manifest, {'schema': 1, 'variants': [
        {'label': label, 'components': str(source), 'expected_sha256': EXPECTED}
        for label in ('control', 'symbols')]})
    plan = fixed.freeze_plan(manifest, output, builder, runner, 1)
    plan.update({'scope': 'R145 exact R136 diagnostic symbols only; no daemon execution',
                 'adapter_sha256': fixed.sha256(Path(__file__)),
                 'reference_plan_sha256': fixed.sha256(args.reference_plan),
                 'map_recipe_sha256': fixed.sha256(map_builder),
                 'only_recipe_change': {'from': old, 'to': new},
                 'rustc_verbose': subprocess.check_output([
                     '/home/ubuntu/.rustup/toolchains/1.98.1-aarch64-unknown-linux-gnu/bin/rustc', '-vV'], text=True),
                 'acceptance': 'Both complete sstripped ELF hashes must equal exact R136; no text-only fallback.'})
    fixed.write_json(output / 'frozen-plan.json', plan)
    parent = os.readlink('/proc/self/ns/mnt')
    records = [fixed.build_one(item, output, builder if item['label'] == 'control' else map_builder, runner)
               for item in plan['variants']]
    flags = {}
    for item in records:
        if item['status'] == 'built':
            fingerprints = list(item['namespace']['cargo_dependency_fingerprints'].values())
            if len(fingerprints) == 1:
                flags[item['label']] = fingerprints[0]['rustflags']
    map_path = output / 'symbols/r136.map'
    passed = (all(x['status'] == 'built' and x['namespace']['mount_namespace'] != parent for x in records)
              and len(flags) == 2 and flags['control'] == flags['symbols']
              and map_path.is_file() and map_path.stat().st_size > 0
              and fixed.source_hashes(source) == hashes
              and fixed.sha256(builder) == plan['builder_sha256']
              and fixed.sha256(runner) == plan['namespace_runner_sha256']
              and fixed.sha256(map_builder) == plan['map_recipe_sha256']
              and fixed.sha256(Path(__file__)) == plan['adapter_sha256'])
    fixed.write_json(output / 'results.json', {
        'schema': 1, 'passed': passed, 'frozen_plan_sha256': fixed.sha256(output / 'frozen-plan.json'),
        'parent_mount_namespace': parent, 'effective_dependency_rustflags': flags, 'variants': records,
        'map_sha256': fixed.sha256(map_path) if map_path.is_file() else None,
        'map_bytes': map_path.stat().st_size if map_path.is_file() else None})
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
