#!/usr/bin/env python3
"""Build one R136 control and one A53-only candidate in R137 private namespaces."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'r137'))
import build_batch as fixed

CONTROL_SHA = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
FLAG = '-Ctarget-cpu=cortex-a53'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cpuinfo', type=Path, required=True, help='existing router CPU evidence, not a live query')
    args = parser.parse_args()
    if pwd.getpwuid(os.geteuid()).pw_name != 'ubuntu':
        parser.error('run as ubuntu; only private namespace setup uses sudo')
    source, output = fixed.outside_mount(args.components), fixed.outside_mount(args.output)
    root = Path(__file__).resolve().parents[2]
    builder, runner = root / 'tools/r135/build_variant.sh', root / 'tools/r137/namespace_build.sh'
    research = root / 'docs/reviews/R140_A53_PLAN.md'
    if output.exists() or source == output or source in output.parents:
        parser.error('output must be new and outside source')
    if fixed.sha256(builder) != fixed.BUILDER_SHA256 or not fixed.CANONICAL.parent.is_dir():
        parser.error('canonical recipe or existing mount parent mismatch')
    cpuinfo = args.cpuinfo.read_text()
    features = [set(line.split(':', 1)[1].split()) for line in cpuinfo.splitlines() if line.startswith('Features')]
    parts = [line.split(':', 1)[1].strip() for line in cpuinfo.splitlines() if line.startswith('CPU part')]
    if len(features) != 2 or parts != ['0xd03', '0xd03'] or not all(
            {'fp', 'asimd', 'aes', 'pmull', 'sha1', 'sha2', 'crc32'} <= value for value in features):
        parser.error('stored router evidence does not establish both A53 cores/features')
    rustc = '/home/ubuntu/.rustup/toolchains/1.98.1-aarch64-unknown-linux-gnu/bin/rustc'
    version = subprocess.check_output([rustc, '-vV'], text=True)
    cpus = subprocess.check_output([rustc, '--target', 'aarch64-unknown-linux-musl', '--print', 'target-cpus'], text=True)
    if 'release: 1.98.1' not in version or 'LLVM version: 22.1.8' not in version or 'cortex-a53' not in cpus:
        parser.error('pinned compiler version or target CPU support mismatch')
    recipe = builder.read_text()
    line = re.findall(r'^export RUSTFLAGS=".*"$', recipe, re.M)
    if len(line) != 1 or 'target-cpu' in recipe:
        parser.error('canonical recipe does not have one expected RUSTFLAGS assignment')
    changed = line[0][:-1] + ' ' + FLAG + '"'
    a53_recipe = recipe.replace(line[0], changed, 1)
    if a53_recipe.replace(changed, line[0], 1) != recipe:
        parser.error('unexpected recipe difference')
    subprocess.run(['sudo', '-n', 'true'], check=True)
    output.mkdir(parents=True, exist_ok=False)
    candidate_builder = output / 'a53-recipe.sh'
    candidate_builder.write_text(a53_recipe)
    subprocess.run(['bash', '-n', str(candidate_builder)], check=True)
    manifest = output / 'input-manifest.json'
    fixed.write_json(manifest, {'schema': 1, 'variants': [
        {'label': 'control', 'components': str(source), 'expected_sha256': CONTROL_SHA},
        {'label': 'a53', 'components': str(source)}]})
    plan = fixed.freeze_plan(manifest, output, builder, runner, 2)
    plan.update({'scope': 'R140 same-source compiler target CPU experiment; build only',
                 'adapter_sha256': fixed.sha256(Path(__file__)),
                 'research_plan_sha256': fixed.sha256(research),
                 'router_cpuinfo_sha256': fixed.sha256(args.cpuinfo),
                 'router_cpu_parts': parts, 'router_cpu_features': [sorted(x) for x in features],
                 'rustc_verbose': version, 'target_cpu_supported': True,
                 'candidate_builder': str(candidate_builder), 'candidate_builder_sha256': fixed.sha256(candidate_builder),
                 'rustflags_assignment': {'control': line[0], 'a53': changed},
                 'only_recipe_difference': 'Append -Ctarget-cpu=cortex-a53 to RUSTFLAGS; std is not rebuilt.'})
    fixed.write_json(output / 'frozen-plan.json', plan)
    parent_namespace = os.readlink('/proc/self/ns/mnt')
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(fixed.build_one, item, output,
                               builder if item['label'] == 'control' else candidate_builder, runner)
                   for item in plan['variants']]
        records = [future.result() for future in futures]
    passed = (all(item['status'] == 'built' for item in records)
              and all(item['namespace']['mount_namespace'] != parent_namespace for item in records)
              and fixed.sha256(builder) == plan['builder_sha256']
              and fixed.sha256(runner) == plan['namespace_runner_sha256']
              and fixed.sha256(candidate_builder) == plan['candidate_builder_sha256']
              and fixed.sha256(Path(__file__)) == plan['adapter_sha256'])
    # The namespace record exposes Cargo's effective dependency flags, not just
    # the requested recipe. Require exactly the one frozen appended flag.
    flags = {}
    for record in records:
        if record['status'] != 'built':
            continue
        fingerprints = list(record['namespace']['cargo_dependency_fingerprints'].values())
        if len(fingerprints) != 1:
            passed = False
        else:
            flags[record['label']] = fingerprints[0]['rustflags']
    passed = passed and flags.get('a53') == flags.get('control', []) + [FLAG]
    fixed.write_json(output / 'results.json', {'schema': 1, 'passed': passed,
                     'frozen_plan_sha256': fixed.sha256(output / 'frozen-plan.json'),
                     'parent_mount_namespace': parent_namespace, 'effective_rustflags': flags, 'variants': records})
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
