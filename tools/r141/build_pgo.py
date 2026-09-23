#!/usr/bin/env python3
"""Build a generic R136 control and one explicit PGO stage; never train or run."""
import argparse
import concurrent.futures
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'r137'))
import build_batch as fixed

CONTROL_SHA = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
PROFDATA_SHA = 'c7160d195180796edf7cc4c3f087f72b5425fc9ec2d9734b956a265e506f982e'
TOOLCHAIN = Path('/home/ubuntu/.rustup/toolchains/1.98.1-aarch64-unknown-linux-gnu')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=('generate', 'use'), required=True)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--source-proof', type=Path, required=True, help='frozen R140 same-source build plan')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profdata', type=Path)
    parser.add_argument('--profdata-sha256')
    args = parser.parse_args()
    if pwd.getpwuid(os.geteuid()).pw_name != 'ubuntu':
        parser.error('run as ubuntu; only namespace setup uses sudo')
    source, output = fixed.outside_mount(args.components), fixed.outside_mount(args.output)
    root = Path(__file__).resolve().parents[2]
    builder, runner = root / 'tools/r135/build_variant.sh', root / 'tools/r137/namespace_build.sh'
    research = root / 'docs/reviews/R141_PGO_PLAN.md'
    if output.exists() or source == output or source in output.parents or any(c.isspace() for c in str(output)):
        parser.error('output must be new, without whitespace and outside source')
    if fixed.sha256(builder) != fixed.BUILDER_SHA256 or not fixed.CANONICAL.parent.is_dir():
        parser.error('canonical recipe or mount parent mismatch')
    import json
    proof = json.loads(args.source_proof.read_text())
    expected_sources = {x['label']: x['source_sha256'] for x in proof['variants']}
    sources = fixed.source_hashes(source)
    if len(sources) != 30 or set(expected_sources) != {'control', 'a53'} or any(x != sources for x in expected_sources.values()):
        parser.error('source differs from the frozen 30-file R136/R140 snapshot')
    profdata = None
    if args.stage == 'generate':
        if args.profdata or args.profdata_sha256:
            parser.error('generate does not accept profile-use inputs')
        extra = [f'-Cprofile-generate={output / "profile-default"}']
    else:
        if not args.profdata or not re.fullmatch('[0-9a-f]{64}', args.profdata_sha256 or ''):
            parser.error('use requires explicit --profdata and --profdata-sha256')
        profdata = fixed.outside_mount(args.profdata)
        if any(c.isspace() for c in str(profdata)) or fixed.sha256(profdata) != args.profdata_sha256:
            parser.error('profile-use path/identity mismatch')
        extra = [f'-Cprofile-use={profdata}', '-Cllvm-args=-pgo-warn-missing-function']
    rustc = TOOLCHAIN / 'bin/rustc'
    merger = TOOLCHAIN / 'lib/rustlib/aarch64-unknown-linux-gnu/bin/llvm-profdata'
    version = subprocess.check_output([str(rustc), '-vV'], text=True)
    merger_version = subprocess.check_output([str(merger), '--version'], text=True)
    if ('release: 1.98.1' not in version or 'LLVM version: 22.1.8' not in version
            or fixed.sha256(merger) != PROFDATA_SHA or '22.1.8-rust-1.98.1-stable' not in merger_version):
        parser.error('pinned compiler or profile tool mismatch')
    profiler = sorted((TOOLCHAIN / 'lib/rustlib/aarch64-unknown-linux-musl/lib').glob('libprofiler_builtins-*.rlib'))
    if len(profiler) != 1:
        parser.error('expected one installed musl profiler runtime')
    recipe = builder.read_text()
    line = re.findall(r'^export RUSTFLAGS=".*"$', recipe, re.M)
    if len(line) != 1 or 'target-cpu' in recipe or 'profile-generate' in recipe or 'profile-use' in recipe:
        parser.error('unexpected original RUSTFLAGS recipe')
    changed = line[0][:-1] + ' ' + ' '.join(extra) + '"'
    stage_recipe = recipe.replace(line[0], changed, 1)
    subprocess.run(['sudo', '-n', 'true'], check=True)
    output.mkdir(parents=True, exist_ok=False)
    stage_builder = output / f'{args.stage}-recipe.sh'
    stage_builder.write_text(stage_recipe)
    subprocess.run(['bash', '-n', str(stage_builder)], check=True)
    manifest = output / 'input-manifest.json'
    fixed.write_json(manifest, {'schema': 1, 'variants': [
        {'label': 'control', 'components': str(source), 'expected_sha256': CONTROL_SHA},
        {'label': args.stage, 'components': str(source)}]})
    plan = fixed.freeze_plan(manifest, output, builder, runner, 2)
    plan.update({'scope': f'R141 generic R136 PGO {args.stage} build only; no training, timing or router access',
                 'stage': args.stage, 'adapter_sha256': fixed.sha256(Path(__file__)),
                 'research_plan_sha256': fixed.sha256(research),
                 'source_proof_sha256': fixed.sha256(args.source_proof),
                 'rustc_verbose': version, 'llvm_profdata': {'path': str(merger), 'sha256': PROFDATA_SHA, 'version': merger_version},
                 'profiler_runtime': {'path': str(profiler[0]), 'sha256': fixed.sha256(profiler[0])},
                 'stage_builder': str(stage_builder), 'stage_builder_sha256': fixed.sha256(stage_builder),
                 'rustflags_assignment': {'control': line[0], args.stage: changed}, 'extra_flags': extra,
                 'profile_input': None if profdata is None else {'path': str(profdata), 'sha256': args.profdata_sha256},
                 'profile_output_default': str(output / 'profile-default') if args.stage == 'generate' else None,
                 'training_environment': 'LLVM_PROFILE_FILE=<absolute owned per-case directory>/default_%m_%p.profraw',
                 'std_rebuilt': False, 'cpu_target': 'original generic; no target-cpu override'})
    fixed.write_json(output / 'frozen-plan.json', plan)
    parent_namespace = os.readlink('/proc/self/ns/mnt')
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(fixed.build_one, item, output,
                               builder if item['label'] == 'control' else stage_builder, runner)
                   for item in plan['variants']]
        records = [future.result() for future in futures]
    passed = (all(item['status'] == 'built' for item in records)
              and all(item['namespace']['mount_namespace'] != parent_namespace for item in records)
              and fixed.sha256(builder) == plan['builder_sha256']
              and fixed.sha256(runner) == plan['namespace_runner_sha256']
              and fixed.sha256(stage_builder) == plan['stage_builder_sha256']
              and fixed.sha256(Path(__file__)) == plan['adapter_sha256']
              and (profdata is None or fixed.sha256(profdata) == args.profdata_sha256))
    flags = {}
    for record in records:
        if record['status'] != 'built':
            continue
        fingerprints = list(record['namespace']['cargo_dependency_fingerprints'].values())
        if len(fingerprints) != 1:
            passed = False
        else:
            flags[record['label']] = fingerprints[0]['rustflags']
    passed = passed and flags.get(args.stage) == flags.get('control', []) + extra
    fixed.write_json(output / 'results.json', {'schema': 1, 'passed': passed, 'stage': args.stage,
                     'frozen_plan_sha256': fixed.sha256(output / 'frozen-plan.json'),
                     'parent_mount_namespace': parent_namespace, 'effective_rustflags': flags, 'variants': records})
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
