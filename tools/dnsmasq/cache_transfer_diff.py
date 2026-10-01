#!/usr/bin/env python3
"""Freeze exact-C child cache pipe/import effects before Rust implementation.

Full native reference objects and matching source rebuilt with the target SDK
both execute the unmodified cache.c over a real child/parent pipe. This is a
primitive source oracle, not a claim to run a modified stock image ELF.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess

import local_answer_diff as reference

NATIVE_SHA = "bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431"
CACHE_SHA = "51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c"
IDENTITY_SHA = "62cec0e9dda0265cb9c4f6af27f7d23067aed967afab3c74e37370149a8326e9"
TARGET_IDENTITY_SHA = "fb873b9abae841a6723db1660752e1a4254a626b81bac099b19d9274a0d719aa"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def cases():
    rows = []
    def add(label, child, after, *, pre=(), between=(), now=103, capacity=8, config=""):
        rows.append(dict(label=label, child=list(child), after=list(after), pre=list(pre),
                         between=list(between), now=now, capacity=capacity, config=config))
    for stale in [None, 5, 0]:
        for now in [103, 110, 111, 116]:
            add(f"expiry-{stale}-{now}", ["B", "I a.test 1 10 7 0 100", "C", "Q a.test 1 100"],
                [f"Q a.test 1 {now}"], now=now,
                config="" if stale is None else f"use-stale-cache={stale}\n")
    for low, high, ttl in [(10, 0, 1), (0, 20, 120), (30, 20, 1)]:
        add(f"ttl-clamp-{low}-{high}", ["B", f"I a.test 1 {ttl} 7 0 100", "C"],
            ["Q a.test 1 103"], config=f"min-cache-ttl={low}\nmax-cache-ttl={high}\n")
    add("multiple-transactions", ["B", "I a.test 1 60 7 0 100", "C", "B", "I b.test 1 60 8 0 100", "C"],
        ["Q a.test 1 103", "Q b.test 1 103"])
    old = ["B", "I a.test 1 60 1 0 100", "C"]
    add("uncommitted-child-removal", ["B", "I a.test 1 60 2 0 100", "Q a.test 1 100"],
        ["Q a.test 1 103"], pre=old)
    add("failed-child-removal", ["B", "I a.test 1 60 2 0 100", "I bad.test 1 0 3 0 100", "C", "Q a.test 1 100"],
        ["Q a.test 1 103"], pre=old)
    add("empty-successful-transaction", ["B", "C"], ["Q a.test 1 103", "Q b.test 1 103"],
        pre=old, between=["B", "I b.test 1 60 4 0 101"])
    add("parent-intervening-replacement", ["B", "I a.test 1 60 2 0 100", "C"], ["Q a.test 1 103"],
        pre=old, between=["B", "I a.test 1 60 3 0 101", "C"])
    add("parent-live-eviction", ["B", "I a.test 1 60 2 0 100", "C"], ["Q a.test 1 103", "Q b.test 1 103"],
        between=["B", "I b.test 1 60 3 0 101", "C"], capacity=1)
    add("parent-abort-after-removal", ["B", "I a.test 1 10 2 0 100", "I b.test 1 60 3 0 100", "C"],
        ["Q a.test 1 110", "Q b.test 1 110"], pre=old, now=110,
        between=["B", "I b.test 1 60 4 0 101", "C"])
    add("cname-multi-address", ["B", "I alias.test 5 60 0 0 100", "I target.test 1 60 7 0 100",
        "I target.test 1 60 8 0 100", "L 0 1", "C", "Q alias.test 5 100", "Q target.test 1 100"],
        ["Q alias.test 5 103", "Q target.test 1 103"])
    add("cname-chain", ["B", "I first.test 5 60 0 0 100", "I second.test 5 60 0 0 100",
        "I target.test 1 60 7 0 100", "L 0 1", "L 1 2", "C"],
        ["Q first.test 5 103", "Q second.test 5 103", "Q target.test 1 103"])
    add("dangling-cname", ["B", "I alias.test 5 60 0 0 100", "I other.test 1 60 7 0 100", "C"],
        ["Q alias.test 5 103", "Q other.test 1 103"])
    for kind in [1, 65536]:
        add(f"negative-soa-{kind}", ["B", "G zone.test 6 60 7 0 100", f"N absent.zone.test {kind} 20 zone.test 100", "C"],
            [f"Q absent.zone.test {kind} 103", "Q zone.test 6 103"])
        add(f"cname-negative-soa-{kind}", ["B", "I alias.test 5 60 0 0 100",
            f"N absent.zone.test {kind} 20 zone.test 100", "L 0 1", "G zone.test 6 60 7 0 100", "C"],
            ["Q alias.test 5 103", f"Q absent.zone.test {kind} 103", "Q zone.test 6 103"])
    for value in [7, 9]:
        add(f"parent-local-{value}", ["B", "I a.test 1 60 7 0 100", "C"], ["Q a.test 1 103"],
            between=[f"H a.test {value} 200"])
        add(f"parent-local-cname-{value}", ["B", "I alias.test 5 60 0 0 100", "I target.test 1 60 7 0 100", "L 0 1", "C"],
            ["Q alias.test 5 103", "Q target.test 1 103"], between=[f"H target.test {value} 200"])
    add("child-local-target-not-transferred", ["B", "I alias.test 5 60 0 0 100",
        "I target.test 1 60 7 0 100", "L 0 1", "C", "Q alias.test 5 100"],
        ["Q alias.test 5 103", "Q target.test 1 103"], pre=["H target.test 7 200"])
    add("parent-local-abort-after-removal", ["B", "I a.test 1 60 7 0 100", "I b.test 1 60 2 0 100", "C"],
        ["Q a.test 1 103", "Q b.test 1 103"], pre=["B", "I b.test 1 60 1 0 100", "C"],
        between=["H a.test 9 200"])
    long = 'x' * 60 + '.' + 'y' * 16
    older = 'z.' + long
    between = ["B", "I oldest.test 1 60 1 0 101", "C", "B", f"I {older} 1 60 2 0 101", "C"]
    for index in range(8):
        between += ["B", f"I filler{index}.test 1 60 3 0 101", "C"]
    add("parent-eviction-before-long-name-abort", ["B", f"I {long} 1 60 7 0 100", "C"],
        ["Q oldest.test 1 103", f"Q {long} 1 103", f"Q {older} 1 103"], capacity=10, between=between)
    return rows


def command(args, out, label, argv, *, env=None):
    run = subprocess.run(list(map(str, argv)), text=True, capture_output=True, env=env)
    (out / f"{label}.stdout").write_text(run.stdout)
    (out / f"{label}.stderr").write_text(run.stderr)
    save(out / f"{label}.command.json", {"argv": list(map(str, argv)), "exit": run.returncode})
    if run.returncode:
        raise RuntimeError(f"{label} exited {run.returncode}; retained stderr")
    return run.stdout.splitlines()


def build(args, out):
    objects = args.reference_build / "dnsmasq"
    reference.validate_reference_variant(objects)
    assert sha(objects / "dnsmasq") == NATIVE_SHA
    assert sha(objects / "cache.c") == CACHE_SHA
    assert sha(args.source_identity) == IDENTITY_SHA
    identity = json.loads(args.source_identity.read_text())
    native_objects = sorted(p for p in objects.glob("*.o") if p.name not in {"cache.o", "dnsmasq.o", "dnsmasq-renamed.o"})
    source_files = [objects / (p.stem + ".c") for p in native_objects] + [objects / "dnsmasq.c", objects / "cache.c"]
    for source in source_files:
        assert sha(source) == identity["patched_files"]["src/" + source.name], source
    driver = Path(__file__).with_name("cache_transfer_driver.c")
    flags = [*reference.REFERENCE_COPTS, '-DVERSION="2.93"', "-O2", "-Wall", "-Wextra",
             "-ffunction-sections", "-fdata-sections",
             f"-I{objects}", f"-I{args.reference_build / 'deps/include'}"]
    native = out / "native-oracle"
    renamed = reference.rename_main(objects, out)
    deps = args.reference_build / "deps/lib"
    command(args, out, "native-build", ["cc", *flags, "-Werror", driver, *native_objects, renamed,
        f"-L{deps}", f"-Wl,-rpath,{deps}", "-lubus", "-lubox", "-o", native])
    target = args.target_reference
    assert sha(target / "identity.json") == TARGET_IDENTITY_SHA
    target_identity = json.loads((target / "identity.json").read_text())
    for name, record in target_identity["files"].items():
        assert sha(target / name) == record["sha256"], name
    cc = args.sdk / "staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
    env = dict(os.environ, STAGING_DIR=str(args.sdk / "staging_dir"))
    target_objects = out / "target-objects"
    target_objects.mkdir()
    def compile_object(source):
        extra = ["-Dmain=reference_main"] if source.name == "dnsmasq.c" else []
        command(args, target_objects, source.stem, [cc, *flags, *extra, "-c", source, "-o", target_objects / (source.stem + ".o")], env=env)
    with ThreadPoolExecutor(max_workers=2) as workers:
        list(workers.map(compile_object, [p for p in source_files if p.name != 'cache.c']))
    target_oracle = out / "target-oracle"
    # The image DSOs have no section table and cannot serve as GNU ld inputs.
    # This primitive fixture uses no UBus functions; discard unreachable full
    # reference functions instead of substituting another runtime library.
    command(args, out, "target-build", [cc, *flags, "-Werror", driver, *sorted(target_objects.glob("*.o")),
        "-Wl,--gc-sections", "-o", target_oracle], env=env)
    target_command = [target / "lib/libc.so", "--library-path", target / "lib", target_oracle]
    command(args, out, "target-dependencies", [*target_command[:3], "--list", target_oracle])
    command(args, out, "native-compiler", ["cc", "--version"])
    command(args, out, "target-compiler", [cc, "--version"], env=env)
    compiler_files = [cc, cc.with_name('.' + cc.name + '.bin'),
        args.sdk / 'staging_dir/host/lib/runas.so',
        args.sdk / 'staging_dir/host/lib/ld-linux-x86-64.so.2',
        cc.parent.parent / 'lib/libc.so', cc.parent.parent / 'include/stdio.h']
    save(out / "identity.json", {"scope": "exact source primitive oracle; target SDK compiler plus image musl dependencies, not stock ELF",
        "native_reference_sha256": NATIVE_SHA, "source_identity_sha256": IDENTITY_SHA,
        "cache_source_sha256": CACHE_SHA, "compiled_sources": {p.name: sha(p) for p in source_files},
        "native_objects": {p.name: sha(p) for p in [*native_objects, renamed]}, "target_objects": {p.name: sha(p) for p in target_objects.glob('*.o')},
        "driver_sha256": sha(driver), "tool_sha256": sha(Path(__file__)), "target_compiler_wrapper_sha256": sha(cc),
        "sdk_files": {str(p.relative_to(args.sdk)): sha(p) for p in compiler_files},
        "native_oracle_sha256": sha(native), "target_oracle_sha256": sha(target_oracle),
        "target_reference_identity_sha256": TARGET_IDENTITY_SHA,
        "target_libraries": {n: r['sha256'] for n, r in target_identity['files'].items() if n.startswith('lib/')}})
    return [native], target_command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--source-identity", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--target-reference", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    native, target = build(args, out)
    schedule = cases()
    assert len(schedule) == 36
    save(out / "plan.json", schedule)
    report = {"scope": __doc__, "planned_cases": len(schedule), "cases": [], "cross_runtime_differences": []}
    for case in schedule:
        folder = out / case['label']
        folder.mkdir()
        (folder / "config").write_text(f"no-hosts\nno-resolv\ncache-size={case['capacity']}\n" + case['config'])
        for stage in ['pre', 'child', 'between', 'after']:
            (folder / stage).write_text(''.join(line + '\n' for line in case[stage]))
        suffix = [folder / name for name in ['config', 'pre', 'child', 'between', 'after']] + [str(case['now'])]
        observed = {}
        for label, prefix in [('native', native), ('target', target)]:
            runs = [command(args, folder, f'{label}-{repeat}', [*prefix, *suffix]) for repeat in range(3)]
            assert runs[0] == runs[1] == runs[2], (case['label'], label, 'reference instability')
            count = sum(len(case[stage]) for stage in ['pre', 'child', 'between', 'after'])
            transferred = sum(line.startswith('CH C 1 |') for line in runs[0])
            assert sum(line.startswith('R ') for line in runs[0]) == transferred
            assert len(runs[0]) == count + transferred, (case['label'], label, 'observation count')
            observed[label] = runs[0]
        different = observed['native'] != observed['target']
        report['cases'].append({'case': case['label'], 'native_observations': len(observed['native']),
            'target_observations': len(observed['target']), 'cross_runtime_equal': not different})
        if different:
            report['cross_runtime_differences'].append(case['label'])
    report['completed_cases'] = len(report['cases'])
    report['observations_per_runtime'] = sum(row['native_observations'] for row in report['cases'])
    calibration = (out / 'expiry-None-103/native-0.stdout').read_text().splitlines()
    assert calibration == ['R 1 | 1 0', 'CH B | 0 0', 'CH I 1 | 0 0',
        'CH C 1 | 1 0', 'CH Q 0:110:0:7 | 1 0', 'P2 Q 0:110:0:7 | 1 0']
    changed = calibration.copy()
    changed[-1] = changed[-1].replace('| 1 0', '| 2 0')
    assert sum(a != b for a, b in zip(calibration, changed)) == 1
    report['calibration'] = {'equal': len(calibration), 'changed_counter_detected': 1,
                             'all_schedules_count_checked': True}
    report['status'] = 'C-baseline-only'
    save(out / 'result.json', report)
    print(json.dumps({k: report[k] for k in ['status', 'completed_cases', 'observations_per_runtime', 'cross_runtime_differences']}))


if __name__ == '__main__':
    main()
