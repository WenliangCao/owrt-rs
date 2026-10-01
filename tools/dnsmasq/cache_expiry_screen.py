#!/usr/bin/env python3
"""EPS1 frozen primitive screen. Preparation, C gate, allocation and timing are separate.

This never edits product code. Timing requires a successful independent C gate
and must be invoked only after coordinating a quiet host window.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import statistics
import subprocess

import dns_cache_diff as reference

ROOT = Path(__file__).resolve().parents[2]
SEED = 0x293001
COUNT = 100_000
ORDER = [["b0", "eps1"], ["eps1", "b0"], ["b0", "eps1"]]
RUST_FLAGS = ["--edition=2021", "-A", "dead_code", "-A", "unused_imports", "-A", "unused_variables",
              "-Copt-level=3", "-Clto", "-Ccodegen-units=1", "-Cpanic=abort"]
VECTORS = ["hot", "unexpired", "mixed", "expiry"]
C_MAIN = r'''
static unsigned long long mix(unsigned long long hash, unsigned long long value) {
  return (hash ^ value) * 1099511628211ULL;
}
int main(void) {
  state.cachesize=1000;state.pipe_to_parent=-1;cache_init();
  char line[4096],name[504],phase;
  unsigned type,ttl,value,negative;long long now;
  unsigned long long warm=14695981039346656037ULL,digest=14695981039346656037ULL;
  unsigned long long completed=0,hits=0,inserts=0,errors=0,warm_count=0;
  while(fgets(line,sizeof(line),stdin)) {
    assert(sscanf(line,"%c %503s %u %u %u %u %lld",&phase,name,&type,&ttl,&value,&negative,&now)==7);
    struct crec *c=NULL,*first=NULL;unsigned long long event[10]={0};
    while((c=cache_find_by_name(c,name,now,flags(type)|F_NO_RR))) {
      if(!first)first=c;event[3]++;
    }
    event[0]=first!=NULL;
    if(!first) {
      cache_start_insert();union all_addr address={0};
      if(type==1 || type==28)address.addr4.s_addr=value;
      first=cache_insert(name,&address,C_IN,now,ttl,F_FORWARD|flags(type)|(negative?F_NEG:0));
      event[1]=first!=NULL;cache_end_insert();event[2]=!insert_error;
      event[3]=first!=NULL && !insert_error;
    }
    if(first) {
      event[4]=type_of(first);event[5]=(type==1 || type==28)?first->addr.addr4.s_addr:0;
      event[6]=!!(first->flags&F_NEG);event[7]=first->ttd;
      event[8]=first->ttd<now?0:first->ttd-now;event[9]=now>first->ttd;
    }
    if(phase=='W') {
      warm_count++;for(int i=0;i<10;i++)warm=mix(warm,event[i]);
    } else if(phase=='T') {
      completed++;hits+=event[0];inserts+=event[1];
      errors+=event[3]!=1 || (!event[0] && (!event[1] || !event[2]));
      for(int i=0;i<10;i++) {digest=mix(digest,event[i]);printf(i==9?"%llu\n":"%llu ",event[i]);}
    } else assert(phase=='P');
  }
  assert(warm_count==100000 && completed==100000);
  fprintf(stderr,"SCREEN_STATS {\"completed\":%llu,\"hits\":%llu,\"inserts\":%llu,\"errors\":%llu,\"digest\":%llu,\"warm_digest\":%llu}\n",completed,hits,inserts,errors,digest,warm);
  return 0;
}
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def hot(index):
    return f"h{index:04}.test", 1 if index % 10 < 7 else 28, 120, index % 251, 0


def vectors():
    rng = random.Random(SEED)
    yield "hot", [hot(rng.randrange(800)) for _ in range(COUNT)]
    yield "unexpired", [(f"u{i:06}.test", 1 if i % 10 < 7 else 28, 120, i % 251, 0) for i in range(COUNT)]
    classes = ([0] * 7 + [1] * 2 + [2]) * (COUNT // 10)
    rng.shuffle(classes)
    unique = 0; mixed = []
    for kind in classes:
        if kind == 0: mixed.append(hot(rng.randrange(800)))
        elif kind == 1:
            mixed.append((f"m{unique:06}.test", 1 if unique % 10 < 7 else 28, 120, unique % 251, 0)); unique += 1
        else: mixed.append((f"nx{rng.randrange(16):02}.test", 65536, 30, 0, 1))
    yield "mixed", mixed
    yield "expiry", [(f"e{i:06}.test", 1 if i % 10 < 7 else 28, (1, 2, 30, 120)[i % 4], i % 251, 0) for i in range(COUNT)]


def prepare(args):
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    for sub in ("inputs", "build", "gate", "allocation", "timing"): (out / sub).mkdir()
    sources = {}
    for label, root, expected in (("b0", args.b0, args.b0_sha256), ("eps1", args.eps1, args.eps1_sha256)):
        root = root.resolve()
        assert sha(root / "components/dnsmasq/src/dns/cache.rs") == expected
        sources[label] = {"root": str(root), "sha256": {name: sha(root / "components/dnsmasq/src/dns" / name)
                                                       for name in ("cache.rs", "wire.rs", "lease_names.rs")}}
    assert sources["b0"]["sha256"]["wire.rs"] == sources["eps1"]["sha256"]["wire.rs"]
    assert sources["b0"]["sha256"]["lease_names.rs"] == sources["eps1"]["sha256"]["lease_names.rs"]
    data = []
    for name, operations in vectors():
        lines = []
        if name in ("hot", "mixed"):
            lines += ["P " + " ".join(map(str, hot(i))) + " 100" for i in range(800)]
        for phase in ("W", "T"):
            for index, operation in enumerate(operations):
                now = (100 if phase == "W" else 200) + index // 1000 if name == "expiry" else 100
                lines.append(phase + " " + " ".join(map(str, operation)) + f" {now}")
        path = out / "inputs" / f"{name}.txt"; path.write_text("\n".join(lines) + "\n")
        data.append({"name": name, "operations": COUNT, "warm_operations": COUNT, "prefill": len(lines) - COUNT * 2,
                     "input_sha256": sha(path)})
    rustc = str(Path(shutil.which(args.rustc or 'rustc')).resolve())
    compiler = subprocess.run([rustc, '--version', '--verbose'], capture_output=True, text=True, check=True).stdout
    manifest = {"sources": sources, "seed": SEED, "capacity": 1000, "vectors": data, "pair_order": ORDER,
        "rustc": rustc, "rust_compiler": compiler, "rustc_sha256": sha(Path(rustc)),
        "rust_flags": RUST_FLAGS, "tool_sha256": sha(Path(__file__)),
        "driver_sha256": sha(Path(__file__).with_suffix(".rs")),
        "plan_sha256": sha(ROOT / "docs/dnsmasq/CACHE_EXPIRY_SCREEN_V1.md"),
        "gates": {"primary_cpu_gain": .15, "hot_expiry_pair_max_regression": .05, "fixed_layout_max_bytes": 16,
                  "extra_heap_bytes": 0, "extra_per_entry_bytes": 0, "extra_allocation_calls": 0},
        "ratio_spread_rule": "primary improvement (1-median EPS1/B0 CPU ratio) must exceed max-min paired ratio spread",
        "untimed_stress": {"iterations": 2000, "capacity": 1000, "sequence": "commit earliest, publication-delete, commit late, abort pending after zero-TTL failure, clear, recommit, clear"},
        "scope": "native Linux cache primitive screen; no component/router acceptance", "status": "prepared"}
    write_json(out / "manifest.json", manifest)
    print(json.dumps({"status": "prepared", "vectors": data}, indent=2))


def load(args):
    out = args.output.resolve(); manifest = json.loads((out / "manifest.json").read_text())
    for source in manifest["sources"].values():
        assert source["sha256"] == {name: sha(Path(source["root"]) / "components/dnsmasq/src/dns" / name)
                                    for name in source["sha256"]}, "frozen source changed"
    for vector in manifest["vectors"]:
        assert sha(out / "inputs" / (vector["name"] + ".txt")) == vector["input_sha256"], "frozen vector changed"
    return out, manifest


def run(command, stem, stdin=None):
    assert not stem.with_suffix(".stdout").exists(), "every run needs a fresh evidence path"
    value = subprocess.run(command, input=stdin, capture_output=True)
    stem.with_suffix(".stdout").write_bytes(value.stdout); stem.with_suffix(".stderr").write_bytes(value.stderr)
    write_json(stem.with_suffix(".command.json"), {"command": list(map(str, command)), "exit": value.returncode})
    value.check_returncode()
    return value


def stats(stderr):
    return json.loads(next(line.removeprefix("SCREEN_STATS ") for line in stderr.decode().splitlines()
                           if line.startswith("SCREEN_STATS ")))


def gate(args):
    out, manifest = load(args)
    rustc = args.rustc or manifest['rustc']
    assert subprocess.run([rustc, '--version', '--verbose'], capture_output=True, text=True, check=True).stdout == manifest['rust_compiler']
    assert sha(Path(rustc).resolve()) == manifest['rustc_sha256']
    assert sha(Path(__file__).with_suffix('.rs')) == manifest['driver_sha256'], 'frozen driver changed'
    reference.SOURCE = args.c_source.resolve()
    reference.ROOT = Path(manifest["sources"]["b0"]["root"])
    reference.build(out / "build", rustc)
    original = (out / "build/oracle.c").read_text()
    source = original[:original.index("int main(int argc,char **argv)")] + C_MAIN
    (out / "build/screen-oracle.c").write_text(source)
    subprocess.run(["cc", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                    str(out / "build/screen-oracle.c"), "-o", str(out / "build/screen-oracle")], check=True)
    template = Path(__file__).with_suffix(".rs").read_text()
    for label in ("b0", "eps1"):
        path = out / "build" / f"{label}.rs"
        path.write_text(template.replace("/* CACHE_MODULES */", reference.rust_modules(Path(manifest["sources"][label]["root"]))))
        for instrumented in (False, True):
            command = [rustc, *RUST_FLAGS, str(path), "-o", str(out / "build" / (label + ("-alloc" if instrumented else "")))]
            if instrumented: command += ["--cfg", "allocation_tracking"]
            subprocess.run(command, check=True)
    results = []; failed = []
    for vector in manifest["vectors"]:
        name = vector["name"]; path = out / "inputs" / f"{name}.txt"
        observed = []
        for number in range(3):
            observed.append(run([str(out / "build/screen-oracle")], out / "gate" / f"{name}-c{number+1}", path.read_bytes()))
        for label in ("b0", "eps1"):
            observed.append(run([str(out / "build" / label), str(path), "trace"], out / "gate" / f"{name}-{label}"))
        expected = stats(observed[0].stderr)
        assert expected["completed"] == COUNT and expected["errors"] == 0
        equal = all(value.stdout == observed[0].stdout and stats(value.stderr) == expected for value in observed)
        assert all(len(value.stdout.splitlines()) == COUNT for value in observed)
        if not equal: failed.append(name)
        results.append({"vector": name, "expected_from_c": expected, "all_traces_equal": equal,
                        "c_trace_sha256": hashlib.sha256(observed[0].stdout).hexdigest()})
    # Calibrate a real output-row mutation rather than using a Rust-produced answer.
    first = (out / "gate/hot-c1.stdout").read_bytes(); changed = bytearray(first); changed[0] ^= 1
    assert first != changed and len(first.splitlines()) == COUNT
    report = {"results": results, "failures": failed, "normalization": "none", "c_processes_per_vector": 3,
              "correctness_rows_per_implementation": COUNT * 4, "status": "passed" if not failed else "failed",
              "rust_compiler": manifest['rust_compiler'],
              "c_compiler": subprocess.run(['cc', '--version'], capture_output=True, text=True, check=True).stdout,
              "platform": subprocess.run(['uname', '-a'], capture_output=True, text=True, check=True).stdout,
              "binaries": {name: sha(out / "build" / name) for name in ("screen-oracle", "b0", "eps1", "b0-alloc", "eps1-alloc")}}
    write_json(out / "gate.json", report); print(json.dumps(report, indent=2))
    return int(bool(failed))


def validate_result(result, expected):
    return all(result[key] == value for key, value in expected.items())


def measure(args, allocations):
    out, manifest = load(args); correctness = json.loads((out / "gate.json").read_text())
    assert correctness["status"] == "passed", "no cost data before the C correctness gate"
    expected = {row["vector"]: row["expected_from_c"] for row in correctness["results"]}
    rows = []
    orders = [["b0", "eps1"]] if allocations else ORDER
    for pair, order in enumerate(orders):
        for name in VECTORS:
            for label in order:
                binary = label + ("-alloc" if allocations else "")
                assert sha(out / "build" / binary) == correctness["binaries"][binary]
                mode = "alloc" if allocations else "timing"
                command = [str(out / "build" / binary), str(out / "inputs" / f"{name}.txt"), mode]
                if not allocations: command = ["taskset", "-c", str(args.cpu), *command]
                value = run(command, out / ("allocation" if allocations else "timing") / f"pair{pair+1}-{name}-{label}")
                result = json.loads(value.stdout)
                row = {"pair": pair + 1, "vector": name, "implementation": label, **result,
                       "correct": validate_result(result, expected[name])}
                rows.append(row)
                if not row['correct']:
                    write_json(out / ("allocation.json" if allocations else "timing.json"), rows)
                    raise RuntimeError('measured run changed C-expected results; remaining cost windows stopped')
    write_json(out / ("allocation.json" if allocations else "timing.json"), rows)
    if allocations:
        stress = {}
        for label in ("b0", "eps1"):
            value = run([str(out / "build" / (label+'-alloc')), 'stress'], out / 'allocation' / (label+'-stress'))
            stress[label] = json.loads(value.stdout)
        write_json(out / 'stress.json', stress)
    print(json.dumps({"runs": len(rows), "correct": sum(row["correct"] for row in rows), "mode": "allocation" if allocations else "timing"}))
    return int(not all(row["correct"] for row in rows))


def summarize(args):
    out, manifest = load(args)
    timings = json.loads((out / "timing.json").read_text()); allocations = json.loads((out / "allocation.json").read_text())
    assert len(timings) == 24 and len(allocations) == 8
    ratios = {}; rows = []
    for name in VECTORS:
        values = []
        for pair in (1, 2, 3):
            by = {row["implementation"]: row for row in timings if row["vector"] == name and row["pair"] == pair}
            values.append(by["eps1"]["cpu_ns"] / by["b0"]["cpu_ns"])
        ratios[name] = values
        rows.append({"vector": name, "ratios_eps1_over_b0": values, "median_cpu_gain": 1-statistics.median(values),
                     "ratio_spread": max(values)-min(values)})
    memory = []
    for name in VECTORS:
        by = {row["implementation"]: row for row in allocations if row["vector"] == name}
        deltas = {label: [right-left for left,right in zip(value["before"], value["finished"])] for label,value in by.items()}
        # Peak starts at pre-cache live bytes, unlike the cumulative allocation counters.
        for label in deltas: deltas[label][4] = by[label]["finished"][4] - by[label]["before"][3]
        balanced = all(value["dropped"][3] == value["before"][3] for value in by.values())
        layout = by["eps1"]["cache_layout"] - by["b0"]["cache_layout"]
        memory.append({"vector": name, "deltas": deltas, "drop_balanced": balanced, "cache_layout_delta": layout,
                       "passes": balanced and 0 <= layout <= 16 and by["eps1"]["entry_layout"] == by["b0"]["entry_layout"]
                       and all(eps <= base for eps,base in zip(deltas["eps1"],deltas["b0"]))})
    primary = all(row["median_cpu_gain"] >= .15 and row["median_cpu_gain"] > row["ratio_spread"] for row in rows if row["vector"] in ("unexpired", "mixed"))
    guard = all(value <= 1.05 for name in ("hot", "expiry") for value in ratios[name])
    stress = json.loads((out / 'stress.json').read_text())
    stress_delta = {label: [right-left for left,right in zip(value['before'],value['finished'])] for label,value in stress.items()}
    for label in stress_delta: stress_delta[label][4] = stress[label]['finished'][4] - stress[label]['before'][3]
    stress_ok = all(value['dropped'][3] == value['before'][3] for value in stress.values()) and all(
        eps <= base for eps,base in zip(stress_delta['eps1'],stress_delta['b0']))
    passed = primary and guard and stress_ok and all(row["passes"] for row in memory) and all(row["correct"] for row in timings+allocations)
    result = {"status": "retain-for-later-service-gate" if passed else "withdraw-from-adoption", "cpu": rows, "allocation": memory,
              "primary_cpu_gate": primary, "hot_expiry_pair_guard": guard, "extra_rounds": 0,
              "stress": {"passes": stress_ok, "deltas": stress_delta},
              "scope": "EPS1 host primitive screen only; default product unchanged; no C/component/router performance acceptance"}
    write_json(out / "result.json", result); print(json.dumps(result, indent=2)); return int(not passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "gate", "allocation", "timing", "summarize"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--b0", type=Path); parser.add_argument("--eps1", type=Path)
    parser.add_argument("--b0-sha256"); parser.add_argument("--eps1-sha256")
    parser.add_argument("--c-source", type=Path); parser.add_argument("--rustc")
    parser.add_argument("--cpu", type=int, default=0)
    args = parser.parse_args()
    assert args.output.resolve().is_relative_to(ROOT / "private"), "artifacts must remain private"
    if args.phase == "prepare": return prepare(args)
    assert os.uname().sysname == "Linux", "single native Linux host only"
    if args.phase == "gate": return gate(args)
    if args.phase == "allocation": return measure(args, True)
    if args.phase == "timing": return measure(args, False)
    return summarize(args)


if __name__ == "__main__":
    raise SystemExit(main())
