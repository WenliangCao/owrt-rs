#!/usr/bin/env python3
"""Exact C cache_find_non_terminal versus read-only Rust name membership."""
import argparse
import json
from pathlib import Path
import subprocess

import cache_metrics_diff as base
import local_answer_diff

ROOT = Path(__file__).resolve().parents[2]


def scenarios():
    yield "kinds", 8, 0, ["B", "I address.test 1 60 1 0 100", "I nodata.test 28 60 0 1 100",
        "I nx.test 65536 60 0 1 100", "I txt.test 16 60 4 0 100", "C", "P address.test 100",
        "P ADDRESS.TEST 100", "P nodata.test 100", "P nx.test 100", "P txt.test 100", "P test 100"]
    yield "pending", 4, 0, ["B", "I pending.test 1 60 1 0 100", "P pending.test 100", "C",
        "P pending.test 100", "B", "I pending.test 1 60 2 0 101", "P pending.test 101",
        "B", "P pending.test 101", "C", "P pending.test 101"]
    yield "invalid-cname", 8, 0, ["B", "I alias.test 5 120 0 0 100", "I target.test 1 1 9 0 100",
        "L 0 1", "C", "P alias.test 100", "P target.test 102", "P target.test 100",
        "P alias.test 102", "Q target.test 1 102", "P alias.test 102", "P alias.test 100"]
    yield "no-lru-touch", 2, 0, ["B", "I old.test 1 60 1 0 100", "C", "B", "I newer.test 1 60 2 0 100", "C",
        "P old.test 100", "P old.test 100", "B", "I third.test 1 60 3 0 101", "C",
        "Q old.test 1 101", "Q newer.test 1 101", "Q third.test 1 101"]
    yield "exact-name", 4, 0, ["B", "I child.parent.test 1 60 1 0 100", "C",
        "P child.parent.test 100", "P parent.test 100", "P test 100", "P unrelated.test 100"]
    for stale in (0, 5, -1):
        yield f"expiry-{stale}", 4, stale, ["B", "I a.test 1 10 1 0 100", "C",
            "P a.test 109", "P a.test 110", "P a.test 114", "P a.test 115", "P a.test 100",
            "Q a.test 1 115", "P a.test 100"]
        yield f"zero-ttl-{stale}", 4, stale, ["B", "I a.test 1 0 1 0 100", "C",
            "P a.test 100", "P a.test 104", "P a.test 105", "P a.test 100"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--c-only", action="store_true")
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    if args.c_only and args.inject_error:
        parser.error("negative control requires Rust")
    out = args.out.resolve()
    assert "private" in out.parts and not out.exists()
    out.mkdir(parents=True)
    build = args.reference_build.resolve()
    objects, deps = build / "dnsmasq", build / "deps/lib"
    local_answer_diff.validate_reference_variant(objects)
    assert base.digest(objects / "cache.c") == base.CACHE_SHA
    renamed = local_answer_diff.rename_main(objects, out)
    c_source = (ROOT / "tools/dnsmasq/cache_metrics_driver.c").read_text()
    marker = "        } else if (op == 'Q') {"
    assert c_source.count(marker) == 1
    c_source = c_source.replace(marker, '''        } else if (op == 'P') {
            assert(sscanf(line, "P %503s %lld", name, &now) == 2);
            printf("P %d", cache_find_non_terminal(name, now));
''' + marker)
    # Only the existing driver gains an observer command. The included C
    # cache translation unit and its name predicate remain unchanged.
    (out / "oracle.c").write_text(c_source)
    probe_source = (ROOT / "tools/dnsmasq/cache_metrics_probe.rs").read_text()
    marker = '            "Q" => {'
    assert probe_source.count(marker) == 1
    probe_source = probe_source.replace(marker, '''            "P" => {
                let name = Name::from_ascii(words[1]).unwrap();
                let now = words[2].parse().unwrap();
                let found = cache.contains_forward_name(&name, now);
                assert_eq!(found, legacy.contains_forward_name(&name, now));
                print!("P {}", u8::from(found));
            }
''' + marker)
    (out / "probe.rs").write_text(probe_source)
    oracle, probe = out / "oracle", out / "probe"
    with (out / "build.log").open("w") as log:
        subprocess.run(["cc", *local_answer_diff.REFERENCE_COPTS, "-O2", "-Wall", "-Wextra", "-Werror",
                        f"-I{objects}", f"-I{build / 'deps/include'}", str(out / "oracle.c"),
                        *map(str, sorted(p for p in objects.glob("*.o") if p.name not in {"cache.o", "dnsmasq.o", "dnsmasq-renamed.o"})),
                        str(renamed), f"-L{deps}", f"-Wl,-rpath,{deps}", "-lubus", "-lubox", "-o", str(oracle)],
                       stdout=log, stderr=log, check=True)
        if not args.c_only:
            subprocess.run([args.cargo, "+1.98.1", "build", "--manifest-path", str(ROOT / "components/dnsmasq/Cargo.toml"),
                            "--lib", "--target-dir", str(out / "target")], stdout=log, stderr=log, check=True)
            subprocess.run([str(Path(args.cargo).with_name("rustc")), "+1.98.1", "--edition=2021", str(out / "probe.rs"),
                            "--extern", f"dnsmasq_rs={out / 'target/debug/libdnsmasq_rs.rlib'}",
                            "-L", f"dependency={out / 'target/debug/deps'}", "-o", str(probe)], stdout=log, stderr=log, check=True)
    report = {"c_cache_sha256": base.CACHE_SHA, "tool_sha256": base.digest(Path(__file__)),
              "c_driver_sha256": base.digest(out / "oracle.c"), "oracle_sha256": base.digest(oracle),
              "rust_cache_sha256": base.digest(ROOT / "components/dnsmasq/src/dns/cache.rs"),
              "probe_sha256": None if args.c_only else base.digest(probe), "c_only": args.c_only,
              "injected_error": args.inject_error, "cases": [], "failures": []}
    for label, capacity, stale, commands in scenarios():
        work = out / label
        work.mkdir()
        config = work / "config"
        config.write_text(f"no-hosts\nno-resolv\ncache-size={capacity}\n" +
                          ("use-stale-cache=0\n" if stale == -1 else f"use-stale-cache={stale}\n" if stale else ""))
        wire = "\n".join(commands) + "\n"
        (work / "input").write_text(wire)
        outputs = []
        for side, command in [(f"c-{i}", [str(oracle), "-C", str(config)]) for i in range(3)] + (
                [] if args.c_only else [("rust", [str(probe), str(capacity), str(stale)])]):
            result = subprocess.run(command, input=wire, text=True, capture_output=True)
            (work / f"{side}.stdout").write_text(result.stdout)
            (work / f"{side}.stderr").write_text(result.stderr)
            result.check_returncode()
            rows = result.stdout.splitlines()
            assert len(rows) == len(commands)
            outputs.append(rows)
        assert outputs[0] == outputs[1] == outputs[2], "C reference unstable"
        if label == "kinds":
            assert [row.split(" | ")[0] for row in outputs[0][-6:]] == ["P 1", "P 1", "P 1", "P 0", "P 1", "P 0"]
        actual = outputs[-1].copy()
        if args.inject_error and label == "kinds":
            actual[6] = actual[6].replace("P 1", "P 0")
        differences = [] if args.c_only else [{"index": index, "command": commands[index], "c": c, "rust": rust}
            for index, (c, rust) in enumerate(zip(outputs[0], actual)) if c != rust]
        report["cases"].append({"label": label, "commands": len(commands),
                                 "presence_checks": sum(line.startswith("P ") for line in commands),
                                 "differences": differences})
    report["commands"] = sum(row["commands"] for row in report["cases"])
    report["presence_checks"] = sum(row["presence_checks"] for row in report["cases"])
    report["mismatches"] = sum(len(row["differences"]) for row in report["cases"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "cases"}))
    return int(bool(report["mismatches"] or report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
