#!/usr/bin/env python3
"""Exact-C clock rollback baseline with hash-layout conditions fixed first.

The C mixing table contains ASLR-dependent pointers. Unrelated same-bucket
expiry is therefore separated from guaranteed same-name/reverse behavior.
Every rejected layout selection is retained; no answers are observed before
the layout condition is accepted. The standard lease_names_diff comparator
can run the resulting concrete commands/configuration against the Rust probe.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import lease_names_diff
import local_answer_diff

ROOT = Path(__file__).resolve().parents[2]


def ask(host, kind=1, now=1000, operation="Q", cls=1):
    wire = lease_names_diff.query(host, kind)[:-2] + cls.to_bytes(2, "big")
    return f"{operation} {now} {wire.hex()}"


def corpus():
    one = ["R", "D 1000 192.0.2.7 lease"]
    yield "same-name-expiry-sticks", "", [], one + [ask("lease"), ask("lease", now=999)]
    yield "wrong-type-lookup-still-expires-name", "", [], one + [ask("lease", 28), ask("lease", now=999)]
    yield "known-domain-check-does-not-expire", "", [], one + [ask("lease", operation="K"), ask("lease", now=999)]
    yield "non-in-class-does-not-expire", "", [], one + [ask("lease", cls=3), ask("lease", now=999)]
    yield "cname-terminal-is-touched", "cname=alias,lease\n", [], one + [ask("alias"), ask("lease", now=999)]
    yield "cname-query-does-not-touch-target", "cname=alias,lease\n", [("alias", "lease", 0)], one + [ask("alias", 5), ask("lease", now=999)]
    yield "reverse-lookup-expires-all-owners", "", [], one + ["D 1000 192.0.2.8 other", ask("9.2.0.192.in-addr.arpa", 12), ask("lease", now=999), ask("other", now=999)]
    reverse = "7.2.0.192.in-addr.arpa"
    yield "explicit-ptr-does-not-scan-reverse", f"ptr-record={reverse},manual\n", [(reverse, "lease", 0)], one + [ask(reverse, 12), ask("lease", now=999)]
    yield "untouched-different-bucket-can-revive", "", [("lease", "other", 0)], one + ["D 1000 192.0.2.8 other", ask("lease"), ask("other", now=999), ask("lease", now=999)]
    yield "parent-lookup-only-expires-parent", "", [("example", "lease.example", 0)], ["R", "D 1000 192.0.2.7 lease.example", ask("example"), ask("lease.example", now=999), ask("example", now=999, operation="K")]


def build(reference, output):
    obj = reference / "dnsmasq"
    if not obj.is_dir():
        obj = reference
    local_answer_diff.validate_reference_variant(obj)
    for name, expected in lease_names_diff.HASHES.items():
        assert hashlib.sha256((obj / name).read_bytes()).hexdigest() == expected
    renamed = local_answer_diff.rename_main(obj, output)
    objects = [p for p in sorted(obj.glob("*.o")) if p.name not in ("cache.o", "dnsmasq.o", "dnsmasq-renamed.o")]
    binary = output / "local-answer-oracle"
    deps = reference / "deps/lib"
    command = ["cc", *local_answer_diff.REFERENCE_COPTS, "-O2", "-Wall", "-Wextra", "-Werror",
        f"-I{obj}", f"-I{reference / 'deps/include'}", str(Path(__file__).with_name("lease_clock_driver.c")),
        *map(str, objects), str(renamed), f"-L{deps}", f"-Wl,-rpath,{deps}", "-lubus", "-lubox", "-o", str(binary)]
    (output / "build-command.json").write_text(json.dumps(command,indent=2)+"\n")
    with (output / "build.log").open("w") as log:
        subprocess.run(command, stdout=log, stderr=log, check=True)
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--same-bucket-diagnostic", action="store_true")
    args = parser.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    binary = build(args.reference_build.resolve(), out)
    cases = list(corpus())
    if args.same_bucket_diagnostic:
        cases = [("unrelated-same-bucket-expiry", "", [("lease", "other", 1)],
            ["R", "D 1000 192.0.2.7 lease", "D 1000 192.0.2.8 other", ask("lease"), ask("other", now=999)])]
    rows, failures = [], []
    for index, (label, extra, conditions, commands) in enumerate(cases):
        config = out / f"{index:02}.conf"
        config.write_text("no-hosts\nno-resolv\nno-round-robin\ncache-size=64\nlocal-ttl=37\n" + extra)
        selections = []
        for attempt in range(512):
            process = subprocess.Popen([str(binary), "-C", str(config)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            observed = []
            for first, second, same in conditions:
                process.stdin.write(f"V {first} {second}\n"); process.stdin.flush()
                observed.append(process.stdout.readline().strip())
            accepted = observed == [f"V {same}" for _, _, same in conditions]
            selections.append({"attempt":attempt,"conditions":conditions,"observed":observed,"accepted":accepted})
            if not accepted:
                stdout, stderr = process.communicate()
                selections[-1].update(exit=process.returncode, stdout=stdout, stderr=stderr)
                continue
            wire = "\n".join(commands)+"\n"
            stdout, stderr = process.communicate(wire)
            (out / f"{index:02}.input").write_text(wire)
            (out / f"{index:02}.stdout").write_text(stdout)
            (out / f"{index:02}.stderr").write_text(stderr)
            lease_names_diff.observations(commands, stdout)
            row = {"case":index,"label":label,"exit":process.returncode,"commands":len(commands)}
            rows.append(row)
            if process.returncode: failures.append(row)
            break
        else:
            raise RuntimeError("no matching predeclared C hash layout within 512 attempts")
        (out / f"{index:02}.selection.json").write_text(json.dumps(selections,indent=2)+"\n")
    invalid = out / "invalid.conf"; invalid.write_text("not-a-real-dnsmasq-option=1\n")
    rejected = subprocess.run([str(binary), "-C", str(invalid)], input="R\n", text=True, capture_output=True)
    (out / "invalid.stderr").write_text(rejected.stderr)
    assert rejected.returncode
    report = {"scope":"C frozen-clock lookup side effects under declared observed hash-layout conditions",
        "cases":len(rows),"rows":rows,"failures":failures,
        "calibration":{"invalid_config_rejected":1},"source_sha256":lease_names_diff.HASHES,
        "c_oracle_sha256":hashlib.sha256(binary.read_bytes()).hexdigest()}
    (out / "result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k != "rows"}))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
