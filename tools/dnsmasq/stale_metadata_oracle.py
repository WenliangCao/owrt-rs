#!/usr/bin/env python3
"""Frozen-clock exact C answer_request stale/filtered metadata and full replies.

No Rust code produces the expected results. Each configuration has a reusable
command stream, raw C trace and parsed metadata. A separate Q replay verifies
the old reply-only protocol is unchanged by the added T output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

import local_answer_diff
from local_answer_diff import dns_semantics

ROOT = Path(__file__).resolve().parents[2]
SOURCE_HASHES = {
    "rfc1035.c": "231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222",
    "cache.c": "51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c",
    "dnsmasq.h": "318942419598f037a97611efbdea5aebba1e384b9a1ba5f7eded091c86e0e228",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def name(value):
    return b"".join(bytes([len(label)]) + label.encode() for label in value.split(".")) + b"\0"


def packet(host, qtype=1, flags=0x100, answers=(), authority=()):
    result = struct.pack("!6H", 0x1234, flags, 1, len(answers), len(authority), 0)
    result += name(host) + struct.pack("!HH", qtype, 1)
    for owner, kind, ttl, data in [*answers, *authority]:
        result += name(owner) + struct.pack("!HHIH", kind, 1, ttl, len(data)) + data
    return result


def profiles():
    for label, stale, minimum, maximum, reply in [
        ("disabled", None, 0, 0, 0), ("finite", 5, 0, 0, 0),
        ("forever", 0, 0, 0, 0), ("min-max", 5, 4, 12, 0),
        ("max-reply-library", 5, 0, 3, 2),
    ]:
        yield {"label": label, "cache_size": 32, "stale_seconds": stale,
               "min_cache_ttl": minimum, "max_cache_ttl": maximum, "max_reply_ttl": reply,
               "negative_ttl": 5, "scope": "library Policy boundary; max-ttl CLI remains rejected" if reply else "cache caller boundary"}


def effective_ttl(ttl, profile):
    # Used only to choose frozen input clocks, from C really_insert's clamp
    # order. Expected packets and metadata always come from the actual C run.
    if profile["max_cache_ttl"]:
        ttl = min(ttl, profile["max_cache_ttl"])
    return max(ttl, profile["min_cache_ttl"])


def corpus(profile):
    rows = []
    def emit(label, op, wire=None, now=100, limit=512):
        command = op if op in ("RESET", "M") else f"{op} {now} {limit} {wire.hex()}"
        rows.append({"case": label, "command": command})
    def ask(label, host, kind=1, now=100, limit=512, flags=0x100):
        emit(label, "T", packet(host, kind, flags), now, limit)
    def clocks(ttl):
        expiry = 100 + effective_ttl(ttl, profile)
        values = [99, 100, expiry-1, expiry, expiry+1]
        stale = profile["stale_seconds"]
        if stale is not None and stale > 0:
            values += [expiry+stale-1, expiry+stale, expiry+stale+1]
        elif stale == 0:
            values += [expiry+1000]
        else:
            values += [expiry+2]
        return sorted(set(values))
    def scenario(label, response, host, query_type, ttl):
        emit(label+"-reset", "RESET"); emit(label+"-reset-metrics", "M")
        emit(label+"-insert", "P", response); emit(label+"-insert-metrics", "M")
        for now in clocks(ttl):
            ask(label+f"-at-{now}", host, query_type, now)

    ipv4, ipv6 = bytes([192, 0, 2, 1]), bytes.fromhex("20010db8000000000000000000000001")
    soa = name("ns.test") + name("hostmaster.test") + struct.pack("!5I", 1, 2, 3, 4, 5)
    emit("initial-reset", "RESET"); emit("initial-metrics", "M")
    ask("initial-miss", "missing.test")
    for kind, data in [(1, ipv4), (28, ipv6)]:
        host = "a.test" if kind == 1 else "aaaa.test"
        scenario("address-"+str(kind), packet(host, kind, 0x8180, [(host, kind, 5, data)]), host, kind, 5)
    for label, rcode in [("nx", 3), ("nodata", 0)]:
        for have_soa in [False, True]:
            host = label + ".test"
            response = packet(host, 1, 0x8180 | rcode, authority=[("test", 6, 20, soa)] if have_soa else [])
            scenario(label+("-soa" if have_soa else "-fallback"), response, host, 1, 5)

    for label, alias_ttl, target_ttl, negative in [
        ("short-target", 20, 5, None), ("short-alias", 5, 20, None),
        ("cname-nx", 20, 5, 3), ("cname-nodata", 20, 5, 0),
    ]:
        answers = [("alias.test", 5, alias_ttl, name("target.test"))]
        if negative is None:
            answers.append(("target.test", 1, target_ttl, ipv4))
        response = packet("alias.test", 1, 0x8180 | (negative or 0), answers,
                          [("test", 6, 20, soa)] if negative is not None else [])
        # Distinct reset streams avoid one query type's expiry pruning hiding
        # what the other query type would observe at the same clock.
        for query_type in [1, 5]:
            scenario(label+f"-q{query_type}", response, "alias.test", query_type,
                     alias_ttl if query_type == 5 else min(alias_ttl, target_ttl))

    for wire_ttl in [0, 1, 20]:
        scenario(f"clamp-wire-{wire_ttl}", packet("clamp.test", 1, 0x8180, [("clamp.test", 1, wire_ttl, ipv4)]),
                 "clamp.test", 1, wire_ttl)

    expiry = 100 + effective_ttl(5, profile)
    for label, first in [("rollback-retained", expiry+1),
                         ("rollback-after-cutoff", expiry+(profile["stale_seconds"] or 0))]:
        emit(label+"-reset", "RESET")
        emit(label+"-insert", "P", packet("clock.test", 1, 0x8180, [("clock.test", 1, 5, ipv4)]))
        for index, now in enumerate([first, expiry-1, 99]):
            ask(label+f"-{index}", "clock.test", now=now)

    emit("coexist-reset", "RESET")
    emit("coexist-old-nx", "P", packet("coexist.test", 1, 0x8183))
    ask("coexist-old-nx-before", "coexist.test", now=expiry+1)
    emit("coexist-new-positive", "P", packet("coexist.test", 1, 0x8180, [("coexist.test", 1, 120, bytes([192, 0, 2, 9]))]), expiry+1)
    for kind in [1, 28, 5, 65401]:
        ask("coexist-new-query-"+str(kind), "coexist.test", kind, expiry+1)
    ask("coexist-after-old-cutoff", "coexist.test", now=expiry+5)
    emit("coexist-reload", "RESET"); emit("coexist-reload-metrics", "M")
    ask("coexist-after-reload", "coexist.test", now=expiry+5)

    emit("special-reset", "RESET")
    response = packet("alias.test", 1, 0x8180, [("alias.test", 5, 5, name("target.test")), ("target.test", 1, 5, ipv4)])
    emit("special-insert", "P", response)
    ask("stale-truncated", "alias.test", now=expiry+1, limit=40)
    ask("stale-no-rd", "alias.test", now=expiry+1, flags=0)
    ask("stale-any", "target.test", 255, expiry+1)
    emit("final-reset", "RESET"); emit("final-metrics", "M")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    build, out = args.reference_build.resolve(), args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    observed_hashes = {name: digest(build / "dnsmasq" / name) for name in SOURCE_HASHES}
    assert observed_hashes == SOURCE_HASHES
    local_answer_diff.DRIVER = Path(__file__).with_name("cache_answer_driver.c")
    oracle = local_answer_diff.build_oracle(build, out)
    identity = {"source_sha256": observed_hashes, "binary": str(oracle), "binary_sha256": digest(oracle),
                "driver_sha256": digest(local_answer_diff.DRIVER), "tool_sha256": digest(Path(__file__)),
                "copts": local_answer_diff.REFERENCE_COPTS,
                "dependencies": {name: digest(build / "deps/lib" / name) for name in ["libubus.so", "libubox.so"]}}
    (out / "identity.json").write_text(json.dumps(identity, indent=2)+"\n")
    report = {"scope": "exact C frozen-clock cache-answer metadata baseline, no Rust acceptance", "identity": identity,
              "profiles": [], "checks": [], "inject_error": args.inject_error}
    def check(label, actual, expected):
        report["checks"].append({"case": label, "actual": actual, "expected": expected, "pass": actual == expected})
    for profile in profiles():
        folder = out / profile["label"]; folder.mkdir()
        config = "no-hosts\nno-resolv\n" + "\n".join([
            f"cache-size={profile['cache_size']}", f"neg-ttl={profile['negative_ttl']}",
            f"min-cache-ttl={profile['min_cache_ttl']}", f"max-cache-ttl={profile['max_cache_ttl']}",
            f"max-ttl={profile['max_reply_ttl']}",
        ]) + "\n"
        if profile["stale_seconds"] is not None:
            config += f"use-stale-cache={profile['stale_seconds']}\n"
        conf = folder / "config.conf"; conf.write_text(config)
        rows = corpus(profile)
        commands = "\n".join(row["command"] for row in rows)+"\n"
        (folder / "commands.txt").write_text(commands)
        (folder / "cases.json").write_text(json.dumps(rows, indent=2)+"\n")
        (folder / "profile.json").write_text(json.dumps(profile, indent=2)+"\n")
        traces = []
        for side, data in [("c", commands), ("legacy-q", "\n".join("Q "+row["command"][2:] if row["command"].startswith("T ") else row["command"] for row in rows)+"\n")]:
            run = subprocess.run([str(oracle), "-C", str(conf)], input=data, text=True, capture_output=True)
            (folder / f"{side}.stdout").write_text(run.stdout); (folder / f"{side}.stderr").write_text(run.stderr)
            assert run.returncode == 0, (profile["label"], side, run.returncode)
            trace = run.stdout.splitlines(); assert len(trace) == len(rows)
            traces.append(trace)
        parsed = []
        for row, c, old in zip(rows, *traces):
            data = {**row, "output": c}
            if row["command"].startswith("T "):
                op, stale, filtered, reply = c.split(" ", 3)
                assert op == "T" and stale in ("0", "1") and filtered in ("0", "1")
                data.update(stale=int(stale), filtered=int(filtered), reply=reply, semantics=dns_semantics(reply))
                check(profile["label"]+"/"+row["case"]+"/old-Q-unchanged", reply, old)
            else:
                check(profile["label"]+"/"+row["case"]+"/old-protocol-unchanged", c, old)
            parsed.append(data)
        by_name = {row["case"]: row for row in parsed}
        check(profile["label"]+"/initial-reset", by_name["initial-metrics"]["output"], "M 0 0")
        check(profile["label"]+"/initial-miss", by_name["initial-miss"]["reply"], "NONE")
        check(profile["label"]+"/reload-reset", by_name["coexist-reload-metrics"]["output"], "M 0 0")
        check(profile["label"]+"/reload-miss", by_name["coexist-after-reload"]["reply"], "NONE")
        check(profile["label"]+"/no-filter-config", [row["filtered"] for row in parsed if "filtered" in row], [0]*sum("filtered" in row for row in parsed))
        if profile["label"] == "finite":
            check("calibration-before-expiry", by_name["address-1-at-104"]["stale"], 0)
            check("calibration-equal-expiry", by_name["address-1-at-105"]["stale"], 0)
            check("calibration-after-expiry", by_name["address-1-at-106"]["stale"], 0 if args.inject_error else 1)
            check("calibration-finite-cutoff", by_name["address-1-at-110"]["reply"], "NONE")
            check("calibration-coexist-keeps-old-nx-stale", by_name["coexist-new-query-1"]["stale"], 1)
            check("calibration-coexist-delivers-new-positive", by_name["coexist-new-query-1"]["semantics"]["flags"] & 15, 0)
        (folder / "trace.json").write_text(json.dumps(parsed, indent=2)+"\n")
        report["profiles"].append({**profile, "folder": profile["label"], "commands": len(rows),
                                   "queries": sum("stale" in row for row in parsed), "stale_true": sum(row.get("stale", 0) for row in parsed),
                                   "hits": sum(row.get("reply", "NONE") != "NONE" for row in parsed),
                                   "config_sha256": digest(conf), "commands_sha256": digest(folder/"commands.txt"), "trace_sha256": digest(folder/"c.stdout")})
    report["passed"] = sum(row["pass"] for row in report["checks"])
    report["failed"] = sum(not row["pass"] for row in report["checks"])
    (out / "result.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"scope": report["scope"], "commands": sum(row["commands"] for row in report["profiles"]),
                      "queries": sum(row["queries"] for row in report["profiles"]), "passed": report["passed"], "failed": report["failed"]}))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
