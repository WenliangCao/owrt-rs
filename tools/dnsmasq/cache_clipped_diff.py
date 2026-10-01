#!/usr/bin/env python3
"""Frozen-clock C/Rust cache side effects with clipped later DNS sections.

Exact C extract_addresses/answer_request supplies all expected cache answers
and insertion counters. This gate does not model UDP admission or doctor I/O.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import shutil
import struct
import subprocess

import cache_answer_diff as base
import cache_edns_diff as driver

ROOT = base.ROOT


def clipped(packet, section):
    result = bytearray(packet)
    at = {"answer": 6, "authority": 8, "additional": 10}[section]
    count = struct.unpack("!H", result[at:at+2])[0]
    result[at:at+2] = struct.pack("!H", count + 1)
    return bytes(result) + b"\0"


def fixtures(host="cached.test", target="terminal.test"):
    address = bytes([192, 0, 2, 7])
    a = base.packet(host, 1, 0x8180, [(host, 1, 53, address)])
    aaaa = base.packet(host, 28, 0x8180, [(host, 28, 53, ipaddress.ip_address("2001:db8::7").packed)])
    cname = base.packet(host, 1, 0x8180, [(host, 5, 60, base.name(target)), (target, 1, 53, address)])
    soa = base.name("ns.test") + base.name("hostmaster.test") + struct.pack("!5I", 1, 2, 3, 4, 17)
    negative = base.packet(host, 1, 0x8183, authority=[("test", 6, 40, soa)])
    cases = [("complete-a", a, 1), ("complete-aaaa", aaaa, 28), ("complete-cname", cname, 1)]
    for label, packet, kind in list(cases):
        for section in ("authority", "additional"):
            cases.append((label + "-clipped-" + section, clipped(packet, section), kind))
    cases += [
        ("negative-soa-clipped-additional", clipped(negative, "additional"), 1),
        ("negative-soa-before-clipped-authority", clipped(negative, "authority"), 1),
        ("negative-clipped-authority-fallback", clipped(base.packet(host, 1, 0x8183), "authority"), 1),
        ("nodata-clipped-additional-fallback", clipped(base.packet(host, 1, 0x8180), "additional"), 1),
        ("clipped-answer", a[:-1], 1),
        ("complete-answer-before-clipped-answer", clipped(a, "answer"), 1),
        ("cname-before-clipped-answer", cname[:-1], 1),
    ]
    assert len(cases) == 16
    return cases


def corpus():
    host = "cached.test"
    rows = []
    for label, packet, kind in fixtures(host):
        rows.append((label + "-reset", "RESET"))
        query = base.packet(host, kind).hex()
        rows.append((label + "-miss", f"Q 100 1232 {query}"))
        rows.append((label + "-insert", f"P 100 1232 {packet.hex()}"))
        for now in (100, 105, 160):
            rows.append((label + f"-query-{now}", f"Q {now} 1232 {query}"))
    return rows


def replacement_corpus():
    host = "replacement.test"
    old = base.packet(host, 1, 0x8180, [(host, 1, 53, bytes([192, 0, 2, 7]))])
    new = clipped(base.packet(host, 1, 0x8180, [(host, 1, 53, bytes([192, 0, 2, 8]))]), "answer")
    query = base.packet(host, 1).hex()
    return [("reset", "RESET"), ("old-insert", f"P 100 1232 {old.hex()}"),
            ("old-hit", f"Q 100 1232 {query}"), ("malformed-replacement", f"P 100 1232 {new.hex()}"),
            ("after-malformed", f"Q 100 1232 {query}"), ("after-five-seconds", f"Q 105 1232 {query}"),
            ("old-ttl-expired", f"Q 160 1232 {query}")]


def compare(rows, left, right):
    if len(left) != len(rows) or len(right) != len(rows):
        raise ValueError("observation count mismatch")
    return [{"label": label, "c": a, "rust": b}
            for (label, _), a, b in zip(rows, left, right) if not driver.matches(a, b)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cargo", default=shutil.which("cargo") or "cargo")
    parser.add_argument("--c-only", action="store_true")
    parser.add_argument("--corpus", choices=["sections", "replacement"], default="sections")
    args = parser.parse_args()
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    # Reuse the existing exact-object linker and independent cache caller. The
    # C status stays in stderr; cache state/counters remain the compared output.
    old = 'assert(extract_addresses(header,length,daemon->namebuff,now,NULL,NULL,0,0,0)==0);puts("P");'
    new = ('int rc=extract_addresses(header,length,daemon->namebuff,now,NULL,NULL,0,0,0);'
           'fprintf(stderr,"EXTRACT %d\\n",rc);printf("P %u %u\\n",'
           '(unsigned)daemon->metrics[METRIC_DNS_CACHE_INSERTED],'
           '(unsigned)daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);')
    assert driver.C_DRIVER.count(old) == 1
    driver.C_DRIVER = driver.C_DRIVER.replace(old, new)
    driver.RUST_DRIVER = driver.RUST_DRIVER.replace("StalePolicy::Seconds(60)", "StalePolicy::Disabled")
    old = 'daemon.cache_reply_at_with_local(&packet,now,None);println!("P");'
    new = ('daemon.cache_reply_at_with_local(&packet,now,None);'
           'println!("P {} {}",daemon.cache_counters.inserted,daemon.cache_counters.live_freed);')
    assert driver.RUST_DRIVER.count(old) == 1
    driver.RUST_DRIVER = driver.RUST_DRIVER.replace(old, new)
    c, rust = driver.build(args, out)
    config = out / "cache.conf"
    config.write_text("no-hosts\nno-resolv\nno-round-robin\ncache-size=100\nneg-ttl=30\n")
    rows = corpus() if args.corpus == "sections" else replacement_corpus()
    data = "".join(command + "\n" for _, command in rows)
    (out / "commands.txt").write_text(data)
    (out / "cases.json").write_text(json.dumps(rows, indent=2) + "\n")
    observed = {}
    for side, binary in (("c", c), ("rust", rust)):
        if binary is None: continue
        result = subprocess.run([str(binary), "-C", str(config)], input=data, text=True, capture_output=True)
        (out / f"{side}.stdout").write_text(result.stdout)
        (out / f"{side}.stderr").write_text(result.stderr)
        result.check_returncode(); observed[side] = result.stdout.splitlines()
    expected = observed["c"]
    assert len(expected) == len(rows)
    if args.corpus == "sections":
        assert len(rows) == 96 and expected[:3] == ["RESET", "T 0 NONE", "P 1 0"]
        assert expected[3].startswith("T 0 ") and not expected[3].endswith("NONE")
        assert expected[5] == "T 0 NONE"
        assert expected[-6:-3] == ["RESET", "T 0 NONE", "P 0 0"]
        assert expected[-3:] == ["T 0 NONE"] * 3
        insertion = 2
    else:
        assert len(rows) == 7 and expected[:2] == ["RESET", "P 1 0"]
        assert not expected[2].endswith("NONE") and expected[3] == "P 1 0"
        assert expected[-3:] == ["T 0 NONE"] * 3
        insertion = 1
    assert not compare(rows, expected, expected)
    changed = list(expected); changed[insertion] = "P 2 0"
    assert len(compare(rows, expected, changed)) == 1
    try: compare(rows, expected, expected[:-1])
    except ValueError: pass
    else: raise AssertionError("missing observation calibration")
    failures = compare(rows, expected, observed["rust"]) if rust else []
    report = {"corpus": args.corpus, "commands": len(rows),
              "queries": sum(command.startswith("Q ") for _, command in rows), "compared": len(rows) if rust else 0,
              "mismatches": len(failures), "failures": failures,
              "calibration": {"reference_state_anchors": 1,
                              "changed_counter": 1, "missing_observation": 1},
              "corpus_sha256": hashlib.sha256(data.encode()).hexdigest(),
              "c_sha256": base.digest(c), "rust_sha256": base.digest(rust) if rust else None,
              "source_sha256": base.HASHES,
              "scope": "frozen-time cache insertion counters and A/AAAA/CNAME/SOA negative replay with clipped later sections; no socket/policy/doctor integration"}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "failures"}))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
