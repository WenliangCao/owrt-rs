#!/usr/bin/env python3
"""Exact C do_doctor packet/event ordering versus bounded Rust primitive.

The unchanged reference objects use a deterministic callback-transport fixture.
Malformed cross-RDATA behavior is retained as a failing reference difference,
not reproduced or normalized into a compatibility pass.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

import local_answer_diff

ROOT = Path(__file__).resolve().parents[2]
RFSHA = "231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def name(text):
    if isinstance(text, bytes):
        return bytes([len(text)]) + text + b"\0"
    return b"".join(bytes([len(part)]) + part.encode() for part in text.split(".")) + b"\0"


def rr(owner, kind, value, ttl=120, cls=1, declared=None):
    owner = owner if isinstance(owner, bytes) else name(owner)
    return owner + struct.pack("!HHIH", kind, cls, ttl, len(value) if declared is None else declared) + value


def packet(answers=(), authority=(), additional=(), flags=0x85a0, question=None):
    question = name("Question.test") + b"\0\1\0\1" if question is None else question
    return struct.pack("!6H", 0x2345, flags, bool(question), len(answers), len(authority), len(additional)) + question + b"".join([*answers, *authority, *additional])


def corpus():
    a = bytes([192, 0, 2, 1])
    a6 = bytes.fromhex("20010db8000000000000000000000001")
    alias = "alias=192.0.2.0,198.51.100.0,255.255.255.0\n"
    mixed = packet([rr(b"\xc0\x0c", 1, a), rr("Answer6.test", 28, a6), rr("unknown.test", 65401, b"opaque")],
                   [rr("Authority.test", 1, a)], [rr("Additional.test", 1, a, ttl=0xffffffff)])
    yield "udp-mixed-no-data", "", 1, mixed, "-,-,-", False
    yield "udp-mixed-rewrite", "", 1, mixed, "192.0.2.9,2001:db8::9,192.0.2.8", False
    yield "udp-same-address", "", 1, mixed, "=,=,=", False
    yield "udp-invalid-family", "", 1, mixed, "2001:db8::9,192.0.2.9,invalid", False
    yield "static-only", alias, 0, mixed, "-", False
    yield "callback-before-static-match", "alias=198.51.100.0,203.0.113.0,255.255.255.0\n", 1, packet([rr("a.test", 1, a)]), "198.51.100.7", False
    yield "callback-before-static-no-match", alias, 1, packet([rr("a.test", 1, a)]), "203.0.113.7", False
    yield "later-alias-first", alias + "alias=192.0.2.1,203.0.113.9\n", 0, packet([rr("a.test", 1, a)]), "-", False
    yield "first-match-stops-alias-chain", "alias=198.51.100.0,203.0.113.0,255.255.255.0\n" + alias, 0, packet([rr("a.test", 1, a)]), "-", False
    yield "static-noop-clears-aa", "alias=192.0.2.1,192.0.2.1\n", 0, packet([rr("a.test", 1, a)]), "-", False
    yield "static-zero-mask-noop", "alias=0.0.0.0,203.0.113.0,0.0.0.0\n", 0, packet([rr("a.test", 1, a)]), "-", False
    yield "noncontiguous-mask", "alias=192.0.2.0,198.0.51.0,255.0.255.0\n", 0, packet([rr("a.test", 1, a)]), "-", False
    for last in [0, 1, 2, 3, 4]:
        yield f"inclusive-range-{last}", "alias=192.0.2.1-192.0.2.3,198.51.100.0,255.255.255.0\n", 0, packet([rr("a.test", 1, bytes([192, 0, 2, last]))]), "-", False
    for ttl in [0, 1, 0x7fffffff, 0x80000000, 0xffffffff]:
        yield f"ttl-{ttl}", "", 1, packet([rr("a.test", 1, a, ttl)]), "192.0.2.9", False
    for label in [b"a.b", b"a\\b", b"a\0b", b"a\x01b", b"a\xffb"]:
        yield "binary-owner-" + label.hex(), "", 1, packet([rr(name(label), 1, a)]), "-", False
    yield "skip-non-in", alias, 1, packet([rr("chaos.test", 1, a, cls=3)], [], [rr("a.test", 1, a)]), "192.0.2.9", False
    yield "authority-only-not-walked", alias, 1, packet([], [rr("ns.test", 1, a)]), "192.0.2.9", False
    yield "skip-authority-bad-pointer", alias, 1, packet([], [rr(b"\xff\xff", 1, a)], [rr("a.test", 1, a)]), "192.0.2.9", False
    yield "additional-without-answers", alias, 1, packet([], [rr("ns.test", 1, a)], [rr("a.test", 1, a)]), "192.0.2.9", False
    yield "extended-address-rdata", alias, 1, packet([rr("a.test", 1, a + b"extra")]), "192.0.2.9", False
    yield "short-a-rdata-crosses-record", "", 1, packet([rr("a.test", 1, b"\xc0\0"), rr("next.test", 1, a)]), "192.0.2.9", True
    yield "short-aaaa-preserves-earlier-static", alias, 0, packet([rr("a.test", 1, a), rr("next.test", 28, bytes(15))]), "-", True
    yield "declared-long-rdata", alias, 1, packet([rr("a.test", 1, a, declared=40)]), "192.0.2.9", False
    yield "malformed-later-name-keeps-earlier-effects", alias, 1, packet([rr("a.test", 1, a), rr(b"\xff\xff", 1, a)]), "192.0.2.9", False
    yield "broken-authority-keeps-answer-effects", alias, 1, packet([rr("a.test", 1, a)], [rr("ns.test", 16, b"", declared=100)], [rr("tail.test", 1, a)]), "192.0.2.9", False
    yield "zero-questions", alias, 1, packet([rr("a.test", 1, a)], question=b""), "192.0.2.9", False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    build = args.reference_build.resolve()
    out = args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    obj = build / "dnsmasq"
    local_answer_diff.validate_reference_variant(obj)
    assert digest(obj / "rfc1035.c") == RFSHA
    renamed = local_answer_diff.rename_main(obj, out)
    deps = build / "deps/lib"
    oracle, probe = out / "oracle", out / "probe"
    with (out / "build.log").open("w") as log:
        subprocess.run(["cc", *local_answer_diff.REFERENCE_COPTS, "-O2", "-Wall", "-Wextra", "-Werror",
                        f"-I{obj}", f"-I{build / 'deps/include'}", str(Path(__file__).with_name("doctor_packet_driver.c")),
                        *map(str, sorted(p for p in obj.glob("*.o") if p.name not in {"ubus.o", "dnsmasq.o", "dnsmasq-renamed.o"})), str(renamed),
                        f"-L{deps}", f"-Wl,-rpath,{deps}", "-Wl,--wrap=log_query", "-Wl,--wrap=inet_pton", "-lubus", "-lubox", "-o", str(oracle)], stdout=log, stderr=log, check=True)
        subprocess.run([args.cargo, "+1.98.1", "build", "--manifest-path", str(ROOT / "components/dnsmasq/Cargo.toml"),
                        "--lib", "--target-dir", str(out / "target")], stdout=log, stderr=log, check=True)
        subprocess.run([str(Path(args.cargo).with_name("rustc")), "+1.98.1", "--edition=2021", str(Path(__file__).with_name("doctor_packet_probe.rs")),
                        "--extern", f"dnsmasq_rs={out / 'target/debug/libdnsmasq_rs.rlib'}", "-L", f"dependency={out / 'target/debug/deps'}",
                        "-o", str(probe)], stdout=log, stderr=log, check=True)
    rows = []
    for label, config, notify, wire, responses, boundary in corpus():
        folder = out / label
        folder.mkdir()
        conf = folder / "config"
        conf.write_text("no-hosts\nno-resolv\n" + config)
        data = f"{notify} {wire.hex()} {responses}\n"
        (folder / "input").write_text(data)
        c = subprocess.run([str(oracle), "-C", str(conf)], input=data, capture_output=True, text=True)
        (folder / "c.stdout").write_text(c.stdout); (folder / "c.stderr").write_text(c.stderr)
        assert c.returncode == 0, (label, "C exit", c.returncode)
        # Both primitives use the exact configuration representation read by C;
        # this tool does not claim a Rust alias CLI/parser implementation.
        aliases = folder / "aliases"
        aliases.write_text("\n".join(line for line in c.stdout.splitlines() if line.startswith("D ")) + "\n")
        rust = subprocess.run([str(probe), str(aliases)], input=data, capture_output=True, text=True)
        (folder / "rust.stdout").write_text(rust.stdout); (folder / "rust.stderr").write_text(rust.stderr)
        assert rust.returncode == 0, (label, "Rust exit", rust.returncode)
        expected = [line for line in c.stdout.splitlines() if not line.startswith("D ")]
        actual = rust.stdout.splitlines()
        if label == "udp-mixed-no-data":
            assert len([line for line in expected if line.startswith("E ")]) == 3
            assert expected[-1].split()[1:5] == ["0", "0", "0", "3"]
            if args.inject_error:
                expected[-1] = expected[-1].replace("R 0 ", "R 1 ", 1)
        rows.append({"case": label, "safe_boundary_difference": boundary, "pass": expected == actual,
                     "c": expected, "rust": actual, "rust_stop": rust.stderr.strip()})
    result = {"scope": "packet primitive with deterministic callback transport; not product reply-path integration",
              "c_sha256": digest(oracle), "rust_sha256": digest(probe), "source_rfc1035_sha256": RFSHA,
              "planned": len(rows), "passed": sum(row["pass"] for row in rows), "failed": sum(not row["pass"] for row in rows),
              "cases": rows, "inject_error": args.inject_error}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ["scope", "planned", "passed", "failed"]}))
    return bool(result["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
