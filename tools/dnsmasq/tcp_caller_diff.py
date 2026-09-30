#!/usr/bin/env python3
"""Compare TCP caller reply/error bytes with the exact C reference functions.

No listener or production network access. C supplies all expected reply bytes;
the thin driver only supplies tcp_request's parameters and CD restoration.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

import local_answer_diff

ROOT = Path(__file__).resolve().parents[2]
FORWARD_SHA = "ac05784d4233ed10bd166da5fe91e464afecf2883d3c2a0063305d3e81692f95"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(text, marker):
    start = text.index(marker)
    brace = text.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end] + "\n"


RUST_ORACLE = r'''
pub fn caller_oracle_main() {
    use std::io::BufRead;
    let mut config = DnsConfig::default();
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    crate::config::loader::load(&args, std::path::Path::new("/etc/dnsmasq.conf"), |d, _| {
        if config.apply(d)? { Ok(()) } else { Err(crate::config::Error("unsupported probe option")) }
    }).unwrap();
    config.finalize().unwrap();
    let policy = address_policy(&config).unwrap();
    let routing = RoutingTable::from_runtime_config(&config, &[]).unwrap();
    let mut hosts = crate::hosts::Hosts::new();
    for path in config.addn_hosts.iter().flatten() {
        hosts.read(&std::fs::read(path).unwrap(), 1, 0, false, |_| None);
    }
    let local = LocalDnsService::new(config.clone(), hosts, 0, 65535);
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap(); let words: Vec<_> = line.split_whitespace().collect();
        let decode = |hex: &str| (0..hex.len()).step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect::<Vec<_>>();
        let query = decode(words[3]);
        if words[0] == "Q" {
            match query_error(&query) {
                Ok(Some(packet)) => println!("{}", packet.iter().map(|b| format!("{b:02x}")).collect::<String>()),
                Ok(None) => println!("FORWARD"),
                Err(_) => println!("CLOSE"),
            }
            continue;
        }
        let result = if words[0] == "R" {
            refusal(&query, words[1].parse().unwrap(), words[2].parse().unwrap(), TCP_LIMIT, true).map_err(TcpServiceError::Wire)
        } else {
            finish_reply(&query, &decode(words[4]), &policy, config.proxy_dnssec, words[1].parse().unwrap(), Some(&local), Some(&routing))
        };
        match result {
            Ok(packet) => println!("{}", packet.iter().map(|b| format!("{b:02x}")).collect::<String>()),
            Err(error) => println!("ERR {error:?}"),
        }
    }
}
'''


def build(args, out):
    text = (args.source / "src/forward.c").read_text()
    if sha(args.source / "src/forward.c") != FORWARD_SHA:
        raise SystemExit("forward.c identity mismatch")
    bodies = extract(text, "static int domain_no_rebind(") + extract(text, "static size_t process_reply(")
    (out / "tcp-caller-exact.inc").write_text(bodies)
    local_answer_diff.DRIVER = Path(__file__).with_name("tcp_caller_driver.c")
    c = local_answer_diff.build_oracle(args.reference_build, out)
    if args.c_only:
        return c, None
    source = out / "rust-source"
    for component in ("dnsmasq", "ubus"):
        dest = source / component
        shutil.copytree(ROOT / f"components/{component}/src", dest / "src")
        shutil.copy2(ROOT / f"components/{component}/Cargo.toml", dest / "Cargo.toml")
    shutil.copy2(ROOT / "components/dnsmasq/Cargo.lock", source / "dnsmasq/Cargo.lock")
    with (source / "dnsmasq/src/dns/tcp_service.rs").open("a") as stream:
        stream.write(RUST_ORACLE)
    binary = source / "dnsmasq/src/bin/tcp-caller-probe.rs"
    binary.parent.mkdir(exist_ok=True)
    binary.write_text("fn main() { dnsmasq_rs::dns::tcp_service::caller_oracle_main(); }\n")
    with (out / "rust-build.log").open("w") as log:
        subprocess.run([args.cargo, "build", "--frozen", "--manifest-path", str(source / "dnsmasq/Cargo.toml"),
                        "--bin", "tcp-caller-probe", "--target-dir", str(out / "target")], check=True, stdout=log, stderr=subprocess.STDOUT)
    return c, out / "target/debug/tcp-caller-probe"


def name(text):
    if not text:
        return b"\0"
    return b"".join(bytes([len(label)]) + label.encode() for label in text.split(".")) + b"\0"


def rr(kind, data, *, owner=b"\xc0\x0c", cls=1, ttl=60):
    return owner + struct.pack("!HHIH", kind, cls, ttl, len(data)) + data


def opt(options=b"", size=4096, ttl=0):
    return rr(41, options, owner=b"\0", cls=size, ttl=ttl)


def query(flags=0x100, options=None, qtype=1, ident=0x2930, qname="caller.test", cls=1):
    return struct.pack("!6H", ident, flags, 1, 0, 0, int(options is not None)) + name(qname) + struct.pack("!HH", qtype, cls) + (options or b"")


def reply(q, answer=None, additional=(), flags=0x81b0, ident=0xabcd):
    end = 12
    while q[end]: end += q[end] + 1
    question = q[12:end + 5]
    return struct.pack("!6H", ident, flags, 1, int(answer is not None), 0, len(additional)) + question + (answer or b"") + b"".join(additional)


def corpus():
    rows = []
    def add(label, config, q, response, operation="P", error=0, maximum=1232):
        rows.append({"label": label, "config": config, "line": f"{operation} {maximum} {error} {q.hex()} {response.hex()}"})
    plain = query()
    with_opt = query(options=opt())
    do_query = query(options=opt(ttl=0x8000))
    public = rr(1, bytes([192, 0, 2, 7]))
    private = rr(1, bytes([10, 0, 0, 7]))
    for ede in (14, 23):
        for flags in (0, 0x100, 0x110, 0x130, 0x7f0):
            for options in (None, opt(), opt(ttl=0x8000)):
                q = query(flags, options)
                add(f"refused-{ede}-{flags}-{options is not None}", "", q, q, "R", ede)
    for proxy in (False, True):
        config = "proxy-dnssec\n" if proxy else ""
        for flags in (0x100, 0x110, 0x120, 0x130):
            for qopt in (None, opt(), opt(ttl=0x8000)):
                q = query(flags, qopt)
                for ropt in ((), (opt(),), (opt(ttl=0x8000),)):
                    add("reply-flags", config, q, reply(q, public, ropt))
    for q in (plain, with_opt, do_query):
        for options in ((), (opt(),), (opt(ttl=0x8000),), (opt(ttl=0x1000000),)):
            add("rebind", "stop-dns-rebind\n", q, reply(q, private, options))
            add("cname-malformed", "", q, reply(q, rr(5, b"\xff\xff"), options))
            add("owner-malformed", "", q, reply(q, rr(1, b"\xc0\x00\x02\x07", owner=b"\xff\xff"), options))
    for options in (b"\x00\x0f\x00\x02\x00\x03", b"\x00\x0f\x00\x04\x00\x03xx", b"\x00\x08\x00\x00", b"\x00\x08\x00\x10x", b"x"):
        for last in (True, False):
            additions = (opt(options),) + (() if last else (rr(16, b"\x01x"),))
            add("ede-options-relocation", "stop-dns-rebind\n", with_opt, reply(with_opt, private, additions))
    for config in ("stop-dns-rebind\nrebind-domain-ok=/caller.test/\n", "stop-dns-rebind\nrebind-localhost-ok\n"):
        address = private if "domain" in config else rr(1, b"\x7f\x00\x00\x01")
        add("rebind-exception", config, do_query, reply(do_query, address, (opt(),)))
    add("tcp-large-no-truncation", "", with_opt, reply(with_opt, rr(16, b"x" * 4096), (opt(),)))
    add("trailing-junk", "", plain, reply(plain, public) + b"trailing")
    unknown = query(qtype=65400)
    add("unknown-rr", "", unknown, reply(unknown, rr(65400, b"\xff\x00\xc0\x0c")))
    for q in (plain, with_opt):
        for flag in (0x8002, 0x8003, 0x8200):
            add("rcode-and-tc", "stop-dns-rebind\n", q, reply(q, private, (opt(),), flags=flag))
        add("signed-reply", "", q, reply(q, public, (opt(), rr(250,b"sig",owner=name("key.test"),cls=255))))
    for opcode in (0, 1, 5):
        for qd in (0, 1, 2):
            for options in ((), (opt(ttl=0x8000),)):
                q = struct.pack("!6H",0x1234,0x130 | (opcode << 11),qd,0,0,len(options)) + (name("caller.test")+struct.pack("!HH",1,1))*qd + b"".join(options)
                add("query-header-rejection", "", q, q, "Q")
    for field in (3,4):
        q = bytearray(with_opt); struct.pack_into("!H",q,field*2,1)
        add("nonstandard-query-record-count", "", q, q, "Q")
    for question in (b"\xff\xff\x00\x01\x00\x01", b"\xc0\x0c\x00\x01\x00\x01", b"\x40bad", b"\x06short"):
        q = struct.pack("!6H",0x1234,0x110,1,0,0,0)+question
        add("malformed-query-name", "", q, q, "Q")
    known_cases = [
        ("host-record=caller.test,192.0.2.7", "caller.test"),
        ("host-record=child.caller.test,192.0.2.7", "caller.test"),
        ("host-record=caller.test,192.0.2.7", "other.caller.test"),
        ("host-record=caller.test,192.0.2.7", "notcaller.test"),
        ("host-record=caller.test,192.0.2.7", ""),
        ("cname=caller.test,target.test", "caller.test"),
        ("txt-record=caller.test,value", "caller.test"),
        ("txt-record=child.caller.test,value", "caller.test"),
        ("txt-record=caller.test,value", ""),
        ("ptr-record=caller.test,target.test", "caller.test"),
        ("mx-host=caller.test,target.test", "caller.test"),
        ("srv-host=_svc._tcp.caller.test,target.test,7", "caller.test"),
        ("dns-rr=caller.test,65400,abcd", "caller.test"),
        ("local=/caller.test/", "caller.test"),
        ("server=/caller.test/192.0.2.53", "caller.test"),
        ("address=/caller.test/192.0.2.7", "caller.test"),
        ("address=/caller.test/#", "caller.test"),
        ("address=/test/192.0.2.7\nserver=/caller.test/192.0.2.53", "caller.test"),
        ("address=/*caller.test/192.0.2.7", "notcaller.test"),
        ("address=/#/192.0.2.7\nserver=//192.0.2.53", "printer"),
        ("address=//192.0.2.7", "printer"),
        ("address=/printer/192.0.2.7\nserver=//192.0.2.53", "printer"),
        ("addn-hosts={HOSTS}", "caller.test"),
        ("addn-hosts={HOSTS}", "test"),
        ("addn-hosts={HOSTS}", ""),
    ]
    for config, hostname in known_cases:
        for cls in (1, 3):
            q = query(options=opt(), qtype=65400, qname=hostname, cls=cls)
            add("known-domain-nxdomain", config + "\n", q, reply(q, None, (opt(),), flags=0x81b3))
    return rows


def matches(expected, actual):
    return (expected.returncode == actual.returncode == 0
            and len(expected.stdout.splitlines()) == len(actual.stdout.splitlines()) == 1
            and expected.stdout == actual.stdout)


def summarize(rows):
    failures = [row for row in rows if not row["match"]]
    return {"success": len(rows) - len(failures), "error_count": len(failures), "failures": failures}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--reference-build", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--cargo", default=shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo"))
    ap.add_argument("--c-only", action="store_true")
    args = ap.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "private"):
        ap.error("output must be a new directory below private/")
    out.mkdir(parents=True)
    fixture = subprocess.CompletedProcess([], 0, b"123481850001000000000000\n")
    calibration = summarize([
        {"match": matches(fixture, fixture)},
        {"match": matches(fixture, subprocess.CompletedProcess([], 0, b"123481820001000000000000\n"))},
        {"match": matches(fixture, subprocess.CompletedProcess([], 1, fixture.stdout))},
    ])
    assert (calibration["success"], calibration["error_count"]) == (1, 2)
    c, rust = build(args, out)
    hosts = out / "hosts"
    hosts.write_text("192.0.2.7 caller.test\n")
    rows, reply_counts = [], Counter()
    for index, case in enumerate(corpus()):
        config = out / f"{index:03}.conf"
        config.write_text("no-hosts\nno-resolv\n" + case["config"].replace("{HOSTS}", str(hosts)))
        wire = (case["line"] + "\n").encode()
        (out / f"{index:03}.input").write_bytes(wire)
        observations = []
        for label, binary in (("c", c), ("rust", rust)):
            if binary is None: continue
            run = subprocess.run([str(binary), "-C", str(config)], input=wire, capture_output=True)
            (out / f"{index:03}.{label}.stdout").write_bytes(run.stdout)
            (out / f"{index:03}.{label}.stderr").write_bytes(run.stderr)
            observations.append(run)
        good = all(p.returncode == 0 and len(p.stdout.splitlines()) == 1 for p in observations)
        if rust: good = matches(observations[0], observations[1])
        expected = observations[0].stdout.decode().strip()
        reply_counts[expected if expected in ("FORWARD", "CLOSE") else f"rcode-{int(expected[6:8],16)&15}"] += 1
        rows.append({"case": index, "label": case["label"], "match": good})
    assert len(rows) == 235
    assert dict(reply_counts) == {"rcode-5":38,"rcode-0":143,"rcode-2":20,"rcode-3":18,"FORWARD":2,"rcode-4":12,"CLOSE":2}
    report = {"cases":len(rows), **summarize(rows), "calibration": calibration, "c_reply_counts": dict(reply_counts),
              "c_sha256":sha(c), "rust_source_sha256":sha(ROOT / "components/dnsmasq/src/dns/tcp_service.rs"),
              "forward_c_sha256":FORWARD_SHA, "extracted_c_sha256":sha(out / "tcp-caller-exact.inc"),
              "rust_probe_sha256": None if rust is None else sha(rust),
              "tool_sha256":sha(Path(__file__)),
              "rust_sources": {name: sha(ROOT / "components/dnsmasq/src" / name) for name in
                  ("dns/tcp_service.rs", "dns/routing.rs", "dns/local.rs", "dns/reply.rs", "dns/process.rs", "dns/wire.rs", "dns/daemon.rs", "config/dns.rs", "hosts.rs")},
              "scope":"TCP caller reply/refusal/local-name byte comparison; no transport or dynamic-cache/ubus side-effect equivalence", "rows":rows}
    (out / "result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
