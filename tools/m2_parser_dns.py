#!/usr/bin/env python3
"""Run the existing exact-C DNS wire oracle with canonical M2 parser evidence.

``dns_wire_diff.py`` already extracts the patched dnsmasq name, section,
EDNS, and RDATA-copy routines.  This wrapper freezes its seed and bounded
mutation count in the M2 evidence tree, records the exact command, and keeps
the raw oracle/candidate outputs alongside the DHCP parser run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "tools/dnsmasq/dns_wire_diff.py"
SOURCE = ROOT / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src"
DEFAULT_OUT = ROOT / "private/dnsmasq-rewrite/evidence/M2/parsers/dns-wire/run-01"
MAX_MUTATIONS = 1024


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--seed", type=int, default=20261002)
    parser.add_argument("--mutations", type=int, default=512)
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    source, out = args.source.resolve(), args.out.resolve()
    if args.mutations < 0 or args.mutations > MAX_MUTATIONS:
        parser.error(f"--mutations must be between 0 and {MAX_MUTATIONS}")
    if not out.is_relative_to(ROOT / "private"):
        parser.error("--out must stay below ignored private/")
    if out.exists() and any(out.iterdir()):
        parser.error("--out must be a fresh directory")
    out.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(ORACLE), "--source", str(source), "--output", str(out),
               "--seed", str(args.seed), "--mutations", str(args.mutations),
               "--rustc", args.rustc, "--cc", args.cc]
    (out / "command.json").write_text(json.dumps({"argv": command}, indent=2) + "\n")
    (out / "plan.json").write_text(json.dumps({
        "schema": 1,
        "seed": args.seed,
        "mutations": args.mutations,
        "bounded_mutation_limit": MAX_MUTATIONS,
        "directed_classes": [
            "compressed and uncompressed names, binary labels and reserved labels",
            "truncated, forward, out-of-range and 255-hop compression pointers",
            "question/section count and record-length truncation boundaries",
            "EDNS OPT, duplicate/non-last OPT, TSIG/TKEY and signed status",
            "typed MX/SRV/NAPTR/SOA/name RDATA descriptors and opaque unknown RR",
            "RDATA length lying inside and beyond packet boundaries",
            "seeded byte, truncation and insertion mutations",
        ],
        "oracle": "dnsmasq rfc1035.c/edns0.c/rrfilter.c extracted routines",
        "candidate": "components/dnsmasq/src/dns/wire.rs",
        "comparison": "successful offsets, decoded bytes, lengths, flags and error-vs-NULL status",
    }, indent=2) + "\n")
    run = subprocess.run(command, text=True, capture_output=True)
    (out / "runner.stdout").write_text(run.stdout)
    (out / "runner.stderr").write_text(run.stderr)
    if run.returncode not in (0, 1):
        raise RuntimeError(f"dns wire oracle failed with {run.returncode}; see {out}/runner.stderr")
    summary = json.loads((out / "summary.json").read_text())
    summary.update({
        "runner": "tools/m2_parser_dns.py",
        "bounded_mutation_limit": MAX_MUTATIONS,
        "raw_input_sha256": sha256(out / "inputs.txt"),
        "raw_oracle_sha256": sha256(out / "oracle.stdout"),
        "raw_candidate_sha256": sha256(out / "driver.stdout"),
        "comparison_exit": run.returncode,
        "outside_scope": ["DNS daemon/cache/transport", "DHCP packet/state", "performance", "router"],
    })
    (out / "m2-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
