#!/usr/bin/env python3
"""Diagnose getFeatures with and without SIGCHLD during helper output reads.

Uses r17's disposable rootfs only. Raw output may contain runtime observations;
the output directory must stay outside Git. Signal injection is diagnostic,
not a performance workload or a replacement for the full compatibility gate.
"""
import argparse
import json
from pathlib import Path

import r17_rpcd_core_check as base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs")
    parser.add_argument("candidate")
    parser.add_argument("output", type=Path)
    parser.add_argument("--calls", type=int, default=64)
    args = parser.parse_args()
    if args.calls <= 0:
        parser.error("calls must be positive")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    summary = []
    for signals in (False, True):
        base.STEPS.clear()
        if signals:
            base.shx("signal_start", "(i=0; while [ $i -lt 6000 ]; do kill -CHLD $core_pid 2>/dev/null || break; sleep 0.001; i=$((i+1)); done) >/tmp/r85-signals.log 2>&1 & echo $! >/tmp/r85-signals.pid")
        for i in range(args.calls):
            base.req(f"features_{i:04d}", "luci", "getFeatures", {})
        if signals:
            base.shx("signal_stop", "kill $(cat /tmp/r85-signals.pid) 2>/dev/null || true")
        for side in ("original", "candidate"):
            results, _, logs = base.run_side(args.rootfs, side, args.candidate)
            directory = args.output / f"{side}-{'signals' if signals else 'normal'}"
            directory.mkdir(mode=0o700)
            for name, data in results.items():
                (directory / name).write_bytes(data)
            (directory / "logs.json").write_text(json.dumps(logs) + "\n")
            missing, no_odhcpd, no_netifd_vrf, invalid = [], [], [], []
            for i in range(args.calls):
                name = f"features_{i:04d}"
                try:
                    assert results[name + ".rc"].strip() == b"0"
                    value = json.loads(results[name + ".out"])
                    if not isinstance(value.get("dnsmasq"), dict):
                        missing.append(i)
                    if not isinstance(value.get("odhcpd"), dict):
                        no_odhcpd.append(i)
                    if value.get("netifd_vrf") is False:
                        no_netifd_vrf.append(i)
                except (KeyError, ValueError, AssertionError):
                    invalid.append(i)
            row = {"side": side, "signals": signals, "calls": args.calls,
                   "missing_dnsmasq": missing, "missing_odhcpd": no_odhcpd,
                   "netifd_vrf_false": no_netifd_vrf,
                   "invalid_responses": invalid}
            summary.append(row)
            print(json.dumps(row), flush=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return int(any(r["invalid_responses"] or (r["side"] == "candidate" and
                   (r["missing_dnsmasq"] or r["missing_odhcpd"] or r["netifd_vrf_false"])) for r in summary))


if __name__ == "__main__":
    raise SystemExit(main())
