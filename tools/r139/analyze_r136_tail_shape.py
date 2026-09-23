#!/usr/bin/env python3
"""Offline, exploratory shape audit of the immutable R136 lifecycle samples.

No collection or new acceptance decisions. Archive identities are anchored to
the published completion report; selected expanded files must match archives.
Only derived values and evidence hashes are emitted, never device identities.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics
import tarfile

ROOT = Path(__file__).resolve().parents[2]
LANES = ("register_1", "register_16", "event_1", "event_8", "event_nomatch")
QUANTILES = (50, 75, 80, 85, 90, 92, 94, 95, 96, 97, 98, 99, 99.5, 99.9)
ORDER = ("stock", "candidate", "candidate", "stock") * 4
RUNS = tuple(f"{i:02d}-{side}" for i, side in enumerate(ORDER, 1))
CONTEXT = ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def quantile(ordered, percentile):
    # Native caller uses Rust's positive .round(), not Python's ties-to-even.
    return ordered[math.floor((len(ordered) - 1) * percentile / 100 + .5)]


def shape(data):
    samples = data["latency_ns"]
    check(data["successful"] == len(samples) == 10000 and data["errors"] == 0
          and data["warmup"] == 20, "unexpected sample count/status/warmup")
    check(all(type(x) is int and x >= 0 for x in samples), "invalid latency")
    ordered = sorted(samples)
    quantiles = {f"p{p:g}_us": quantile(ordered, p) / 1000 for p in QUANTILES}
    for name in ("p50_us", "p95_us", "p99_us"):
        check(quantiles[name] == data[name], f"native {name} mismatch")
    check(math.isclose(statistics.mean(samples) / 1000, data["mean_us"],
                       rel_tol=1e-10), "native mean mismatch")
    check(len(data["daemon_cpu"]) == 1, "expected one lifecycle daemon")
    daemon = data["daemon_cpu"][0]
    check(daemon["before"]["start_ticks"] == daemon["after"]["start_ticks"],
          "daemon identity changed")
    context = {key: daemon["after"][key] - daemon["before"][key] for key in CONTEXT}
    check(all(value >= 0 for value in context.values()), "context counter regressed")
    tail = [x > quantile(ordered, 95) for x in samples]
    deciles = [sum(tail[i:i + 1000]) for i in range(0, 10000, 1000)]
    return {
        "quantiles": quantiles, "daemon_context_switches": context,
        "daemon_cpu_us_per_cycle": daemon["cpu_clock_ns"] / 10000 / 1000,
        "client_cpu_us_per_cycle": data["client_cpu_clock_ns"] / 10000 / 1000,
        "client_boundary_snapshots_present": all(
            name in data for name in ("client_before", "client_after")),
        "p95_strict_tail": {
            "count": sum(tail), "counts_per_1000_cycles": deciles,
            "first_1000_share_pct": deciles[0] / sum(tail) * 100,
            "largest_block_share_pct": max(deciles) / sum(tail) * 100,
            "next_sample_tail_given_tail_pct":
                sum(a and b for a, b in zip(tail, tail[1:])) / sum(tail[:-1]) * 100,
        },
    }


def derive(matrix, report):
    published_bytes = report.read_bytes()
    published = json.loads(published_bytes)
    check(published["verified"] is True, "completion report not verified")
    sources = {row["run"]: row for row in published["matrix"]["sources"]}
    check(set(sources) == set(RUNS), "unexpected published window set")
    check(json.loads((matrix / "order.json").read_text()) == list(ORDER), "window order")
    rows, samples, provenance = {}, {}, []
    for run in RUNS:
        archive = matrix / run / "raw.tar.gz"
        archive_sha = sha(archive.read_bytes())
        check(archive_sha == sources[run]["archive_sha256"], f"{run}: archive identity")
        with tarfile.open(archive) as tar:
            file_hashes = {}
            for lane in LANES:
                raw = (matrix / run / "raw" / f"{lane}.json").read_bytes()
                check(raw == tar.extractfile(f"./{lane}.json").read(),
                      f"{run}/{lane}: archive/expanded mismatch")
                file_hashes[lane] = sha(raw)
                data = json.loads(raw)
                rows[run, lane] = shape(data)
                samples[run, lane] = data["latency_ns"]
        provenance.append({"run": run, "archive_sha256": archive_sha,
                           "selected_raw_sha256": file_hashes})
    lanes = {}
    for lane in LANES:
        summaries = {}
        for side in ("stock", "candidate"):
            selected = [rows[run, lane] for run in RUNS if run.endswith(side)]
            summaries[side] = {
                group: {key: statistics.median(row[group][key] for row in selected)
                        for key in selected[0][group]}
                for group in ("quantiles", "daemon_context_switches")}
            summaries[side]["p95_strict_tail"] = {
                key: statistics.median(row["p95_strict_tail"][key] for row in selected)
                for key in ("first_1000_share_pct", "largest_block_share_pct",
                            "next_sample_tail_given_tail_pct")}
        pairs = []
        for i in range(0, 16, 2):
            stock, candidate = sorted(RUNS[i:i + 2], key=lambda run: not run.endswith("stock"))
            threshold = quantile(sorted(samples[stock, lane]), 95)
            above = [x > threshold for x in samples[candidate, lane]]
            pairs.append({"stock_run": stock, "candidate_run": candidate,
                          "stock_p95_us": threshold / 1000,
                          "candidate_exceeds_stock_p95_pct": sum(above) / 100,
                          "candidate_exceedances_per_1000_cycles":
                              [sum(above[j:j + 1000]) for j in range(0, 10000, 1000)]})
        lanes[lane] = {"side_medians": summaries, "pairs": pairs,
                       "windows": {run: rows[run, lane] for run in RUNS}}
    return {"schema": 1, "scope": "Exploratory R136 lifecycle shape audit; no new ranking",
            "completion_report_sha256": sha(published_bytes),
            "script_sha256": sha(Path(__file__).read_bytes()),
            "provenance": provenance, "lanes": lanes,
            "limits": [
                "Only the five complete lifecycle lanes are audited: 16 windows x 10000 cycles each.",
                "Deciles use cycle sequence, not elapsed-time bins; no per-cycle timestamps exist.",
                "P95 strict-tail sets use each window's own p95; ties can change set size.",
                "Additional quantiles, tail rates and clustering are exploratory; no inferential tests.",
                "Boundary daemon switches cannot locate a switch in a cycle or measure waiting time.",
                "The archived formal caller lacks per-process client context/placement snapshots.",
                "No samples/windows are dropped; original acceptance decisions and limitations remain.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path,
                        default=ROOT / "private/r136/completion-01/matrix")
    parser.add_argument("--completion-report", type=Path,
                        default=ROOT / "docs/reviews/r136-ubusd-completion-results.json")
    args = parser.parse_args()
    print(json.dumps(derive(args.matrix, args.completion_report), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
