#!/usr/bin/env python3
"""Reuse the R136 raw-evidence verifier and add paired contrasts to R136."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def analyze(root):
    base = load("r136_analyze", Path(__file__).resolve().parents[1] / "r136/analyze_batch.py")
    report = base.analyze(root)
    plan = report["plan"]
    base.r135.require(set(plan["subjects"]) == {"c", "r136", "remove"}
                      and plan["subjects"]["r136"]["sha256"] ==
                      "ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330",
                      "expected exact C/R136/REMOVE screen subjects")
    base.r135.require(plan["pairs"] == [[0, 1], [2, 3]] and plan["repeats"] == 4
                      and plan["iterations"] == 10000 and plan["warmup"] == 20,
                      "bounded R138 screen dimensions changed")
    indexed = {(tuple(item["pair"]), item["affinity"], item["lane"], item["label"], item["block"]):
               item["metrics"] for item in report["records"]}
    for group in report["groups"]:
        prefix = tuple(group["pair"]), group["affinity"], group["lane"]
        group["vs"]["r136"] = {
            metric: base.r135.contrast(
                [indexed[*prefix, group["label"], block][metric] for block in range(plan["repeats"])],
                [indexed[*prefix, "r136", block][metric] for block in range(plan["repeats"])])
            for metric in group["metrics"]}
    report["scope"] = "R138 bounded Oracle REMOVE screen; paired descriptive comparisons only"
    report["roles"] = {"primary": ["register_1", "register_16"],
                       "fallback_sentinels": ["event_1", "event_8", "event_nomatch"]}
    report["limitations"].append("Guarded REMOVE intentionally falls back for the three named object-event lanes.")
    identity = json.loads((root / "manifest-identity.json").read_text())
    policy_path = Path(__file__).with_name("screen-policy.json")
    policy = json.loads(policy_path.read_text())
    base.r135.require(identity["r138_policy"] == policy
                      and identity["provenance"]["policy_sha256"] == hashlib.sha256(policy_path.read_bytes()).hexdigest(),
                      "pre-screen policy differs from the analyzer policy")
    primary, veto = [], []
    for group in report["groups"]:
        if group["label"] != "remove":
            continue
        if group["lane"] == policy["primary_lane"] and group["affinity"] == policy["primary_affinity"]:
            for metric in policy["primary_metrics"]:
                delta = group["vs"]["r136"][metric]
                primary.append({"pair": group["pair"], "metric": metric, **delta,
                                "passed": delta["median_delta_pct"] < policy["primary_median_delta_pct_below"]
                                and delta["lower_blocks"] >= policy["primary_min_lower_blocks"]})
        if group["lane"] in policy["latency_veto_lanes"] and group["affinity"] in policy["latency_veto_affinities"]:
            for metric in policy["latency_veto_metrics"]:
                delta = group["vs"]["r136"][metric]
                if (delta["median_delta_pct"] > policy["latency_veto_median_delta_pct_above"]
                        and delta["higher_blocks"] == policy["latency_veto_higher_blocks"]):
                    veto.append({"pair": group["pair"], "affinity": group["affinity"],
                                 "lane": group["lane"], "metric": metric, **delta})
    base.r135.require(len(primary) == 4, "primary screen conditions missing")
    report["eligibility"] = {"policy": policy, "primary": primary, "latency_vetoes": veto,
                             "screen_passed": all(item["passed"] for item in primary) and not veto,
                             "mechanism_confirmation_required_separately": True,
                             "router_acceptance": False}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.root.resolve())
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"verified": True, "measurements": len(report["records"]),
                      "groups": len(report["groups"]), "router_conclusion": False}))


if __name__ == "__main__":
    main()
