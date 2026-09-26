#!/usr/bin/env python3
"""Freeze C/R89 event contracts from separate, untimed isolated captures.

The candidate uses the C reference. This tool neither captures nor runs a
benchmark; any C/R89 difference is retained in baseline-differences.json.
"""
import argparse
import hashlib
import json
from pathlib import Path

C = "8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90"
R89 = "b127c49888b70a1f1e59318c0b05661623e05030b923975881e4b2279388a478"
ACTIONS = ("lan-down", "lan-up", "wired-down", "wired-up")


def capture(raw, digest):
    assert (raw / "CAPTURE_COMPLETE").exists() and not (raw / "COMPLETE").exists(), "not an untimed capture"
    assert (raw / "binary-sha256.txt").read_text().split()[0] == digest
    assert (raw / "subject-sha256.txt").read_text().split()[0] == digest
    prelude = raw / "events_static2/prelude"
    assert (prelude / "COMPLETE").exists() and not (prelude / "FAILED").exists()
    assert (prelude / "actions.txt").read_text().splitlines() == list(ACTIONS)
    final = json.loads((prelude / "final-interfaces.json").read_text())["interface"]
    assert [p["interface"] for p in final] == ["lan", "loopback", "wired"]
    assert all(p["up"] and not p["pending"] for p in final)
    assert json.loads((raw / "events_static2/cursor.json").read_text()) == json.loads((raw / "events_static2/prelude-cursor-after.json").read_text())
    records = [json.loads(line) for line in (prelude / "records.jsonl").read_text().splitlines()]
    assert [r["step"] for r in records] == list(ACTIONS)
    steps = {}
    for record in records:
        step = record["step"]; iface, action = step.split("-")
        expected_up = action == "up"; value = record["evidence"]
        assert record["raw"]["command.rc"].strip() == "0"
        assert value["status"]["up"] == expected_up and value["status"]["pending"] is False
        assert value["listen"] and value["subscribe"]
        for event in value["listen"]:
            assert list(event) == ["network.interface"]
            assert event["network.interface"] == {"action": "if" + action, "interface": iface}
        for event in value["subscribe"]:
            assert list(event) == ["interface.update" if expected_up else "interface.down"]
            payload = next(iter(event.values()))
            assert payload["interface"] == iface and payload["up"] == expected_up and payload["pending"] is False
        hotplug = value["hotplug"].splitlines()
        assert len(hotplug) == 1, "one successful real hotplug callback required per action"
        fields = hotplug[0].split("|")
        assert len(fields) == 9 and fields[:3] == ["iface", iface, "if" + action] and fields[-1] == "0"
        steps[step] = value
    files = {str(p.relative_to(raw)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(raw.rglob("*")) if p.is_file()}
    return {"schema": 1, "lane": "events_static2", "actions_per_cycle": 4,
            "reference_subject_sha256": digest, "source_raw_directory": str(raw.resolve()),
            "source_sha256": files, "normalization": ["named-status uptime removed", "subscription payload uptime removed",
                                                        "kernel address ifindex removed; kernel address/route lines sorted"],
            "steps": steps}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stock_raw", type=Path)
    parser.add_argument("r89_raw", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    stock = capture(args.stock_raw, C); baseline = capture(args.r89_raw, R89)
    args.output.mkdir(exist_ok=False)
    for name, value in (("stock", stock), ("r89", baseline), ("candidate", stock)):
        (args.output / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")
    differences = {step: {"stock": stock["steps"][step], "r89": baseline["steps"][step]}
                   for step in ACTIONS if stock["steps"][step] != baseline["steps"][step]}
    (args.output / "baseline-differences.json").write_text(json.dumps(differences, indent=2) + "\n")
    print(json.dumps({"contracts": str(args.output), "steps_with_baseline_differences": list(differences),
                      "status": "review-required-before-calibration"}))


if __name__ == "__main__":
    main()
