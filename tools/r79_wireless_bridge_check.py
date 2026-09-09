#!/usr/bin/env python3
"""Assert actual packet delivery as well as C/Rust structural equivalence."""
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
errors = []
phases = ("initial", "reload", "down", "up", "changed", "removed", "restored")


def check(ok, message):
    if not ok:
        errors.append(message)


def normalized(value):
    if isinstance(value, dict):
        return {k: normalized(v) for k, v in value.items()
                if k not in {"uptime", "statistics"}}
    if isinstance(value, list):
        return [normalized(v) for v in value]
    return value


try:
    for side in ("c", "rs"):
        base = out / side
        setups = [json.loads(line) for line in (base / "setup.jsonl").read_text().splitlines()]
        # C may run another setup when a recreated bridge gets a new ifindex.
        # Assert progress at each requested change and no restart on a no-op.
        counts = {p: int((base / f"{p}-setups.txt").read_text()) for p in phases}
        check(counts["initial"] > 0 and counts["initial"] == counts["reload"],
              f"{side}: no-op reload restarted wireless")
        for before, after in (("down", "up"), ("up", "changed"), ("removed", "restored")):
            check(counts[after] > counts[before], f"{side}/{after}: handler did not run")
        before_up = [json.loads(line) for line in (base / "before-up.jsonl").read_text().splitlines()]
        check(before_up and before_up[0]["up"] and before_up[0]["available"],
              f"{side}: static LAN must be up before the first wireless port")
        check(json.loads((base / "prepare.json").read_text()) == {"bridge": "br-test"},
              f"{side}: prepare must report the bridge")
        for setup in setups:
            vif = setup["interfaces"]["01"]
            check(vif.get("bridge") == "br-test", f"{side}: handler lacks bridge")
            check(vif.get("bridge-ifname") == "br-test", f"{side}: handler lacks bridge-ifname")
        for phase in phases:
            wireless = json.loads((base / f"{phase}-wireless.json").read_text())
            lan = json.loads((base / f"{phase}-lan.json").read_text())
            active = phase not in ("down", "removed")
            if phase == "removed":
                check(wireless == {}, f"{side}/{phase}: removed radio remains")
            else:
                check(wireless["radio0"]["up"] == active, f"{side}/{phase}: radio state")
            check(lan["up"] == active and lan["available"] == active, f"{side}/{phase}: LAN state")
            addressed = "192.168.79.1/24" in (base / f"{phase}-address.txt").read_text()
            check(addressed == active, f"{side}/{phase}: LAN address")
            master = (base / f"{phase}-master.txt").read_text().strip()
            check(master.endswith("/br-test") == active, f"{side}/{phase}: bridge membership")
            reachable = (base / f"{phase}-ping.txt").read_text().strip() == "reachable"
            check(reachable == active, f"{side}/{phase}: station traffic")
    for phase in phases:
        check((out / "c" / f"{phase}-port-settings.txt").read_text() ==
              (out / "rs" / f"{phase}-port-settings.txt").read_text(),
              f"{phase}: wireless bridge port settings differ")
        for method in ("lan", "wireless", "devices"):
            file = f"{phase}-{method}.json"
            c = normalized(json.loads((out / "c" / file).read_text()))
            rs = normalized(json.loads((out / "rs" / file).read_text()))
            if c != rs:
                (out / f"{file}.c-normalized").write_text(json.dumps(c, indent=2) + "\n")
                (out / f"{file}.rs-normalized").write_text(json.dumps(rs, indent=2) + "\n")
                errors.append(f"{file}: C/Rust differ")
except (OSError, ValueError, KeyError, TypeError) as exc:
    errors.append(f"incomplete probe: {exc}")

for error in errors:
    print(error)
sys.exit(bool(errors))
