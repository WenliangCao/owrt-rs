#!/usr/bin/env python3
"""Compare captured WAN6 updates with the installed fw4 ELF, offline only."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value))


def prepare(capture, output):
    monitor = capture / "ubus-monitor-resumed.txt"
    states = []
    baseline = None
    previous = None
    for number, line in enumerate(monitor.read_text().splitlines(), 1):
        if not line.startswith("<-") or "{" not in line:
            continue
        item = json.loads(line[line.index("{"):])
        data = item.get("data", {})
        if baseline is None and isinstance(data.get("interface"), list):
            baseline = data
        if item.get("method") != "interface.update" or data.get("interface") != "wan6":
            continue
        # The bus sends one event to the global and per-interface objects.
        if data == previous:
            continue
        states.append((number, data))
        previous = data
    assert baseline is not None and states
    config = (capture / "firewall-and-renew-readonly.txt").read_text()
    start = config.index("config defaults")
    end = config.index("\nRULESET", start)
    config = config[start:end]
    common = output / "common"
    write(common / "uci/firewall", config)
    write(common / "ubus/service~get_data~type-firewall.json", {})
    include = capture / "10-custom-filter-chains.nft"
    assert all(not line.strip() or line.lstrip().startswith("#") for line in include.read_text().splitlines())
    # Constants isolate WAN6 status as the only changed input; no live FS,
    # nft or ubus calls occur in FW4_MOCK_DIRS mode. Version selects >=4.10.
    write(common / "fs/open~_proc_version.txt", "Linux version 6.12.0 (offline constant)\n")
    for device in ["br-lan", "wan"]:
        write(common / f"fs/open~_sys_class_net_{device}.txt", "")
    write(common / "fs/popen~_usr_sbin_nft_--terse_--json_list_flowtables_inet.txt",
          {"nftables": [{"flowtable": {"table": "fw4", "name": "ft"}}]})
    cases = [(0, None)] + states
    index = []
    for case, (number, data) in enumerate(cases):
        dump = copy.deepcopy(baseline)
        if data is not None:
            dump["interface"] = [data if x.get("interface") == "wan6" else x for x in dump["interface"]]
        write(output / f"case-{case:02d}/ubus/network.interface~dump.json", dump)
        index.append({"case": case, "source_line": number, "uptime": data.get("uptime") if data else None,
                      "updated": data.get("updated", []) if data else [],
                      "address_count": len(data.get("ipv6-address", [])) if data else None})
    write(output / "index.json", {"monitor_sha256": sha(monitor.read_bytes()),
                                  "monitor_bytes": monitor.stat().st_size,
                                  "cases": index,
                                  "prediction": "Only unused define wan_subnets changes; effective rules identical.",
                                  "fixed_inputs": "Other interfaces held at first dump; modern kernel branch; existing flowtable; br-lan/wan devices; no service firewall data. One actual /etc/nftables.d include contains comments only; no /usr/share/nftables.d includes.",
                                  "comments_only_include_sha256": sha(include.read_bytes()),
                                  "not_measured": "reload side effects, runtime timing, nft installation"})


def run(root, executable):
    index = json.loads((root / "index.json").read_text())
    rows = []
    normalized = []
    raw = []
    for item in index["cases"]:
        case = root / f"case-{item['case']:02d}"
        env = dict(os.environ, FW4_MOCK_DIRS=f"{case}:{root / 'common'}")
        result = subprocess.run([str(executable), "print"], env=env, capture_output=True, check=True)
        (case / "stdout.nft").write_bytes(result.stdout)
        (case / "stderr.txt").write_bytes(result.stderr)
        text = result.stdout.decode()
        assert "$wan_subnets" not in text, "WAN subnet define is referenced; cannot discard it"
        effective = re.sub(r"^\s*define wan_subnets = .*\n", "", text, flags=re.MULTILINE).encode()
        raw.append(result.stdout)
        normalized.append(effective)
        rows.append(dict(item, stdout_sha256=sha(result.stdout), effective_sha256=sha(effective),
                         stderr_bytes=len(result.stderr), stdout_bytes=len(result.stdout)))
    summary = dict(index, executable_sha256=sha(executable.read_bytes()), cases=rows,
                   unique_full_outputs=len(set(raw)), unique_effective_outputs=len(set(normalized)),
                   all_stderr_empty=all(row["stderr_bytes"] == 0 for row in rows),
                   removed_only_unreferenced_define="wan_subnets")
    write(root / "summary.json", json.dumps(summary, indent=2) + "\n")
    print(json.dumps({key: summary[key] for key in ["monitor_sha256", "monitor_bytes", "executable_sha256", "unique_full_outputs", "unique_effective_outputs", "all_stderr_empty"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "run"])
    parser.add_argument("root", type=Path)
    parser.add_argument("other", type=Path)
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.root, args.other)
    else:
        run(args.root.resolve(), args.other.resolve())
