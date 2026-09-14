#!/usr/bin/env python3
"""Compare four private wireless windows; publish counts and decisions only.

No SSIDs, MACs, DUIDs, IP addresses, hostnames or configuration enter output.
Volatile fields and membership handling are explicit. Frequency flags require
the separate exact-library zeroed/poisoned buffer control, never a blanket mask.
"""
import argparse
from collections import defaultdict
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess

WINDOWS = ("rust-1", "stock-1", "stock-2", "rust-2")
SIGNAL = {"signal", "noise", "quality", "bitrate"}
ASSOC = SIGNAL | {"signal_avg", "inactive", "connected_time", "thr", "preamble", "rx", "tx"}


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ordered(values):
    return sorted(values, key=lambda v: json.dumps(v, sort_keys=True))


def ipv6_role(value):
    address = ipaddress.ip_interface(value)
    assert address.version == 6
    return {"role": "link-local" if address.ip.is_link_local else "global-or-ula",
            "prefix_length": address.network.prefixlen}


def ipv6_fields(value):
    value = copy.deepcopy(value)
    if "ip6addrs" in value:
        value["ip6addrs"] = ordered([json.loads(v) for v in {
            json.dumps(ipv6_role(a), sort_keys=True) for a in value["ip6addrs"]}])
    if "ip6addr" in value:
        value["ip6addr"] = ipv6_role(value["ip6addr"])
    if "ipaddrs" in value:
        assert all(ipaddress.ip_address(a).version == 4 for a in value["ipaddrs"])
        value["ipaddrs"] = sorted(value["ipaddrs"])
    return value


def common_records(tables, normalize):
    common = set.intersection(*(set(table) for table in tables))
    assert common, "no common observed records for comparison"
    normalized = [{key: normalize(table[key]) for key in common} for table in tables]
    assert all(value == normalized[0] for value in normalized), "common-record static fields differ"
    return {"records_per_sample": [len(t) for t in tables], "common_records_compared": len(common),
            "changing_membership": len(set.union(*(set(t) for t in tables)) - common)}


def input_controls(device):
    """Require independent input controls before excluding input-sensitive fields."""
    base = device.parent
    manifest = read(base / "deployment-r92/manifest.json")
    hints = base / "oracle-evidence/raw/host-hints-01"
    scan = base / "oracle-evidence/raw/scan-ie-01"
    live = device / "host-hints-live"
    assert all((root / "COMPLETE").exists() for root in (hints, scan, live))
    rows = read(hints / "results.json")
    assert len(rows) == 2 and {r["side"] for r in rows} == {"original", "candidate"}
    for row in rows:
        assert row["passed"] and row["exit"] == 0 and len(row["checks"]) == 20
        assert all(v["passed"] for v in row["checks"].values())
        expected = manifest["components"]["rpcd"]["original" if row["side"] == "original" else "rust"]["sha256"]
        assert row["checks"]["identity"]["actual"] == expected
    replay = read(scan / "results.json")
    assert replay["passed"] and replay["byte_identical"] and replay["cases"] == 262144
    repository = Path(__file__).resolve().parents[1]
    for name, expected in replay["source_sha256"]["candidate"].items():
        original = subprocess.check_output(["git", "show", manifest["fix_commit"] + ":" + name], cwd=repository)
        assert hashlib.sha256(original).hexdigest() == expected, "parser source does not match the formal runtime commit"
    adjacent = read(live / "summary.json")
    assert adjacent["passed"] and len(adjacent["pairs"]) == 3
    assert all(row["exact_json_equal"] for row in adjacent["pairs"])
    assert adjacent["candidate_rpcd_sha256"] == manifest["components"]["rpcd"]["rust"]["sha256"]
    assert adjacent["original_sha256"]["rpcd"] == manifest["components"]["rpcd"]["original"]["sha256"]
    assert adjacent["configuration_and_identities_unchanged"] and adjacent["client_health_passed"]
    return {"host_hints_fixed_input": {"sides": 2, "phases_per_side": 6, "calls_per_phase": 2,
                "assertions_per_side": 20, "passed": True, "results_sha256": sha(hints / "results.json")},
            "host_hints_same_boot": adjacent, "ht_ie_fixed_input": replay}


def host_hints(values):
    common = set.intersection(*(set(value) for value in values))
    # Preserve all non-IPv6 fields. Every IPv6 value is parsed and its changing
    # role inventory is reported; fixed-input and same-boot controls are required.
    normalized = [{key: ipv6_fields(entry) for key, entry in table.items()} for table in values]
    changes = sum(len({json.dumps(table[key]["ip6addrs"], sort_keys=True) for table in normalized}) > 1
                  for key in common)
    result = common_records(normalized, lambda entry: {k: v for k, v in entry.items() if k != "ip6addrs"})
    result.update({"ipv6_role_inventory_changed_common_records": changes,
                   "ipv6_address_counts_per_sample": [sum(len(table[key]["ip6addrs"]) for key in common) for table in values],
                   "input_sensitive_fields": ["ip6addrs"],
                   "disposition": "Neighbor/lease address inventory is input, not a cross-boot constant. Exact JSON equality is separately checked on three adjacent live pairs; add/remove/NUD_NOARP is checked on fixed neighbors."})
    return result


def scans(tables):
    common = set.intersection(*(set(table) for table in tables))
    width_pairs = []
    for key in common:
        widths = [table[key].get("ht_operation", {}).get("channel_width") for table in tables]
        assert all(width is None or (type(width) is int and width in (20, 2040)) for width in widths)
        if len(set(widths)) > 1:
            assert all(width is not None for width in widths), "HT output schema changed"
            width_pairs.append(widths)

    def normalize(entry):
        entry = copy.deepcopy(entry)
        entry.pop("signal", None)
        entry.pop("quality", None)
        entry.get("ht_operation", {}).pop("channel_width", None)
        return entry

    result = common_records(tables, normalize)
    result.update({"ht_channel_width_different_records": len(width_pairs),
                   "different_width_pairs_in_sample_order": sorted(width_pairs),
                   "input_sensitive_fields": ["ht_operation.channel_width"],
                   "disposition": "Retain the exact reference parser, proven equal on 262144 fixed IEs. Earlier scan frames were not captured; these differing values are not a byte-equivalence claim or proof of an RF width change."})
    return result


def normalize_static(obj, method, value):
    value = copy.deepcopy(value)
    if obj == "iwinfo":
        if method == "info":
            return {key: val for key, val in value.items() if key not in SIGNAL}
        if method == "survey":
            fields = {"mhz", "noise", "active_time", "busy_time", "busy_time_ext", "rx_time", "tx_time"}
            assert all(set(e) == fields and all(type(v) is int for v in e.values()) for e in value["results"])
            return {"results": [{"mhz": e["mhz"]} for e in value["results"]]}
    if method == "getWirelessDevices":
        for radio in value.values():
            for entry in [radio] + radio.get("interfaces", []):
                if "iwinfo" in entry:
                    entry["iwinfo"] = {k: v for k, v in entry["iwinfo"].items() if k not in SIGNAL}
    if method == "getNetworkDevices":
        for entry in value.values():
            counters = entry.pop("stats", {})
            assert counters and all(type(v) is int and v >= 0 for v in counters.values())
            # Preserve counter schema even when values advance between boots.
            entry["stats_fields"] = sorted(counters)
            for key in ("changes", "up_count", "down_count"):
                entry.get("link", {}).pop(key, None)
            if "ipaddrs" in entry:
                entry["ipaddrs"] = ordered(entry["ipaddrs"])
            if "ip6addrs" in entry:
                for address in entry["ip6addrs"]:
                    address["address"] = ipv6_role(address["address"])
                entry["ip6addrs"] = ordered(entry["ip6addrs"])
    return value


def frequency(rows, expected):
    extra = []
    stable = []
    assert expected
    oracle = {e["mhz"]: e for e in expected}
    for window, _, data in rows:
        assert set(e["mhz"] for e in data["results"]) == set(oracle)
        extras = 0
        for entry in data["results"]:
            reference = oracle[entry["mhz"]]
            assert all(entry[key] == reference[key] for key in ("band", "channel", "mhz"))
            assert entry["restricted"] == ("no_ir" in entry["flags"])
            if window.startswith("rust"):
                assert entry["flags"] == reference["flags"] and entry["restricted"] == reference["restricted"]
            else:
                assert set(reference["flags"]) <= set(entry["flags"]), "original omitted a real kernel restriction"
                extras += entry["flags"] != reference["flags"]
        extra.append(extras)
        stable.append([{k: v for k, v in entry.items() if k not in ("flags", "restricted")}
                       for entry in data["results"]])
    assert all(s == stable[0] for s in stable)
    return {"frequency_entries": len(oracle), "extra_flag_entries_per_sample": extra,
            "candidate_matches_zeroed_library": True,
            "disposition": "Keep deterministic kernel flags; do not reproduce the original uninitialized buffer."}


def derive(device):
    sensitivity = input_controls(device)
    controls = device / "iwinfo-flags"
    assert (controls / "COMPLETE").exists()
    oracle = {r["device"]: r["candidate"] for r in read(controls / "results.json")}
    assert len(oracle) == 2
    groups = defaultdict(list)
    sources = []
    call_count = 0
    for window in WINDOWS:
        root = device / "windows" / window / "wireless"
        assert (root / "COMPLETE").exists()
        observation = read(root / "observations.json")
        assert observation["configuration_unchanged"] and observation["running_identities_unchanged"]
        calls = read(root / "calls.json")
        assert len(calls) == observation["calls"] == (54 if window.endswith("-1") else 52)
        call_count += len(calls)
        for row in calls:
            assert row["exit"] == 0
            key = (row["object"], row["method"], json.dumps(row["arguments"], sort_keys=True))
            groups[key].append((window, row["round"], json.loads(row["stdout"])))
        sources.append({"window": window, "calls": len(calls), "calls_sha256": sha(root / "calls.json"),
                        "health_sha256": sha(root / "observations.json")})
    output = []
    for (obj, method, argument_json), rows in groups.items():
        args = json.loads(argument_json)
        scope = ("radio-" + str(sorted(oracle).index(args["device"]) + 1) if "device" in args
                 else "family-" + str(args["family"]) if "family" in args
                 else args.get("section", "all"))
        item = {"object": obj, "method": method, "scope": scope, "samples": len(rows)}
        assert len(rows) == (2 if method == "scan" else 8)
        values = [row[2] for row in rows]
        if method == "freqlist":
            item.update(frequency(rows, oracle[args["device"]]))
        elif method in ("assoclist", "scan"):
            key = "mac" if method == "assoclist" else "bssid"
            volatile = ASSOC if method == "assoclist" else {"signal", "quality"}
            tables = [{e[key]: e for e in value["results"]} for value in values]
            assert all(len(t) == len(v["results"]) for t, v in zip(tables, values))
            item.update(scans(tables) if method == "scan" else
                        common_records(tables, lambda e: {k: v for k, v in e.items() if k not in volatile}))
            item["volatile_fields"] = sorted(volatile)
        elif method == "getHostHints":
            item.update(host_hints(values))
            item["volatile_fields"] = ["record membership", "IPv6 address inventory"]
        elif method == "getDUIDHints":
            item.update(common_records(values, ipv6_fields))
            item["volatile_fields"] = ["record membership", "IPv6 address bytes and temporary-address count"]
        elif method == "getDHCPLeases":
            families = {}
            assert all(set(v) == set(values[0]) for v in values)
            for family in values[0]:
                key = "macaddr" if family == "dhcp_leases" else "duid"
                tables = [{e[key]: e for e in v[family]} for v in values]
                assert all(len(t) == len(v[family]) for t, v in zip(tables, values))
                families[family] = common_records(tables, lambda e: ipv6_fields({k: v for k, v in e.items() if k != "expires"}))
            item["families"] = families
            item["volatile_fields"] = ["record membership", "expires", "IPv6 address bytes and temporary-address count"]
        else:
            normalized = [normalize_static(obj, method, value) for value in values]
            assert all(value == normalized[0] for value in normalized), (obj, method, scope, "static fields differ")
            item["normalized_static_equal"] = True
            if method in ("info", "getWirelessDevices"):
                item["volatile_fields"] = sorted(SIGNAL)
            elif method == "getNetworkDevices":
                item["volatile_fields"] = ["stats values", "link changes/up_count/down_count", "IPv6 address bytes"]
                item["order_normalization"] = "sort IPv4/IPv6 address lists; preserve all other fields and masks"
            elif method == "survey":
                item["volatile_fields"] = ["noise", "active_time", "busy_time", "busy_time_ext", "rx_time", "tx_time"]
        item["passed"] = True
        output.append(item)
    assert call_count == 212 and len(output) == 28
    return {"schema": 1, "calls": call_count, "scan_calls": 4, "radios": 2, "groups": output,
            "sources": sources, "input_controls": sensitivity, "flags_control_sha256": sha(controls / "results.json"),
            "flags_helper_identity": read(controls / "identities.json"),
            "limitations": ["Two observation rounds in each of four boots; dynamic fields are not byte-equivalence assertions.",
                "Changing neighbor, client and lease membership is recorded; only common records are compared.",
                "Scan signal/quality and HT width observations are handled separately; all other common-record fields must match.",
                "Historical neighbor tables and raw scan IEs were not captured. Fixed-input and adjacent live controls do not reconstruct those inputs.",
                "Input contains private identifiers and configuration; none are exported here."]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("device", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    result = derive(a.device)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"passed": True, "calls": result["calls"], "groups": len(result["groups"])}))


if __name__ == "__main__":
    main()
