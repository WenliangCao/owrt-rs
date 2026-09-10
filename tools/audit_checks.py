#!/usr/bin/env python3
"""Evidence gates shared by the differential harnesses.

Equality is checked by each harness. These checks separately require that the
scenario actually ran: two missing replies or two dead daemons are not parity.
Only synthetic transcripts belong in Git; runtime captures remain in outdirs.
"""
import json
import re
import sys
from pathlib import Path


COUNTERS = {"rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_errors",
            "tx_errors", "rx_dropped", "tx_dropped", "multicast", "collisions"}


def volatile_netifd_path(path):
    parts = path.split(".")
    return ((len(parts) == 3 and parts[0] in ("interface dump", "interfaces")
             and parts[-1] == "uptime")
            or (len(parts) >= 2 and parts[-2] == "statistics" and parts[-1] in COUNTERS))


def mask_session_ids(text, session_list=False):
    text = re.sub(r'("ubus_rpc_session"\s*:\s*")[0-9a-f]{32}(")',
                  r'\1<SID>\2', text)
    if session_list:
        text = re.sub(r'"[0-9a-f]{32}"(\s*:\s*\{)', r'"<SID>"\1', text)
    return text


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sections(text):
    result, current = {}, None
    for line in text.splitlines(True):
        if line.startswith("--- "):
            current = line[4:].strip()
            require(current not in result, "duplicate section: " + current)
            result[current] = ""
        elif current is not None:
            result[current] += line
    return result


def blocks(text):
    result, current = {}, None
    for line in text.splitlines(True):
        if line.startswith("===== "):
            current = line[6:].strip()
            require(current not in result, "duplicate case: " + current)
            result[current] = ""
        elif current is not None:
            result[current] += line
    return {k: sections(v) for k, v in result.items()}


def object_json(text):
    result = json.loads(text)
    require(isinstance(result, dict), "reply is not a JSON object")
    return result


def interfaces(text, expected=("loopback",)):
    obj = object_json(text)
    rows = obj.get("interface")
    require(isinstance(rows, list) and rows, "missing interface dump")
    require(all(isinstance(row, dict) and isinstance(row.get("interface"), str)
                for row in rows), "malformed interface dump")
    names = {row["interface"]: row for row in rows}
    require(len(names) == len(rows), "duplicate interfaces")
    for name in expected:
        require(name in names and names[name].get("up") is True, name + " did not come up")
    require(any(a.get("address") == "127.0.0.1"
                for a in names.get("loopback", {}).get("ipv4-address", [])),
            "loopback address missing")
    return obj


def lease(text):
    obj = object_json(text)
    require(obj.get("up") is True and any(a.get("address") == "10.0.0.100"
            for a in obj.get("ipv4-address", [])), "DHCP lease was not acquired")


def kernel(text):
    require(re.search(r"\binet 127\.0\.0\.1/8\b", text) is not None,
            "kernel capture has no loopback address")
    require("---" in text and "Error" not in text and "Cannot" not in text,
            "kernel capture missing or contains command errors")


def resources(text, cycles, rss_budget=1024):
    require(cycles > 0, "cycle count must be positive")
    require(re.search(rf"^cycles: {cycles}$", text, re.M), "cycle count missing or incomplete")
    require(re.search(r"^failed calls: 0$", text, re.M), "cycle calls failed")
    require(re.search(r"^alive: yes$", text, re.M), "daemon died during cycles")
    samples = re.findall(r"^(before|after).*rss_kb=(\d+) fds=(\d+) threads=(\d+)", text, re.M)
    require([row[0] for row in samples] == ["before", "after"], "resource samples incomplete")
    before, after = [tuple(map(int, row[1:])) for row in samples]
    require(min(before + after) > 0, "invalid resource samples")
    require(after[0] - before[0] <= rss_budget, f"RSS grew by more than {rss_budget} KiB")
    require(after[1] <= before[1], "file descriptors grew across cycles")
    require(after[2] == before[2], "thread count changed across cycles")


def transcript36(text):
    require("skipped" not in text.lower(), "helper scenario was skipped")
    require("daemon_alive: yes" in text, "ubusd did not survive")
    require("list_rc: 0" in text and "still_serving: 0" in text, "ubusd was not serving")
    survived = re.findall(r"^\w+_survived: (\w+)$", text, re.M)
    require(len(survived) == 6 and set(survived) == {"yes"}, "incomplete/failed survival probes")
    require(len(re.findall(r"^--- \d+\.", text, re.M)) == 16, "incomplete ubusd transcript")
    require(re.search(r"^session_create: .*\"sid\":MASKED", text, re.M), "provider never replied")


def transcript42(text):
    for line in ("survived: yes", "final objects unchanged: yes", "final serving: 0", "final fd bounded: yes"):
        require(line in text.splitlines(), "missing/failed " + line.split(":")[0])
    cases = re.findall(r"^mutated#(\d+) ", text, re.M)
    require([int(n) for n in cases] == list(range(600)), "fuzzer did not complete 600 mutations")


def validate(case, out, cycles=200):
    def read(side, name):
        return (out / f"{side}-{name}").read_text(errors="surrogateescape")
    for side in ("c", "rs"):
        if case == "r49":
            require(read(side, "alive.txt").strip() == "yes", f"{side}: netifd did not survive")
        if case in ("r49", "r50", "r52", "r55", "r57", "r58", "r63"):
            kernel(read(side, "kernel.txt"))
        if case in ("r49", "r63"):
            sec = sections(read(side, "ubus.txt"))
            interfaces(sec.get("interface dump", ""))
            require(object_json(sec.get("device status", "")), "missing device status")
            if case == "r63":
                require(object_json(sec.get("wireless status", "")), "wireless fixture was not loaded")
                object_json(sec.get("wireless get_validate", ""))
        elif case == "r50":
            resources(read(side, "resource.txt"), cycles)
            interfaces(read(side, "final.json"), ("loopback", "lan", "wired"))
            require("192.168.1.1/24" in read(side, "kernel.txt")
                    and "10.0.0.1/24" in read(side, "kernel.txt"), "cycle lost kernel addresses")
        elif case == "r52":
            sec = sections(read(side, "ubus.txt"))
            interfaces(sec.get("interface dump", ""), ("loopback", "wan"))
            lease(sec.get("wan status", ""))
            lease(read(side, "reup-status.txt"))
            addr = [set(re.findall(r"\binet6? (\S+)", read(side, f"veth0-{phase}.txt")))
                    for phase in ("before", "after")]
            # veth0 is discovered as veth1's parent. system_if_clear_state
            # removes its IPv4 address on BOTH daemons; link-local survives.
            require("10.0.0.1/24" in addr[0] and addr[1] == {"fe80::ff:fe00:0/64"},
                    "unconfigured parent veth0 did not follow reference clear-state behavior")
            require("udhcpc stopped by the teardown" in read(side, "down.txt"), "DHCP helper survived teardown")
        elif case == "r53":
            for phase in ("initial", "renewed"):
                lease(read(side, f"{phase}-lease.json"))
            require(read(side, "A-kill.txt").strip() == "helper killed", "helper kill did not land")
        elif case == "r57":
            require(read(side, "survived.txt").splitlines() == [
                "daemon still running without the bus", "daemon still running after the bus returned"],
                "daemon did not survive bus restart")
            for phase in ("before", "after"):
                interfaces(sections(read(side, phase + ".txt")).get("interface dump", ""))
        elif case in ("r55", "r58"):
            calls = blocks(read(side, "calls.txt"))
            if case == "r55":
                require("setdata_wired" in calls and "upd_data_repeat" in calls and len(calls) >= 30,
                        "write-method transcript incomplete")
                for sec in calls.values():
                    require(sec.get("status", "").strip().isdigit(), "call status missing")
                    interfaces(sec.get("interface dump", ""))
                    require(object_json(sec.get("devices", "")), "device registry missing")
                    code = sec.get("device-status-code", "").strip()
                    require(code in ("0", "254"), "device status failed unexpectedly")
                    if code == "0":
                        require("present" in object_json(sec.get("device status veth6", "")), "device reply missing")
                    else:
                        require("Invalid argument" in sec.get("device status veth6", ""), "invalid device failure reply")
            else:
                for phase in ("startup", "after-add", "after-remove", "after-config-remove"):
                    sec = calls.get(phase, {})
                    interfaces(sec.get("interfaces", ""))
                    require(object_json(sec.get("devices", "")), "device registry missing")
                for label in ("add a dynamic interface with a real device", "remove it again",
                              "remove a config interface, which must survive"):
                    require(calls.get(label, {}).get("status", "").strip() == "0", "dynamic call failed")
        elif case in ("r36", "r42"):
            text = (out / f"{side}.txt").read_text(errors="surrogateescape")
            (transcript36 if case == "r36" else transcript42)(text)


if __name__ == "__main__":
    try:
        validate(sys.argv[1], Path(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else 200)
    except (ValueError, KeyError, OSError) as error:
        print(f"{sys.argv[1]}: evidence gate FAILED: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"{sys.argv[1]}: both scenarios completed and remained usable")
