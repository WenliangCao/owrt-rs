#!/usr/bin/env python3
"""Observe a guarded odhcpd trial from a Mac; never activates or confirms it.

Only read network state and issue DNS/HTTPS requests. No lease renewal, client
reconfiguration or router mutation. Private JSONL retains actual addresses.
"""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from zoneinfo import ZoneInfo

import r84_device_probe as base

REPO = Path(__file__).resolve().parent.parent
SDK_SHA = "79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55"
UUID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def ipv6(text):
    return ipaddress.IPv6Address(text.split("%", 1)[0])


def parse_addresses(text):
    addresses = []
    for line in text.splitlines():
        match = re.search(r"\binet6\s+(\S+)\s+prefixlen\s+(\d+)(.*)", line)
        if not match:
            continue
        address = ipv6(match[1])
        flags = match[3].split()
        addresses.append({"address": str(address), "length": int(match[2]), "flags": flags,
                          "usable": not (address.is_link_local or address.is_loopback or
                                         address.is_unspecified or address.is_multicast) and
                          not any(flag in flags for flag in ("tentative", "duplicated", "detached", "deprecated"))})
    return addresses


def parse_defaults(text, interface):
    routes = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == "default" and fields[3] == interface:
            gateway = ipv6(fields[1])
            require("U" in fields[2] and "G" in fields[2], "IPv6 default route is not up through a gateway")
            routes.append({"gateway": str(gateway), "flags": fields[2], "interface": interface})
    return routes


def parse_dns(text):
    result = []
    for block in re.split(r"(?m)^resolver #", text)[1:]:
        servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", block)
        interface = re.search(r"if_index\s*:\s*\d+\s*\(([^)]+)\)", block)
        if servers:
            result.append({"servers": servers, "interface": interface[1] if interface else None,
                           "local_proxy": any(ipaddress.ip_address(server.split("%", 1)[0]).is_loopback
                                              for server in servers)})
    return result


def parse_ra(text, timezone):
    match = re.search(r"RA Received (\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}) from ([^,\s]+).*?lifetime (\d+)s", text)
    require(match is not None, "ipconfig getra did not return a received RA with a lifetime")
    local = dt.datetime.strptime(match[1], "%m/%d/%Y %H:%M:%S").replace(tzinfo=ZoneInfo(timezone))
    servers = []
    for line in text.splitlines():
        if "rdnss option" not in line:
            continue
        lifetime = re.search(r"lifetime (\d+)s", line)
        if not lifetime or int(lifetime[1]) == 0:
            continue
        for address in re.findall(r"addr:\s*([0-9a-fA-F:%._-]+)", line):
            servers.append(str(ipv6(address)))
    return {"received_local": match[1], "timezone": timezone,
            "received_epoch": local.timestamp(), "received_utc": local.astimezone(dt.timezone.utc).isoformat(),
            "source": str(ipv6(match[2])), "router_lifetime": int(match[3]), "rdnss": servers}


def parse_stat(line):
    tail = line.rsplit(") ", 1)[1].split()
    require(len(tail) >= 20, "truncated odhcpd /proc stat")
    return {"parent_pid": int(tail[1]), "start_ticks": int(tail[19])}


def production_identity(host, expected):
    command = "ubus -S -t 3 call service list '{\"name\":\"odhcpd\"}'"
    services = json.loads(base.ssh(host, command))
    instances = services.get("odhcpd", {}).get("instances", {})
    require(len(instances) == 1, "expected one procd odhcpd instance")
    name, instance = next(iter(instances.items()))
    pid = instance.get("pid")
    require(instance.get("running") is True and type(pid) is int and pid > 1,
            "procd odhcpd instance is not running")
    require(instance.get("command", [None])[0] == "/usr/sbin/odhcpd", "unexpected procd odhcpd command")
    lines = base.ssh(host, f"set -eu\ncat /proc/{pid}/stat\nsha256sum /proc/{pid}/exe\ncat /proc/{pid}/stat\nsha256sum /proc/{pid}/exe").splitlines()
    require(len(lines) == 4, "malformed odhcpd runtime identity")
    before, after = parse_stat(lines[0]), parse_stat(lines[2])
    require(before == after and before["parent_pid"] == 1, "odhcpd PID changed or is not a production procd child")
    require(lines[1].split()[0] == lines[3].split()[0] == expected, "running odhcpd ELF does not match trial candidate")
    current = json.loads(base.ssh(host, command)).get("odhcpd", {}).get("instances", {})
    require(set(current) == {name} and current[name].get("running") is True and
            all(current[name].get(key) == instance.get(key) for key in ("pid", "command")),
            "procd odhcpd instance changed during verification")
    ra = json.loads(base.ssh(host, "ubus -S -t 3 call dhcp ipv6ra"))
    leases = json.loads(base.ssh(host, "ubus -S -t 3 call dhcp ipv6leases"))
    require(isinstance(ra.get("interfaces", {}).get("br-lan"), list) and ra["interfaces"]["br-lan"],
            "dhcp.ipv6ra has no LAN prefixes")
    require(isinstance(leases.get("device", {}).get("br-lan", {}).get("leases"), list),
            "dhcp.ipv6leases has no LAN lease array")
    return {"pid": pid, "instance": name, **before, "sha256": expected, "ra": ra, "leases": leases}


def optional_command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=5)
        return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "optional read timed out"}


def sample(host, interface, expected_sha, expected_boot, timezone):
    # Existing full gate includes both radios/bridges, WAN/WAN6, DHCPv4 lease,
    # watchdog, router DNS/HTTPS, LuCI and direct en0 dual-stack client HTTPS.
    identity = production_identity(host, expected_sha)
    health = base.probe(host=host, interface=interface, require_client_egress=True)
    require(health["boot_id"] == expected_boot, "router boot differs from the trial gate")
    raw_addresses = base.run(["ifconfig", interface])
    addresses = parse_addresses(raw_addresses)
    usable = [item for item in addresses if item["usable"]]
    require(usable, "client has no usable non-link-local IPv6 address on " + interface)
    raw_routes = base.run(["netstat", "-rn", "-f", "inet6"])
    routes = parse_defaults(raw_routes, interface)
    require(routes, "client has no IPv6 default route on " + interface)
    raw_dns = base.run(["scutil", "--dns"])
    resolvers = parse_dns(raw_dns)
    require(resolvers, "client DNS configuration has no resolver")
    raw_ra = base.run(["ipconfig", "getra", interface])
    ra = parse_ra(raw_ra, timezone)
    require(ra["router_lifetime"] > 0 and any(route["gateway"] == ra["source"] for route in routes),
            "received RA does not describe the active LAN IPv6 default router")
    now = time.time()
    require(ra["received_epoch"] <= now + 2 and now - ra["received_epoch"] < ra["router_lifetime"],
            "received RA is expired or its timestamp/timezone is inconsistent")
    router_addresses = base.ssh(host, "ip -6 addr show dev br-lan")
    lan = {str(ipv6(address)) for address in re.findall(r"\binet6\s+([^/\s]+)/\d+", router_addresses)}
    require(ra["source"] in lan, "received RA source is not the actual router LAN")
    servers = [address for address in ra["rdnss"] if address in lan]
    require(servers, "received RA has no live router-owned IPv6 RDNSS server")
    server = servers[0]
    server_ip = ipv6(server)
    # The local proxy resolver is retained, not reconfigured. The direct check
    # proves DNS over IPv6 to the exact RDNSS received by this client.
    sources = sorted(usable, key=lambda item: (ipv6(item["address"]).is_private != server_ip.is_private,
                                             "temporary" in item["flags"], item["address"]))
    source = sources[0]["address"]
    scoped_server = server + ("%" + interface if server_ip.is_link_local else "")
    route = base.run(["route", "-n", "get", "-inet6", scoped_server])
    require(re.search(r"interface:\s+" + re.escape(interface) + r"(?:\s|$)", route),
            "IPv6 RDNSS route uses another interface")
    answer = base.run(["dig", "-6", "+tcp", "-b", source, "@" + scoped_server, "example.com", "AAAA",
                       "+time=2", "+tries=1", "+noall", "+answer"])
    answers = []
    for line in answer.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[-2] == "AAAA":
            answers.append(str(ipv6(fields[-1])))
    require(answers, "client received no AAAA via TCP over IPv6 to RA RDNSS")
    css = "/luci-static/bootstrap/cascade.css"
    expected_css = base.ssh(host, "sha256sum /www" + css).split()[0]
    local_https = {}
    for family, address in ((4, "192.168.1.1"), (6, scoped_server)):
        target = address if family == 4 else "[" + address.replace("%", "%25") + "]"
        fetched = subprocess.run(["curl", "--interface", interface, "--noproxy", "*", f"-{family}",
                                  "-k", "-f", "-sS", "--connect-timeout", "3", "--max-time", "8",
                                  "https://" + target + css], capture_output=True, timeout=10)
        require(fetched.returncode == 0 and hashlib.sha256(fetched.stdout).hexdigest() == expected_css,
                f"LuCI IPv{family} HTTPS bound to {interface} did not return the expected content")
        local_https[f"ipv{family}"] = True
    final = production_identity(host, expected_sha)
    require(all(final[key] == identity[key] for key in ("pid", "start_ticks", "sha256")),
            "candidate restarted during the client health sample")
    return {"health": health, "candidate": final, "client_ipv6_addresses": addresses,
            "client_ipv6_defaults": routes, "system_resolvers": resolvers,
            "ra": ra, "tcp_ipv6_dns": {"server": scoped_server, "source": source, "answers": answers},
            "luci_https_bound_interface": local_https,
            "raw": {"ifconfig": raw_addresses, "routes6": raw_routes, "dns": raw_dns, "ra": raw_ra,
                    "dhcpv6_packet": optional_command(["ipconfig", "getv6packet", interface])}}


def parse_activation(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "--activated-at must include an explicit UTC offset")
    return parsed.timestamp()


def alarm(_signal, _frame):
    raise TimeoutError("health sample exceeded its bounded deadline")


def observe(args):
    require(sys.platform == "darwin", "run the observer on the actual Mac LAN client")
    require(re.fullmatch(r"en[0-9]+", args.interface), "invalid client LAN interface")
    require(args.continuous_seconds >= 120, "at least 120 seconds of continuous client health is required")
    require(1 <= args.interval <= 10 and 10 <= args.sample_timeout <= 60, "invalid bounded probe schedule")
    activated = parse_activation(args.activated_at)
    receipt = json.loads(args.trial_receipt.read_text())
    expected_sha, boot, token = (receipt[key] for key in ("candidate_sha256", "expected_boot_id", "token"))
    require(expected_sha == SDK_SHA, "trial does not contain the frozen SDK ELF")
    require(re.fullmatch(UUID, boot) and re.fullmatch(UUID, token), "invalid trial boot/token")
    guard = receipt["timeout_s"]
    require(type(guard) is int and guard >= args.continuous_seconds + 60, "guard too short for health window")
    remaining = min(args.max_seconds, activated + guard - 20 - time.time())
    require(activated <= time.time() and remaining >= args.continuous_seconds + args.sample_timeout,
            "insufficient guard time for a fresh continuous health window")
    deadline = time.monotonic() + remaining
    output = args.output.resolve()
    require(output.is_relative_to((REPO / "private").resolve()) and not output.exists(),
            "output must be a new directory below ignored private/")
    os.umask(0o077)
    output.mkdir(parents=True, mode=0o700)
    logpath = output / "health.jsonl"
    start = time.monotonic()
    first_good = None
    selected_identity = None
    fresh_ra = None
    signal.signal(signal.SIGALRM, alarm)
    count = 0
    with logpath.open("x") as log:
        def write(value):
            log.write(json.dumps(value, sort_keys=True) + "\n")
            log.flush()
            os.fsync(log.fileno())
        write({"event": "start", "trial_token": token, "boot_id": boot, "candidate_sha256": expected_sha,
               "activated_at": args.activated_at, "continuous_seconds_required": args.continuous_seconds,
               "instrument_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "base_probe_sha256": hashlib.sha256(Path(base.__file__).read_bytes()).hexdigest()})
        try:
            while time.monotonic() < deadline:
                sample_start = time.monotonic()
                signal.setitimer(signal.ITIMER_REAL, min(args.sample_timeout, deadline - time.monotonic()))
                value = sample(args.host, args.interface, expected_sha, boot, args.client_timezone)
                signal.setitimer(signal.ITIMER_REAL, 0)
                identity = tuple(value["candidate"][key] for key in ("pid", "start_ticks", "sha256"))
                require(selected_identity in (None, identity), "candidate process changed within the continuous window")
                selected_identity = identity
                now = time.monotonic()
                if first_good is None:
                    first_good = now
                held = now - first_good
                # getra timestamps have second granularity. A strict later
                # second proves receipt after activation; equality is not proof.
                if value["ra"]["received_epoch"] > activated:
                    fresh_ra = value["ra"]
                count += 1
                write({"event": "pass", "at": dt.datetime.now(dt.timezone.utc).isoformat(),
                       "elapsed_s": now - start, "sample_duration_s": now - sample_start,
                       "continuous_s": held, "fresh_candidate_ra_seen": fresh_ra is not None, "sample": value})
                print(json.dumps({"sample": count, "continuous_s": round(held, 1),
                                  "fresh_candidate_ra_seen": fresh_ra is not None}), flush=True)
                if held >= args.continuous_seconds:
                    require(fresh_ra is not None, "no client RA received after trial activation")
                    write({"event": "complete", "continuous_client_health_s": held, "samples": count})
                    summary = {"passed": True, "trial_token": token, "boot_id": boot,
                               "candidate_sha256": expected_sha,
                               "external_health_token": hashlib.sha256(logpath.read_bytes()).hexdigest(),
                               "continuous_client_health_s": held, "samples": count,
                               "fresh_candidate_ra": fresh_ra, "client_interface": args.interface,
                               "client_dns_transport": "TCP over IPv6 directly to received RA RDNSS",
                               "system_resolver_unchanged": True}
                    (output / "client-health.json").write_text(json.dumps(summary, indent=2) + "\n")
                    return summary
                time.sleep(min(args.interval, max(0, deadline - time.monotonic())))
            raise TimeoutError("guard reserve reached before client health completed")
        except Exception as exc:
            signal.setitimer(signal.ITIMER_REAL, 0)
            write({"event": "failure", "elapsed_s": time.monotonic() - start,
                   "error": str(exc), "error_type": type(exc).__name__})
            (output / "failure.json").write_text(json.dumps({"passed": False, "error": str(exc)}, indent=2) + "\n")
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trial-receipt", type=Path, required=True)
    parser.add_argument("--activated-at", required=True, help="activation time as ISO8601 with offset, e.g. UTC Z")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--interface", default="en0")
    parser.add_argument("--client-timezone", default="Europe/Berlin")
    parser.add_argument("--continuous-seconds", type=float, default=120)
    parser.add_argument("--interval", type=float, default=5)
    parser.add_argument("--sample-timeout", type=float, default=45)
    parser.add_argument("--max-seconds", type=float, default=240)
    args = parser.parse_args()
    try:
        print(json.dumps(observe(args), indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"passed": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
