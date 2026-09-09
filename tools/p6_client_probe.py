#!/usr/bin/env python3
"""Read-only P6 check from the Mac connected to the AX3000T over Wi-Fi.

Proves the running binary, DHCP lease, DNS via the router, and HTTPS over
both address families. Emits no SSIDs, keys, client MACs or hostnames.
"""
import argparse
import ipaddress
import json
import re
import subprocess


def run(args, timeout=8):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}")
    return result.stdout.strip()


def ssh(command):
    return run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4",
                "-o", "ConnectionAttempts=1", "openwrt", command], timeout=6)


def identity():
    boot = ssh("cat /proc/sys/kernel/random/boot_id")
    pid = ssh("pidof netifd")
    if not re.fullmatch(r"[0-9]+", pid):
        raise RuntimeError("expected exactly one netifd process")
    digest = ssh(f"md5sum /proc/{pid}/exe").split()[0]
    return {"boot_id": boot, "netifd_pid": int(pid), "netifd_md5": digest}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def probe(expected_md5=None, ipv6=True):
    result = identity()
    if expected_md5:
        require(result["netifd_md5"] == expected_md5, "candidate is not the running netifd")
    route = run(["route", "-n", "get", "default"])
    require(re.search(r"gateway:\s+192\.168\.1\.1\s", route) and
            re.search(r"interface:\s+en0\s", route), "Mac default route is not the router Wi-Fi")
    address = run(["ipconfig", "getifaddr", "en0"])
    ipaddress.IPv4Address(address)
    leases = ssh("cat /tmp/dhcp.leases")
    require(any(len(fields) >= 3 and fields[2] == address
                for fields in (line.split() for line in leases.splitlines())),
            "Mac has no DHCP lease on this router boot")
    result["client_dhcp"] = True
    interfaces = json.loads(ssh("ubus -S -t 3 call network.interface dump"))["interface"]
    interfaces = {i["interface"]: i for i in interfaces}
    for name in ("loopback", "lan", "wan", "wan6") if ipv6 else ("loopback", "lan", "wan"):
        require(interfaces.get(name, {}).get("up") is True, f"{name} is not up")
    result["network_interfaces"] = "up"
    wireless = json.loads(ssh("ubus -S -t 3 call network.wireless status"))
    require(set(wireless) == {"radio0", "radio1"}, "expected both device radios")
    aps = []
    for name, radio in wireless.items():
        require(radio["up"] and not radio["pending"] and not radio["retry_setup_failed"],
                f"{name} is not settled and up")
        for vif in radio["interfaces"]:
            if vif["config"].get("mode") != "ap":
                continue
            port = vif.get("ifname", "")
            require(re.fullmatch(r"[A-Za-z0-9_.-]+", port), "invalid AP interface name")
            master = ssh(f"readlink /sys/class/net/{port}/master")
            require(master.endswith("/br-lan"), f"{port} is not in br-lan")
            aps.append(port)
    require(len(aps) >= 2, "expected an AP on each band")
    result["ap_bridges"] = aps
    for family, rr in ((4, "A"), (6, "AAAA")) if ipv6 else ((4, "A"),):
        answers = run(["dig", "+time=2", "+tries=1", "@192.168.1.1", "example.com", rr, "+short"])
        addresses = []
        for answer in answers.splitlines():
            try:
                ip = ipaddress.ip_address(answer)
                if ip.version == family:
                    addresses.append(str(ip))
            except ValueError:
                pass
        require(addresses, f"router DNS has no {rr} response")
        target = addresses[0]
        route = run(["route", "-n", "get", "-inet6" if family == 6 else "-inet", target])
        require(re.search(r"interface:\s+en0\s", route), f"IPv{family} egress bypasses router Wi-Fi")
        resolved = f"[{target}]" if family == 6 else target
        status = run(["curl", f"-{family}", "--interface", "en0", "--noproxy", "*",
                      "--connect-timeout", "4", "--max-time", "8", "-fsS",
                      "--resolve", f"example.com:443:{resolved}",
                      "-o", "/dev/null", "-w", "%{http_code}", "https://example.com/"], timeout=10)
        require(status == "200", f"IPv{family} HTTPS failed")
        result[f"dns_https_ipv{family}"] = True
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-md5")
    parser.add_argument("--ipv4-only", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(probe(args.expected_md5, not args.ipv4_only), sort_keys=True))
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"error": str(exc)}))
        raise SystemExit(1)
