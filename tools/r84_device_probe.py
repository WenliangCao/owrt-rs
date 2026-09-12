#!/usr/bin/env python3
"""Read-only, redacted health check through the router's actual LAN interface.

Unlike the earlier Wi-Fi-only probe, an alternate Internet connection may be
the Mac's default route. DNS and HTTPS probes explicitly use the router LAN.
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
import re
import shlex
import ssl
import subprocess


def run(args, timeout=10):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}")
    return result.stdout.strip()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def ssh(host, command, timeout=12):
    return run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4",
                "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=4",
                "-o", "ServerAliveCountMax=1", host, command], timeout=timeout)


def probe(host="openwrt", mode="existing", interface=None, ipv6=True,
          static_client=False):
    boot = ssh(host, "cat /proc/sys/kernel/random/boot_id")
    result = {"boot_id": boot, "mode": mode}
    require(re.fullmatch(r"[0-9a-f-]{36}", boot), "invalid boot identity")
    if mode != "existing":
        identity = ssh(host, "/bin/sh /root/r84/stack-switch.sh verify " + shlex.quote(mode))
        components = [line.split()[0] for line in identity.splitlines()]
        require(len(components) == 9 and len(set(components)) == 9,
                "not all nine running identities were verified")
        result["verified_components"] = components
    route = run(["route", "-n", "get", "192.168.1.1"])
    match = re.search(r"interface:\s+(\S+)", route)
    require(match is not None, "router LAN has no client route")
    if interface is None:
        interface = match.group(1)
    require(re.fullmatch(r"en[0-9]+", interface), "invalid Mac LAN interface")
    require(match.group(1) == interface, "router route uses another interface")
    result["client_interface"] = interface
    address = run(["ipconfig", "getifaddr", interface])
    require(ipaddress.ip_address(address) in ipaddress.ip_network("192.168.1.0/24"),
            "client is not on the expected router LAN")
    if not static_client:
        leases = ssh(host, "cat /tmp/dhcp.leases")
        require(any(len(fields) >= 3 and fields[2] == address
                    for fields in (line.split() for line in leases.splitlines())),
                "client has no DHCP lease on this router boot")
        result["client_dhcp"] = True
    else:
        result["client_addressing"] = "static; DHCP validated by daemon health only"
    interfaces = json.loads(ssh(host, "ubus -S -t 3 call network.interface dump"))["interface"]
    interfaces = {entry["interface"]: entry for entry in interfaces}
    required = ("loopback", "lan", "wan", "wan6") if ipv6 else ("loopback", "lan", "wan")
    for name in required:
        require(interfaces.get(name, {}).get("up") is True, f"{name} is not up")
    result["interfaces_up"] = list(required)
    wireless = json.loads(ssh(host, "ubus -S -t 3 call network.wireless status"))
    require(set(wireless) == {"radio0", "radio1"}, "expected both radios")
    aps = []
    for name, radio in wireless.items():
        require(radio["up"] and not radio["pending"] and not radio["retry_setup_failed"],
                f"{name} is not settled")
        for vif in radio["interfaces"]:
            if vif["config"].get("mode") != "ap":
                continue
            port = vif.get("ifname", "")
            require(re.fullmatch(r"[A-Za-z0-9_.-]+", port), "invalid AP name")
            master = ssh(host, "readlink /sys/class/net/" + port + "/master")
            require(master.endswith("/br-lan"), f"{port} is not bridged")
            aps.append(port)
    require(len(aps) >= 2, "expected an AP on each band")
    result["ap_bridges"] = aps
    watchdog = json.loads(ssh(host, "ubus -S -t 3 call system watchdog"))
    require(watchdog.get("status") == "running", "hardware watchdog is not running")
    result["watchdog_running"] = True
    css = "/luci-static/bootstrap/cascade.css"
    expected_css = ssh(host, "sha256sum /www" + css).split()[0]
    for tls in (False, True):
        if tls:
            connection = http.client.HTTPSConnection("192.168.1.1", 443, timeout=6,
                context=ssl._create_unverified_context(), source_address=(address, 0))
        else:
            connection = http.client.HTTPConnection("192.168.1.1", 80, timeout=6,
                source_address=(address, 0))
        try:
            connection.request("GET", css)
            response = connection.getresponse()
            body = response.read()
            require(response.status == 200 and hashlib.sha256(body).hexdigest() == expected_css,
                    ("local HTTPS" if tls else "local HTTP") + " response failed validation")
        finally:
            connection.close()
    result["local_http_https"] = True
    services = json.loads(ssh(host, "ubus -S -t 3 call service list"))
    for name in ("dnsmasq", "odhcpd"):
        instances = services.get(name, {}).get("instances", {})
        require(instances and all(i.get("running") is True for i in instances.values()),
                f"{name} has a stopped instance")
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
        resolved = f"[{target}]" if family == 6 else target
        status = run(["curl", f"-{family}", "--interface", interface, "--noproxy", "*",
                      "--connect-timeout", "4", "--max-time", "8", "-fsS",
                      "--resolve", f"example.com:443:{resolved}", "-o", "/dev/null",
                      "-w", "%{http_code}", "https://example.com/"], timeout=10)
        require(status == "200", f"IPv{family} HTTPS through router LAN failed")
        result[f"dns_https_ipv{family}"] = True
    require(ssh(host, "cat /proc/sys/kernel/random/boot_id") == boot, "router rebooted during probe")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--mode", choices=("existing", "stock", "rust"), default="existing")
    parser.add_argument("--interface")
    parser.add_argument("--ipv4-only", action="store_true")
    parser.add_argument("--static-client", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(probe(args.host, args.mode, args.interface, not args.ipv4_only,
                               args.static_client), sort_keys=True))
    except (RuntimeError, OSError, ValueError, KeyError, http.client.HTTPException,
            subprocess.TimeoutExpired) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
