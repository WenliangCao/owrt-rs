#!/usr/bin/env python3
"""Read-only, redacted health check through the router's actual LAN interface.

Unlike the earlier Wi-Fi-only probe, an alternate Internet connection may be
the Mac's default route. DNS and HTTPS probes explicitly use the router LAN.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex
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


NATIVE_PATHS = {
    "uci": "/sbin/uci", "reload-config": "/sbin/reload_config", "fw4": "/sbin/fw4",
    "logd": "/sbin/logd", "httpd": "/usr/sbin/uhttpd", "rpcd": "/sbin/rpcd",
    "procd": "/sbin/procd", "ubusd": "/sbin/ubusd", "netifd": "/sbin/netifd",
    "dnsmasq": "/usr/sbin/dnsmasq",
}
# Exact stock image executables.json; ujail remains an execution-plane input.
STOCK_UJAIL_SHA256 = "b141627f4c2064b69f214ecc1425904544b69b5b2210fb3195f10ad587c48644"


def load_native_manifest(path):
    raw = Path(path).read_bytes()
    manifest = json.loads(raw)
    require(manifest.get("deployment_layout") == "native-ten", "expected native-ten release manifest")
    require(re.fullmatch(r"[0-9a-f]{40}", manifest.get("source_commit", "")), "invalid native source identity")
    require(set(manifest.get("components", {})) == set(NATIVE_PATHS), "native manifest must contain exactly ten components")
    for name, expected in NATIVE_PATHS.items():
        item = manifest["components"][name]
        require(item.get("path") == expected, "wrong native component path: " + name)
        for key in ("rust_sha256", "stock_sha256"):
            require(re.fullmatch(r"[0-9a-f]{64}", item.get(key, "")), "invalid native hash: " + name)
    return manifest, hashlib.sha256(raw).hexdigest()


def native_identity(host, manifest):
    # Read installed/ROM bytes and production generations; never switch.
    components = manifest["components"]
    expected = {prefix + item["path"]: item["rust_sha256"]
                for item in components.values() for prefix in ("", "/rom")}
    expected.update({prefix + "/sbin/ujail": STOCK_UJAIL_SHA256 for prefix in ("", "/rom")})
    actual = dict(line.split(None, 1)[::-1] for line in ssh(
        host, "sha256sum " + " ".join(shlex.quote(path) for path in expected), timeout=30).splitlines())
    require(actual == expected, "native installed/ROM executable identity mismatch")
    release = json.loads(ssh(host, "cat /usr/share/owrt-control-plane/release.json"))
    require(release.get("layout") == "native-ten" and release.get("source_commit") == manifest["source_commit"],
            "wrong installed native release")
    require(set(release.get("components", {})) == set(NATIVE_PATHS), "installed release omits a component")
    for name, item in components.items():
        require(all(release["components"][name].get(key) == item[key] for key in ("path", "rust_sha256", "stock_sha256")),
                "installed release component differs: " + name)

    command = "ubus -S -t 3 call service list '{\"name\":\"dnsmasq\"}'"
    instances = json.loads(ssh(host, command)).get("dnsmasq", {}).get("instances", {})
    require(instances and all(value.get("running") is True and value.get("jail")
                             and type(value.get("pid")) is int and value["pid"] > 1
                             for value in instances.values()), "dnsmasq is not supervised under ujail")
    parents = {value["pid"] for value in instances.values()}
    require(len(parents) == len(instances), "dnsmasq instances share a supervisor PID")
    # Restrict ordinary daemons to host PID1's children; only configured ujail
    # children may satisfy DNS. Same-name isolated processes never qualify.
    inventory_script = r'''set -eu
for process in /proc/[0-9]*; do
    pid=${process#/proc/}
    before=$(cat "$process/stat" 2>/dev/null) || continue
    fields=$(printf '%s\n' "$before" | awk '{sub(/^.*\) /, ""); print $2, $20}')
    parent=${fields%% *}
    case "$pid:$parent" in 1:*|*:1|__PARENTS__) ;; *) continue;; esac
    digest=$(sha256sum "$process/exe" 2>/dev/null) || continue
    after=$(cat "$process/stat" 2>/dev/null) || continue
    final=$(sha256sum "$process/exe" 2>/dev/null) || continue
    [ "$fields" = "$(printf '%s\n' "$after" | awk '{sub(/^.*\) /, ""); print $2, $20}')" ] || continue
    [ "${digest%% *}" = "${final%% *}" ] || continue
    printf '%s %s %s\n' "$pid" "$fields" "${digest%% *}"
done
'''.replace("__PARENTS__", "|".join("*:" + str(pid) for pid in sorted(parents)))

    def inventory():
        rows = {}
        for line in ssh(host, inventory_script, timeout=30).splitlines():
            pid, parent, start, digest = line.split()
            require(all(value.isdecimal() for value in (pid, parent, start))
                    and re.fullmatch(r"[0-9a-f]{64}", digest), "malformed production process identity")
            require(int(pid) not in rows, "duplicate process snapshot")
            rows[int(pid)] = (int(parent), int(start), digest)
        return rows

    before = inventory()
    selected = {}
    lines = []
    for name in sorted(components):
        digest = components[name]["rust_sha256"]
        if name in ("uci", "fw4", "reload-config"):
            lines.append(f"{name} - - {digest}")
        elif name != "dnsmasq":
            matches = [pid for pid, (parent, _, value) in before.items()
                       if value == digest and (pid == 1 if name == "procd" else parent == 1)]
            require(len(matches) == 1, "expected one production process: " + name)
            pid = matches[0]
            selected[pid] = before[pid]
            lines.append(f"{name} {pid} {before[pid][1]} {digest}")
        else:
            for instance in sorted(instances):
                value = instances[instance]
                parent = value["pid"]
                require(parent in before and before[parent][0] == 1 and before[parent][2] == STOCK_UJAIL_SHA256,
                        "dnsmasq supervisor is not production ujail")
                matches = [pid for pid, row in before.items() if row[0] == parent and row[2] == digest]
                require(len(matches) == 1, "expected one DNS child per production instance")
                pid = matches[0]
                argv = ssh(host, f"cat /proc/{pid}/cmdline")
                require(argv.endswith("\0") and argv[:-1].split("\0") == value.get("command"),
                        "dnsmasq argv differs from the production init submission")
                selected[parent], selected[pid] = before[parent], before[pid]
                lines.append(f"{name} {pid} {before[pid][1]} {digest}")
    after = inventory()
    require(all(after.get(pid) == row for pid, row in selected.items()), "production process changed during capture")
    current = json.loads(ssh(host, command)).get("dnsmasq", {}).get("instances", {})
    require(set(current) == set(instances) and all(current[name].get("running") is True
            and all(current[name].get(key) == value.get(key) for key in ("pid", "command", "jail"))
            for name, value in instances.items()), "dnsmasq production instances changed during capture")
    return "\n".join(lines) + "\n"


def probe(host="openwrt", mode="existing", interface=None, ipv6=True,
          static_client=False, native_manifest=None, host_bundle="/root/r84"):
    boot = ssh(host, "cat /proc/sys/kernel/random/boot_id")
    result = {"boot_id": boot, "mode": mode}
    require(re.fullmatch(r"[0-9a-f-]{36}", boot), "invalid boot identity")
    if mode == "native":
        require(native_manifest is not None, "native probe requires a local release manifest")
        manifest, digest = load_native_manifest(native_manifest)
        result.update(verified_components=sorted(NATIVE_PATHS), native_source_commit=manifest["source_commit"],
                      native_manifest_sha256=digest, native_identity=native_identity(host, manifest))
    elif mode != "existing":
        require(mode in ("stock", "rust"), "invalid production mode")
        identity = ssh(host, "/bin/sh " + shlex.quote(host_bundle + "/stack-switch.sh") + " verify " + shlex.quote(mode))
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
    # Fetch through curl bound to the router LAN address. A per-application VPN
    # filter on the client can force a raw Python socket into the tunnel (where
    # 192.168.1.1 is unroutable) while permitting curl; the assertion (HTTP and
    # HTTPS on the router both return the exact cascade.css) is unchanged.
    for scheme in ("http", "https"):
        fetched = subprocess.run(
            ["curl", "--interface", address, "--noproxy", "*", "-4", "-k", "-sS",
             "--connect-timeout", "4", "--max-time", "8",
             f"{scheme}://192.168.1.1" + css],
            capture_output=True, timeout=10)
        require(fetched.returncode == 0 and hashlib.sha256(fetched.stdout).hexdigest() == expected_css,
                ("local HTTPS" if scheme == "https" else "local HTTP") + " response failed validation")
    result["local_http_https"] = True
    services = json.loads(ssh(host, "ubus -S -t 3 call service list"))
    for name in ("dnsmasq", "odhcpd"):
        instances = services.get(name, {}).get("instances", {})
        require(instances and all(i.get("running") is True for i in instances.values()),
                f"{name} has a stopped instance")
    # Router DNS + internet, checked from the router itself over ssh. A
    # per-application VPN on the client blocks both a raw dig and curl's
    # Mac->internet egress, so the Mac-through-router variant is untestable
    # here; the router's own resolver and fetch are the real health signal.
    nsout = ssh(host, "nslookup example.com 127.0.0.1")
    families = [4, 6] if ipv6 else [4]
    for family in families:
        found = False
        for line in nsout.splitlines():
            token = line.split("Address:")[-1].strip() if "Address:" in line else ""
            try:
                if token and ipaddress.ip_address(token).version == family:
                    found = True
                    break
            except ValueError:
                pass
        require(found, f"router DNS has no IPv{family} answer for example.com")
        result[f"dns_ipv{family}"] = True
    require("OK" in ssh(host, "uclient-fetch -q -T 8 -O /dev/null https://example.com/ && echo OK"),
            "router could not fetch https://example.com")
    result["router_internet_https"] = True
    require(ssh(host, "cat /proc/sys/kernel/random/boot_id") == boot, "router rebooted during probe")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--mode", choices=("existing", "stock", "rust", "native"), default="existing")
    parser.add_argument("--interface")
    parser.add_argument("--native-manifest", type=Path)
    parser.add_argument("--host-bundle", default="/root/r84")
    parser.add_argument("--ipv4-only", action="store_true")
    parser.add_argument("--static-client", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(probe(args.host, args.mode, args.interface, not args.ipv4_only,
                               args.static_client, args.native_manifest, args.host_bundle), sort_keys=True))
    except (RuntimeError, OSError, ValueError, KeyError,
            subprocess.TimeoutExpired) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
