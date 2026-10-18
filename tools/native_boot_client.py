#!/usr/bin/env python3
"""One real veth DHCP/DNS client for the isolated native PID1 boot fixture.

Runs outside the router chroot inside its private outer namespaces. Reuses
the accepted deployment client's DORA, option and UDP/TCP DNS checks. It never
changes a host interface or accesses a physical router.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import traceback

DNS_TOOLS = Path(__file__).resolve().parent / "dnsmasq"
sys.path.insert(0, str(DNS_TOOLS))
from test_deploy_oracle import CLIENT, host, wait


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists()
    assert os.environ.get("NATIVE_BOOT_ISOLATED") == "1"
    assert {name for _, name in socket.if_nameindex()} <= {"lo", "lan1", "client0", "br-lan", "wan"}
    root = args.rootfs.resolve()
    out = root / "tmp/out"
    client = None
    result = {"passed": False, "physical_hardware_tested": False}
    release = json.loads((root / "usr/share/owrt-control-plane/release.json").read_text())
    ipv6 = release["layout"] == "native-eleven"
    try:
        client = subprocess.Popen(["unshare", "--net", "sleep", "infinity"])
        wait(lambda: os.readlink(f"/proc/{client.pid}/ns/net") != os.readlink("/proc/self/ns/net"),
             "private client namespace", seconds=3)
        for command in (("ip", "link", "set", "client0", "netns", str(client.pid)),
                        ("nsenter", "-t", str(client.pid), "-n", "ip", "link", "set", "lo", "up"),
                        ("nsenter", "-t", str(client.pid), "-n", "ip", "link", "set", "client0", "up")):
            host(*command)
        wait(lambda: (out / "server-ready").exists(), "native services ready", seconds=90)
        environment = dict(os.environ, PYTHONPATH=str(DNS_TOOLS))
        response = subprocess.run(["nsenter", "-t", str(client.pid), "-n", sys.executable, "-c", CLIENT],
                                  env=environment, capture_output=True, text=True, timeout=20)
        (out / "client-stdout.log").write_text(response.stdout)
        (out / "client-stderr.log").write_text(response.stderr)
        assert response.returncode == 0, {"returncode": response.returncode, "stderr": response.stderr}
        result["client"] = json.loads(response.stdout)
        assert result["client"]["dhcp_offer"] and result["client"]["dhcp_ack"]
        assert result["client"]["dns"] == {"udp": True, "tcp": True}
        assert result["client"]["address"] == "192.168.1.100"
        def matching_lease():
            leases = (root / "tmp/dhcp.leases").read_text()
            matching = [line.split() for line in leases.splitlines()
                        if len(line.split()) >= 5 and line.split()[1:4] ==
                        ["02:00:00:00:00:27", "192.168.1.100", "native-client"]]
            return leases if len(matching) == 1 else None
        leases = wait(matching_lease, "ACK persisted in the actual lease file", seconds=3)
        (out / "dhcp.leases").write_text(leases)
        result["lease_file_matches_client"] = True
        if ipv6:
            namespace = ["nsenter", "-t", str(client.pid), "-n"]
            host(*namespace, "sysctl", "-q", "-w", "net.ipv6.conf.client0.accept_ra=2", "net.ipv6.conf.client0.autoconf=1")
            host(*namespace, "ip", "-6", "addr", "replace", "fe80::27/64", "dev", "client0", "nodad")
            response = subprocess.run(namespace + [sys.executable, str(Path(__file__).with_name("native_boot_ipv6_client.py"))],
                                      env=environment, capture_output=True, text=True, timeout=35)
            (out / "client-ipv6-stdout.log").write_text(response.stdout)
            (out / "client-ipv6-stderr.log").write_text(response.stderr)
            assert response.returncode == 0, {"returncode": response.returncode, "stderr": response.stderr}
            result["ipv6"] = json.loads(response.stdout)
            assert result["ipv6"]["passed"]
            def matching_v6_state():
                response = host("chroot", root, "/bin/ubus", "-S", "-t", "2", "call", "dhcp", "ipv6leases")
                state = json.loads(response.stdout)
                entries = state["device"]["br-lan"]["leases"]
                client_entries = [entry for entry in entries if entry["duid"] == result["ipv6"]["duid"]]
                if len(client_entries) != 2 or not all("bound" in entry["flags"] for entry in client_entries):
                    return None
                return state
            state = wait(matching_v6_state, "DHCPv6 bound leases visible through dhcp object", seconds=5)
            (out / "odhcpd-ipv6leases.json").write_text(json.dumps(state, indent=2) + "\n")
            entries = state["device"]["br-lan"]["leases"]
            na = next(entry for entry in entries if entry.get("iaid") == 1)
            pd = next(entry for entry in entries if entry.get("iaid") == 2)
            assert {item["address"] for item in na["ipv6-addr"]} == {item["address"] for item in result["ipv6"]["ia_na"]}
            assert {item["address"] for item in pd["ipv6-prefix"]} == {item["address"] for item in result["ipv6"]["ia_pd"]}
            text = (root / "tmp/odhcpd.leases").read_text()
            assert len([line for line in text.splitlines() if result["ipv6"]["duid"] in line]) == 2
            assert result["ipv6"]["hostname"] in text
            for item in result["ipv6"]["ia_na"] + result["ipv6"]["ia_pd"]:
                assert item["address"] + "/" + str(item["length"]) in text
            (out / "odhcpd.leases").write_text(text)
            hosts = (root / "tmp/hosts/odhcpd.hosts.lan").read_text()
            assert all(item["address"] in hosts for item in result["ipv6"]["ia_na"])
            (out / "odhcpd-hosts.txt").write_text(hosts)
            result["ipv6"]["ubus_and_lease_files_match_client"] = True

            def process_identity():
                response = host("chroot", root, "/bin/ubus", "-S", "-t", "2", "call", "service", "list", '{"name":"odhcpd"}')
                instances = json.loads(response.stdout)["odhcpd"]["instances"]
                running = [instance for instance in instances.values() if instance["running"]]
                assert len(running) == 1 and running[0]["command"] == ["/usr/sbin/odhcpd"]
                pid = running[0]["pid"]
                ticks = (root / f"proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
                digest = hashlib.sha256((root / f"proc/{pid}/exe").read_bytes()).hexdigest()
                assert digest == release["components"]["odhcpd"]["rust_sha256"]
                return {"pid": pid, "start_ticks": int(ticks), "sha256": digest}

            before = process_identity()
            (out / "dhcp-before-reload.uci").write_text(host("chroot", root, "/sbin/uci", "export", "dhcp").stdout)
            for command in (("set", "dhcp.lan.leasetime=10m"),
                            ("add_list", "dhcp.lan.dns=2001:db8:53::1"), ("commit", "dhcp")):
                host("chroot", root, "/sbin/uci", *command)
            (out / "dhcp-after-reload.uci").write_text(host("chroot", root, "/sbin/uci", "export", "dhcp").stdout)
            response = host("chroot", root, "/etc/init.d/odhcpd", "reload")
            (out / "odhcpd-init-reload.log").write_text(response.stdout + response.stderr)
            response = subprocess.run(namespace + [sys.executable, str(Path(__file__).with_name("native_boot_ipv6_client.py")), "--renew"],
                                      input=json.dumps(result["ipv6"]), env=environment,
                                      capture_output=True, text=True, timeout=35)
            (out / "client-ipv6-renew-stdout.log").write_text(response.stdout)
            (out / "client-ipv6-renew-stderr.log").write_text(response.stderr)
            assert response.returncode == 0, {"returncode": response.returncode, "stderr": response.stderr}
            renewal = json.loads(response.stdout)
            assert renewal["passed"]
            after = process_identity()
            assert before == after, {"before_reload": before, "after_reload": after}
            renewal["process_before"] = before
            renewal["process_after"] = after
            result["ipv6"]["uci_reload_renewal"] = renewal
            state = matching_v6_state()
            assert state and all(120 < entry["valid"] <= 600 for entry in state["device"]["br-lan"]["leases"])
            (out / "odhcpd-ipv6leases-after-reload.json").write_text(json.dumps(state, indent=2) + "\n")

            response = host("chroot", root, "/bin/ubus", "-S", "-t", "3", "call", "luci-rpc", "getDHCPLeases", '{"family":6}')
            consumers = json.loads(response.stdout)
            (out / "luci-dhcp6-leases.json").write_text(json.dumps(consumers, indent=2) + "\n")
            exported = [entry for entry in consumers["dhcp6_leases"] if entry.get("duid") == result["ipv6"]["duid"]]
            assert len(exported) == 2
            for iaid, key in (("1", "ia_na"), ("2", "ia_pd")):
                entry = next(entry for entry in exported if entry["iaid"] == iaid)
                expected = {item["address"] + "/" + str(item["length"]) for item in result["ipv6"][key]}
                assert set(entry["ip6addrs"]) == expected
                assert entry["interface"] == "br-lan" and 120 < entry["expires"] <= 600
            response = host("chroot", root, "/bin/ubus", "-S", "-t", "3", "call", "luci", "getFeatures")
            features = json.loads(response.stdout)
            (out / "luci-features.json").write_text(json.dumps(features, indent=2) + "\n")
            expected = {"ra": True, "dhcpv6": True, "ubus": True, "ndp": False, "dhcpv4": False}
            assert features["odhcpd"] == expected, features["odhcpd"]
            result["ipv6"]["luci_consumers"] = {"leases": exported, "features": features["odhcpd"], "passed": True}
        result["passed"] = True
    except Exception:
        result["error"] = traceback.format_exc()
    finally:
        if ipv6 and result["passed"]:
            # Keep the real client veth alive until the server has captured
            # its PD route, RA state and supervised daemon identity. Destroying
            # this namespace first brings br-lan down and correctly removes RA.
            result["client_source_sha256"] = hashlib.sha256(CLIENT.encode()).hexdigest()
            result["helper_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            result["ipv6_helper_sha256"] = hashlib.sha256(Path(__file__).with_name("native_boot_ipv6_client.py").read_bytes()).hexdigest()
            (out / "client-result.json").write_text(json.dumps(result, indent=2) + "\n")
            (out / "client-pass").touch()
            try:
                wait(lambda: (out / "client-release").exists(), "server captured IPv6 state", seconds=30)
            except Exception:
                result["passed"] = False
                result["error"] = traceback.format_exc()
        if client is not None:
            client.terminate()
            try:
                client.wait(timeout=3)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait(timeout=3)
        result["client_source_sha256"] = hashlib.sha256(CLIENT.encode()).hexdigest()
        result["helper_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if ipv6:
            result["ipv6_helper_sha256"] = hashlib.sha256(Path(__file__).with_name("native_boot_ipv6_client.py").read_bytes()).hexdigest()
        (out / "client-result.json").write_text(json.dumps(result, indent=2) + "\n")
        (out / ("client-pass" if result["passed"] else "client-fail")).touch()
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
