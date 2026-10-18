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
