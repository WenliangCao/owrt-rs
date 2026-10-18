#!/usr/bin/env python3
"""Private minimal audit cases; imports the frozen fixture without modifying it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import traceback

import odhcpd_baseline as base


def extra_probe(f, name):
    code = r"""import json, socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
i = socket.if_nametoindex('broken1')
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'broken1\0')
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, i)
s.bind(('::', 546)); s.settimeout(1)
s.sendto(bytes.fromhex('0b7a7b7c000600020017'), ('ff02::1:2', 547, 0, i))
try:
    data, address = s.recvfrom(8192)
    print(json.dumps({'timeout':False, 'hex':data.hex(), 'source':address[0]}))
except TimeoutError:
    print(json.dumps({'timeout':True}))
"""
    value = json.loads(base.run(*f.ns, sys.executable, "-c", code).stdout)
    f.record(name, value)
    return value


def check_lan(f, label):
    assert f.daemon.poll() is None, "original daemon exited"
    dhcp = f.dhcp(label + "_info", 11, duid=None, timeout=1)
    ra = f.request(label + "_rs", "rs", timeout=2)
    assert not dhcp.get("timeout"), "existing LAN DHCPv6 stopped"
    assert not ra.get("timeout"), "existing LAN RA stopped"
    assert f.bus("dhcp", "ipv6leases", check=False)["status"] == 0
    f.record(label + "_pid", f.daemon.pid)


def case(f):
    f.provider.terminate()
    f.provider.wait(3)
    state_path = f.root / "tmp/audit-state.json"
    state = {"interface": [{"interface": "lan", "up": True, "l3_device": "br-lan", "data": {}}]}
    state_path.write_text(json.dumps(state))
    (f.root / "tmp/provider.uc").write_text("""import { connect } from 'ubus';
import { readfile, writefile } from 'fs'; import { init, run } from 'uloop';
init(); let bus=connect();
let obj=bus.publish('network.interface',{dump:{call:()=>json(readfile('/tmp/audit-state.json'))}});
bus.publish('fixture',{notify:{call:()=>{obj.notify('update',{interface:'lan'});return {};}}});
writefile('/tmp/fixture.ready','ready'); run();
""")
    f.start_provider()
    f.begin_case()
    f.record("original_daemon_pid", f.daemon.pid)
    f.record("before_dhcp", f.dhcp("before_info", 11, duid=None, timeout=1))
    f.record("before_ra", f.request("before_rs", "rs", timeout=2))
    blocker = None
    if f.args.case in ("secondary_socket_failure", "secondary_port_conflict"):
        base.run("ip", "link", "add", "broken0", "type", "veth", "peer", "name", "broken1")
        if f.args.case == "secondary_socket_failure":
            base.run("sysctl", "-q", "-w", "net.ipv6.conf.broken0.disable_ipv6=1")
        base.run("ip", "link", "set", "broken1", "netns", str(f.netns.pid))
        base.run(*f.ns, "ip", "link", "set", "broken1", "up")
        base.run(*f.ns, "ip", "-6", "addr", "add", "fe80::4/64", "dev", "broken1", "nodad")
        base.run("ip", "link", "set", "broken0", "up")
        base.run("ip", "-6", "addr", "add", "fe80::3/64", "dev", "broken0", "nodad")
        if f.args.case == "secondary_port_conflict":
            blocker = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            blocker.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"broken0\0")
            blocker.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            blocker.bind(("::", 547))
        f.record("broken_link", base.run("ip", "-j", "link", "show", "broken0").stdout)
        state["interface"].append({"interface": "extra", "up": True, "l3_device": "broken0", "data": {"ra":"server", "dhcpv6":"server"}})
    elif f.args.case == "ra_preference_default":
        state["interface"][0]["data"]["ra_preference"] = "default"
    else:
        raise RuntimeError("unknown private case")
    state_path.write_text(json.dumps(state))
    f.record("selected_dump", state)
    f.record("notify", f.bus("fixture", "notify"))
    time.sleep(.5)
    f.record("exit_after_notify", f.daemon.poll())
    f.record("after_dhcp", f.dhcp("after_info", 11, duid=None, timeout=1))
    f.record("after_ra", f.request("after_rs", "rs", timeout=2))
    f.record("after_ubus", f.bus("dhcp", "ipv6leases", check=False))
    check_lan(f, "during_change")
    if blocker is not None:
        assert extra_probe(f, "extra_during_conflict")["timeout"]
        blocker.close()
        f.record("notify_after_unblock", f.bus("fixture", "notify"))
        time.sleep(.5)
        extra = extra_probe(f, "extra_after_unblock")
        assert not extra["timeout"], "new interface did not recover after notify"
        assert extra["hex"].startswith("077a7b7c"), "not the matching DHCPv6 Reply"
        check_lan(f, "after_recovery")
    else:
        state["interface"][0]["data"]["ra_preference"] = "invalid-audit-value"
        state_path.write_text(json.dumps(state))
        f.record("invalid_config_notify", f.bus("fixture", "notify"))
        time.sleep(.3)
        check_lan(f, "after_invalid_config")
        state["interface"][0]["data"]["ra_preference"] = "high"
        state_path.write_text(json.dumps(state))
        f.record("valid_config_notify", f.bus("fixture", "notify"))
        time.sleep(.3)
        check_lan(f, "after_valid_config")
        assert f.results["events"]["after_valid_config_rs"]["decoded"]["flags"] & 0x18 == 0x08
    f.record("complete", True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rootfs", required=True)
    p.add_argument("--daemon")
    p.add_argument("--out", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--inside", action="store_true")
    args = p.parse_args()
    if not args.inside:
        Path(args.out).mkdir(mode=0o700, parents=True, exist_ok=False)
        command = ["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", sys.executable, __file__, *sys.argv[1:], "--inside"]
        sys.exit(subprocess.run(command, timeout=45).returncode)
    f = base.Fixture(args)
    try:
        f.setup()
        f.record("private_instrument_sha256", hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        case(f)
        print(json.dumps({"case":args.case,"exit":f.results["events"].get("exit_after_notify"),"after_dhcp_timeout":f.results["events"]["after_dhcp"].get("timeout",False),"after_ra_timeout":f.results["events"]["after_ra"].get("timeout",False)}))
    except Exception:
        f.record("error", traceback.format_exc())
        raise
    finally:
        f.close()


if __name__ == "__main__":
    main()
