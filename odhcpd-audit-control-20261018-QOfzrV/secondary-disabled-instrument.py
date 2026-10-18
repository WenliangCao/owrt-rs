#!/usr/bin/env python3
"""Private minimal audit cases; imports the frozen fixture without modifying it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback

import odhcpd_baseline as base


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
    f.record("before_dhcp", f.dhcp("before_info", 11, duid=None, timeout=1))
    f.record("before_ra", f.request("before_rs", "rs", timeout=2))
    if f.args.case == "secondary_socket_failure":
        base.run("ip", "link", "add", "broken0", "type", "veth", "peer", "name", "broken1")
        base.run("sysctl", "-q", "-w", "net.ipv6.conf.broken0.disable_ipv6=1")
        base.run("ip", "link", "set", "broken1", "up")
        base.run("ip", "link", "set", "broken0", "up")
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
