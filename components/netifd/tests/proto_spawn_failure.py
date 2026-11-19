#!/usr/bin/env python3
"""Protocol recovery differential in disposable Linux mount/net/PID namespaces.

Compare the exact image's netifd with a candidate. Each case starts from
the same image and requires a live daemon and a reached precondition. Raw
observations stay in OUTPUT; a missing case or failed fixture is a failure.
Usage: sudo python3 components/netifd/tests/proto_spawn_failure.py ROOTFS BINS OUTPUT
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

CASES = ("healthy_spawn", "fail_spawn", "dependency", "bridge_remove", "bridge_last_port", "bridge_options", "bridge_unused", "external_bridge", "prefix_lengths",
         "offlink_reload", "offlink_failure", "assignment_route", "ifaceid_list", "prefix_class", "expiry", "inactive_ip", "vanish", "typed_config")
ORIGINAL_CHECKS = {}
CHECKS = {case: {"recovered", "same_daemon"} for case in CASES}
CHECKS["bridge_remove"] = {"removed_from_kernel", "removed_from_status", "dynamic_preserved"}
CHECKS["bridge_last_port"] = {"removed_from_kernel", "unavailable", "address_removed"}
CHECKS["dependency"] = {"initially_unavailable", "recovered", "loss_detected", "recovered_again", "same_daemon"}
CHECKS["bridge_options"] = {"snooping_on_applied", "snooping_off_applied", "configured_port_preserved", "same_daemon"}
CHECKS["prefix_lengths"] = {"invalid_lengths_rejected", "valid_lengths_kept", "same_daemon"}
CHECKS["bridge_unused"] = {"managed_bridge_removed", "member_detached", "same_daemon"}
CHECKS["external_bridge"] = {"unclaimed_external_object", "external_bridge_preserved", "same_daemon"}
CHECKS["offlink_reload"] = {"null_route_preserved", "no_connected_route", "no_host_prefix_route", "same_daemon"}
CHECKS["offlink_failure"] = {"null_route_after_failure", "address_renewed", "null_route_after_renewal", "same_daemon"}
CHECKS["assignment_route"] = {"assignment_withdrawn", "old_route_removed", "address_deprecated", "same_daemon"}
CHECKS["ifaceid_list"] = {"scalar_policy_ignores_list", "same_daemon"}
CHECKS["prefix_class"] = {"explicit_class_assigned", "fallback_class_rejected", "same_daemon"}
CHECKS["expiry"] = {"address_retired", "finite_route_retired", "infinite_route_preserved", "same_daemon"}
CHECKS["inactive_ip"] = {"still_down", "no_inactive_route", "no_inactive_neighbor", "unowned_neighbor_preserved", "same_daemon"}
CHECKS["vanish"] = {"absent_from_named_status", "absent_from_bulk_status", "both_recovered", "same_daemon"}
CHECKS["typed_config"] = {"typed_arguments", "equivalent_reload_kept", "string_reload_restarted", "same_daemon"}

PROTO = r'''#!/bin/sh
. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"
proto_probe_init_config() {
    renew_handler=1
    proto_config_add_string token
}
proto_probe_setup() {
    local cfg="$1" iface="$2" token
    json_get_var token token
    echo "setup:$token" >> /tmp/out/actions
    if [ -e /tmp/dependency ]; then
        proto_add_host_dependency "$cfg" "" under || return
    fi
    proto_run_command "$cfg" /bin/sh /tmp/helper.sh
    proto_init_update "$iface" 1
    proto_add_ipv4_address 10.90.0.1 24
    proto_add_data
    json_add_int lease 1
    json_add_string retained yes
    proto_close_data
    proto_send_update "$cfg"
}
proto_probe_teardown() {
    local cfg="$1" token
    json_get_var token token
    echo "teardown:$token" >> /tmp/out/actions
    proto_kill_command "$cfg"
}
proto_probe_renew() { echo renew >> /tmp/out/actions; }
add_protocol probe
'''

HELPER = r'''#!/bin/sh
trap 'kill "$sleeper"; wait "$sleeper"; echo term >> /tmp/out/helper-signals; exit 0' TERM
echo $$ > /tmp/out/helper-pid
sleep 600 &
sleeper=$!
wait "$sleeper"
'''

HOTPLUG = r'''#!/bin/sh
printf '%s:%s:%s\n' "$INTERFACE" "$ACTION" "$IFUPDATE_DATA" >> /tmp/out/hotplug
'''

TYPED_PROTO = r'''#!/bin/sh
if [ "$2" = dump ]; then
 echo '{"name":"probe","config":[["label",3],["count",5]]}'
 exit 0
fi
printf '%s\t%s\n' "$2" "$4" >> /tmp/out/arguments
if [ "$2" = setup ]; then
 ubus call network.interface.$3 notify_proto '{"action":0,"link-up":true}'
fi
'''


def run(*cmd, **kwargs):
    return subprocess.run([str(c) for c in cmd], check=True, **kwargs)


def wait_for(fn, seconds=10):
    until = time.monotonic() + seconds
    while True:
        value = fn()
        if value:
            return value
        if time.monotonic() >= until:
            raise AssertionError("precondition or completion timed out")
        time.sleep(0.05)


def write(path, text, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if executable:
        path.chmod(0o755)


def config(token="old"):
    return ("config interface 'wan'\n option device 'veth1'\n"
            f" option proto 'probe'\n option token '{token}'\n")


def inner(root, side, case):
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "proc", "proc", "/proc")
    run("mount", "-t", "proc", "proc", root / "proc")
    run("mount", "-t", "sysfs", "sysfs", root / "sys")
    run("mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", root / "dev")
    for name, minor in (("null", 3), ("zero", 5), ("urandom", 9)):
        run("mknod", "-m", "666", root / "dev" / name, "c", "1", minor)
    run("mount", "--bind", root / "dev/null", root / "proc/kmsg")
    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
    run("ip", "link", "set", "veth0", "up")

    if case == "dependency":
        run("ip", "link", "add", "under0", "type", "dummy")
    output = root / "tmp/out"
    processes = []

    def start(binary, *args):
        log = (output / (Path(binary).name + ".log")).open("wb")
        p = subprocess.Popen(["chroot", str(root), binary, *args], stdout=log, stderr=log)
        log.close()
        processes.append(p)
        return p

    def call(obj, method, data=None):
        p = run("chroot", root, "ubus", "-S", "-t", "3", "call", obj, method,
                json.dumps(data or {}), capture_output=True, timeout=5)
        return json.loads(p.stdout or "{}")

    def ready(obj):
        return subprocess.run(["chroot", str(root), "ubus", "-S", "list", obj],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=5).stdout.strip() == obj.encode()

    def snapshot(label):
        value = call("network.interface.wan", "status")
        write(output / (label + ".json"), json.dumps(value, indent=2) + "\n")
        return value

    start("/sbin/ubusd")
    wait_for(lambda: (root / "tmp/run/ubus/ubus.sock").exists())
    binary = "/sbin/netifd" if side == "original" else "/tmp/netifd-rs"
    daemon = start(binary)
    wait_for(lambda: ready("network.interface.wan"))
    assert daemon.poll() is None
    assert Path(f"/proc/{daemon.pid}/exe").resolve() == root / binary.lstrip("/")
    result = {}
    if case in ("offlink_reload", "offlink_failure", "expiry", "inactive_ip"):
        wait_for(lambda: snapshot("ready").get("up"))

        def notify(data):
            return call("network.interface.wan", "notify_proto", {"action": 0, "link-up": True, **data})

        def routes(family):
            return json.loads(run("ip", "-j", family, "route", "show", "table", "all", capture_output=True).stdout)

        def null_route():
            return any(r.get("type") == "unreachable" and r.get("dst") == "2001:db8:44::/64"
                       and r.get("metric") == 2147483647 and "table" not in r for r in routes("-6"))

        if case.startswith("offlink_"):
            data = {"ip6addr": [{"ipaddr": "2001:db8:44::8", "mask": "64", "offlink": True}]}
            notify(data)
            assert null_route(), "initial offlink route missing"
            if case == "offlink_failure":
                Path("/proc/sys/net/ipv6/conf/veth1/disable_ipv6").write_text("1")
            path = root / "etc/config/network"
            path.write_text(path.read_text().replace("metric '10'", "metric '11'"))
            call("network", "reload")
            write(output / "reload-routes.json", json.dumps(routes("-6"), indent=2))
            if case == "offlink_failure":
                actual = json.loads(run("ip", "-j", "addr", "show", "dev", "veth1", capture_output=True).stdout)[0]["addr_info"]
                assert not any(a["local"] == "2001:db8:44::8" for a in actual), "address re-add did not fail"
                result["null_route_after_failure"] = null_route()
                Path("/proc/sys/net/ipv6/conf/veth1/disable_ipv6").write_text("0")
                notify(data)
                result["address_renewed"] = any(a["address"] == "2001:db8:44::8" for a in snapshot("renewed")["ipv6-address"])
                result["null_route_after_renewal"] = null_route()
            else:
                result["null_route_preserved"] = null_route()
                result["no_connected_route"] = not any(r.get("dst") == "2001:db8:44::/64" and r.get("dev") == "veth1" for r in routes("-6"))
                notify({"ip6addr": [{"ipaddr": "2001:db8:44::8", "mask": "128", "offlink": True}]})
                path.write_text(path.read_text().replace("metric '11'", "metric '12'"))
                call("network", "reload")
                result["no_host_prefix_route"] = not any(r.get("dst") in ("2001:db8:44::8", "2001:db8:44::8/128") and r.get("protocol") == "static" for r in routes("-6"))
        elif case == "expiry":
            notify({"ipaddr": [{"ipaddr": "192.0.2.8", "mask": "24"}],
                    "ip6addr": [{"ipaddr": "2001:db8:44::8", "mask": "64", "offlink": True, "preferred": 1, "valid": 2}],
                    "routes": [{"target": "198.51.100.0", "netmask": "24", "valid": 2}, {"target": "203.0.113.0", "netmask": "24"}]})
            write(output / "before-routes.json", json.dumps(routes("-4"), indent=2))
            assert any(r.get("dst") == "198.51.100.0/24" for r in routes("-4"))
            time.sleep(4)  # Cross both the lifetime and the daemon's one-second expiry tick.
            result["address_retired"] = not snapshot("expired").get("ipv6-address")
            result["finite_route_retired"] = not any(r.get("dst") == "198.51.100.0/24" for r in routes("-4"))
            result["infinite_route_preserved"] = any(r.get("dst") == "203.0.113.0/24" for r in routes("-4"))
        else:
            call("network.interface.wan", "down")
            wait_for(lambda: not snapshot("down").get("up") and not snapshot("down").get("pending"))
            run("ip", "link", "set", "veth1", "up")
            run("ip", "addr", "add", "192.0.2.200/24", "dev", "veth1")
            notify({"ipaddr": [{"ipaddr": "192.0.2.8", "mask": "24"}],
                    "routes": [{"target": "198.51.100.0", "netmask": "24", "gateway": "192.0.2.1"}],
                    "neighbor": [{"ipaddr": "192.0.2.9", "mac": "02:00:00:00:00:09"}]})
            result["still_down"] = not snapshot("notified").get("up")
            result["no_inactive_route"] = not any(r.get("dst") == "198.51.100.0/24" for r in routes("-4"))
            result["no_inactive_neighbor"] = not json.loads(run("ip", "-j", "neigh", "show", "to", "192.0.2.9", "dev", "veth1", capture_output=True).stdout)
            run("ip", "neigh", "replace", "192.0.2.9", "lladdr", "02:00:00:00:00:19", "nud", "permanent", "dev", "veth1")
            notify({})
            result["unowned_neighbor_preserved"] = any(n.get("lladdr") == "02:00:00:00:00:19" for n in json.loads(run("ip", "-j", "neigh", "show", "dev", "veth1", capture_output=True).stdout))
        result["same_daemon"] = daemon.poll() is None
    elif case in ("assignment_route", "ifaceid_list", "prefix_class"):
        wait_for(lambda: snapshot("ready").get("up"))
        if case == "prefix_class":
            call("network.interface.wan", "notify_proto", {"action": 0, "link-up": True,
                 "ip6prefix": ["2001:db8:30::/48,4294967295,4294967295,class=gold"]})
            state = call("network.interface.lan", "status")
            write(output / "assignment.json", json.dumps(state, indent=2))
            result["explicit_class_assigned"] = any(a["address"] == "2001:db8:30::" for a in state.get("ipv6-prefix-assignment", []))
            path = root / "etc/config/network"
            path.write_text(path.read_text().replace("ip6class 'gold'", "ip6class 'wan'"))
            call("network", "reload")
            result["fallback_class_rejected"] = not call("network.interface.lan", "status").get("ipv6-prefix-assignment")
        elif case == "ifaceid_list":
            result["scalar_policy_ignores_list"] = snapshot("assigned")["ipv6-prefix-assignment"][0]["local-address"].get("address") == "fd00:30::1"
        else:
            before = snapshot("assigned")
            local = before["ipv6-prefix-assignment"][0]["local-address"]["address"]
            path = root / "etc/config/network"
            path.write_text(path.read_text().replace("ip6class 'local'", "ip6class 'gone'"))
            call("network", "reload")
            result["assignment_withdrawn"] = not snapshot("withdrawn").get("ipv6-prefix-assignment")
            routes = json.loads(run("ip", "-j", "-6", "route", "show", "table", "100", capture_output=True).stdout)
            write(output / "table100.json", json.dumps(routes, indent=2))
            result["old_route_removed"] = not any(r.get("dst") == "fd00:30::/64" and r.get("protocol") == "static" for r in routes)
            addresses = json.loads(run("ip", "-j", "addr", "show", "dev", "veth1", capture_output=True).stdout)[0]["addr_info"]
            result["address_deprecated"] = any(a["local"] == local and a.get("preferred_life_time") == 0 and 7180 <= a["valid_life_time"] <= 7200 for a in addresses)
        result["same_daemon"] = daemon.poll() is None
    elif case == "vanish":
        wait_for(lambda: snapshot("ready").get("up") and call("network.interface.other", "status").get("up"))
        run("ip", "link", "del", "veth1")
        time.sleep(1)
        named = call("network.device", "status", {"name": "veth1"})
        write(output / "removed-device.json", json.dumps(named, indent=2))
        result["absent_from_named_status"] = named.get("present") is False
        result["absent_from_bulk_status"] = "veth1" not in call("network.device", "status")
        run("ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
        run("ip", "link", "set", "veth0", "up")
        wait_for(lambda: snapshot("recovered").get("up") and call("network.interface.other", "status").get("up"))
        result["both_recovered"] = True
        result["same_daemon"] = daemon.poll() is None
    elif case == "typed_config":
        wait_for(lambda: snapshot("ready").get("up"))
        path = root / "etc/config/network"
        def arguments():
            return [(op, json.loads(data)) for op, data in (line.split("\t", 1) for line in (output / "arguments").read_text().splitlines())]
        initial = arguments()
        result["typed_arguments"] = initial[0][1].get("label") == " two  spaces " and initial[0][1].get("count") == 16
        path.write_text(path.read_text().replace("count '0x10'", "count '16'"))
        call("network", "reload")
        time.sleep(0.2)
        result["equivalent_reload_kept"] = arguments() == initial
        path.write_text(path.read_text().replace("label ' two  spaces '", "label 'two spaces'"))
        call("network", "reload")
        wait_for(lambda: len(arguments()) > len(initial))
        wait_for(lambda: snapshot("reloaded").get("up"))
        final = arguments()
        result["string_reload_restarted"] = any(op == "teardown" and data.get("label") == " two  spaces " for op, data in final) and final[-1][1].get("label") == "two spaces"
        result["same_daemon"] = daemon.poll() is None
    elif case == "external_bridge":
        wait_for(lambda: snapshot("ready").get("up"))
        run("ip", "link", "add", "br-external", "type", "bridge")
        before = json.loads(run("ip", "-j", "link", "show", "dev", "br-external",
                                capture_output=True).stdout)[0]
        request = subprocess.run(["chroot", str(root), "ubus", "-S", "call", "network.interface.wan",
                                  "add_device", '{"name":"br-external","link-ext":true}'],
                                 capture_output=True, timeout=5)
        assert request.returncode != 0, "plain interface unexpectedly accepted a bridge member"
        observed = call("network.device", "status", {"name": "br-external"})
        write(output / "external-device.json", json.dumps(observed, indent=2))
        result["unclaimed_external_object"] = observed.get("external") is True and not observed.get("up")
        call("network", "reload")
        call("network", "get_proto_handlers")
        after = json.loads(run("ip", "-j", "link", "show", capture_output=True).stdout)
        write(output / "after-links.json", json.dumps(after, indent=2))
        result["external_bridge_preserved"] = any(
            link["ifname"] == "br-external" and link["ifindex"] == before["ifindex"] for link in after)
        result["same_daemon"] = daemon.poll() is None
    elif case == "bridge_unused":
        wait_for(lambda: snapshot("ready").get("up"))
        write(root / "etc/config/network", "config interface 'wan'\n option device 'veth1'\n"
              " option proto 'static'\n option ipaddr '10.90.0.1/24'\n")
        call("network", "reload")
        wait_for(lambda: snapshot("reloaded").get("l3_device") == "veth1")
        after = json.loads(run("ip", "-j", "link", "show", capture_output=True).stdout)
        write(output / "after-links.json", json.dumps(after, indent=2))
        result["managed_bridge_removed"] = all(link["ifname"] != "br-test" for link in after)
        result["member_detached"] = next(link for link in after if link["ifname"] == "veth1").get("master") is None
        result["same_daemon"] = daemon.poll() is None
    elif case == "bridge_options":
        wait_for(lambda: snapshot("ready").get("up"))
        bridge = root / "sys/class/net/br-test/bridge"
        assert (bridge / "multicast_snooping").read_text().strip() == "0"
        path = root / "etc/config/network"
        for old, new, label in ((0, 1, "on"), (1, 0, "off")):
            path.write_text(path.read_text().replace(f"option igmp_snooping '{old}'", f"option igmp_snooping '{new}'"))
            call("network", "reload")
            time.sleep(1)
            actual = {name: (bridge / name).read_text().strip()
                      for name in ("multicast_snooping", "multicast_querier")}
            write(output / (label + "-kernel.json"), json.dumps(actual, indent=2))
            write(output / (label + "-device.json"), json.dumps(call("network.device", "status", {"name": "br-test"}), indent=2))
            result["snooping_" + label + "_applied"] = all(value == str(new) for value in actual.values())
        links = json.loads(run("ip", "-j", "link", "show", capture_output=True).stdout)
        result["configured_port_preserved"] = next(x for x in links if x["ifname"] == "veth1").get("master") == "br-test"
        result["same_daemon"] = daemon.poll() is None
    elif case.startswith("bridge_"):
        wait_for(lambda: snapshot("ready").get("up"))
        if case == "bridge_remove":
            run("ip", "link", "add", "dynamic0", "type", "dummy")
            call("network.interface.wan", "add_device", {"name": "dynamic0", "link-ext": False})
            time.sleep(0.5)
        before = json.loads(run("ip", "-j", "link", "show", capture_output=True).stdout)
        assert next(x for x in before if x["ifname"] == "veth1").get("master") == "br-test"
        if case == "bridge_remove":
            assert next(x for x in before if x["ifname"] == "dynamic0").get("master") == "br-test"
        write(output / "before-links.json", json.dumps(before, indent=2))
        path = root / "etc/config/network"
        path.write_text(path.read_text().replace(" list ports 'veth1'\n", ""))
        call("network", "reload")
        time.sleep(1)
        after = json.loads(run("ip", "-j", "link", "show", capture_output=True).stdout)
        write(output / "after-links.json", json.dumps(after, indent=2))
        result["removed_from_kernel"] = next(x for x in after if x["ifname"] == "veth1").get("master") != "br-test"
        if case == "bridge_remove":
            status = call("network.device", "status", {"name": "br-test"})
            write(output / "after-device.json", json.dumps(status, indent=2))
            result["removed_from_status"] = "veth1" not in status.get("bridge-members", [])
            result["dynamic_preserved"] = next(x for x in after if x["ifname"] == "dynamic0").get("master") == "br-test"
        else:
            result["unavailable"] = snapshot("empty").get("available") is False
            addrs = json.loads(run("ip", "-j", "addr", "show", capture_output=True).stdout)
            write(output / "after-addresses.json", json.dumps(addrs, indent=2))
            result["address_removed"] = all(a.get("local") != "10.90.0.1" for link in addrs for a in link["addr_info"])
    elif case == "prefix_lengths":
        call("network.interface.wan", "up")
        wait_for(lambda: snapshot("ready").get("up"))
        observations = []
        for length in (56, 0, *range(65, 129), 64):
            call("network.interface.wan", "notify_proto", {"action": 0, "link-up": True,
                                                          "ip6prefix": [f"2001:db8:1::/{length}"]})
            observed = snapshot(f"prefix-{length}").get("ipv6-prefix", [])
            observations.append({"length": length, "prefixes": observed})
        write(output / "prefixes.json", json.dumps(observations, indent=2))
        result["invalid_lengths_rejected"] = all(not row["prefixes"] for row in observations if row["length"] not in (56, 64))
        result["valid_lengths_kept"] = all(any(p["mask"] == row["length"] for p in row["prefixes"])
                                          for row in observations if row["length"] in (56, 64))
        result["same_daemon"] = daemon.poll() is None
    elif case == "dependency":
        time.sleep(0.5)
        result["initially_unavailable"] = snapshot("initial").get("available") is False
        call("network.interface.under", "up")
        time.sleep(1)
        result["recovered"] = snapshot("first-recovery").get("up") is True
        call("network.interface.under", "down")
        time.sleep(1)
        result["loss_detected"] = snapshot("dependency-lost").get("available") is False
        call("network.interface.under", "up")
        time.sleep(1)
        result["recovered_again"] = snapshot("second-recovery").get("up") is True
        result["same_daemon"] = daemon.poll() is None
    else:
        script = root / "lib/netifd/proto/probe.sh"
        saved = script.read_text()
        if case == "fail_spawn":
            script.unlink()
        call("network.interface.wan", "up")
        time.sleep(0.5)
        snapshot("before-repair")
        if case == "fail_spawn":
            write(script, saved, True)
        time.sleep(3)
        result["recovered"] = snapshot("after-repair").get("up") is True
        result["same_daemon"] = daemon.poll() is None
    assert daemon.poll() is None, "daemon died"
    call("network", "get_proto_handlers")
    write(output / "result.json", json.dumps(result, indent=2) + "\n")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        inner(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
        return
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rootfs", type=Path)
    p.add_argument("bins", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--cases", nargs="+", choices=CASES, default=CASES)
    p.add_argument("--sides", nargs="+", choices=("original", "candidate"), default=("original", "candidate"))
    args = p.parse_args()
    if os.geteuid() != 0 or sys.platform != "linux":
        p.error("run as root on the Linux build host")
    args.output.mkdir(parents=True, exist_ok=False)
    components = ["netifd"]
    identities = {name: hashlib.sha256((args.bins / (name + "-rs")).read_bytes()).hexdigest()
                  for name in components}
    identities["original_netifd"] = hashlib.sha256((args.rootfs / "sbin/netifd").read_bytes()).hexdigest()
    write(args.output / "binaries.json", json.dumps(identities, indent=2) + "\n")
    rows = []
    for side in args.sides:
        for case in args.cases:
            destination = args.output / f"{side}-{case}"
            destination.mkdir()
            with tempfile.TemporaryDirectory(prefix="netifd-exec-recovery-") as temp:
                root = Path(temp) / "root"
                shutil.copytree(args.rootfs, root, symlinks=True)
                for directory in ("out", "run/ubus", "lock", "state", "resolv.conf.d"):
                    (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
                for component in components:
                    shutil.copy2(args.bins / (component + "-rs"), root / "tmp" / (component + "-rs"))
                write(root / "etc/config/network", config() + " option auto '0'\n")
                if case in ("offlink_reload", "offlink_failure", "expiry", "inactive_ip", "prefix_class", "typed_config"):
                    write(root / "etc/config/network", config() + " option metric '10'\n")
                if case in ("assignment_route", "ifaceid_list"):
                    extra = " option ip6class 'local'\n option metric '17'\n option ip6table '100'\n" if case == "assignment_route" else " list ip6ifaceid '::beef'\n"
                    write(root / "etc/config/network", "config globals 'globals'\n option ula_prefix 'fd00:30::/48'\nconfig interface 'wan'\n option device 'veth1'\n option proto 'static'\n option ip6assign '64'\n" + extra)
                if case == "vanish":
                    write(root / "etc/config/network", "config interface 'wan'\n option device 'veth1'\n option proto 'static'\n option ipaddr '10.90.0.1/24'\nconfig interface 'other'\n option device 'veth1'\n option proto 'static'\n option ipaddr '10.91.0.1/24'\n")
                if case == "prefix_class":
                    path = root / "etc/config/network"
                    path.write_text(path.read_text() + "config interface 'lan'\n option device 'veth0'\n option proto 'static'\n option ip6assign '64'\n option ip6class 'gold'\n")
                if case == "typed_config":
                    path = root / "etc/config/network"
                    path.write_text(path.read_text() + " option label ' two  spaces '\n option count '0x10'\n")
                if case == "external_bridge":
                    write(root / "etc/config/network", "config interface 'wan'\n option device 'veth1'\n"
                          " option proto 'static'\n option ipaddr '10.90.0.1/24'\n")
                if case == "dependency":
                    write(root / "etc/config/network", config() + "config interface 'under'\n option device 'under0'\n option proto 'static'\n option auto '0'\n option ipaddr '10.91.0.1/24'\n")
                    write(root / "tmp/dependency", "")
                if case.startswith("bridge_"):
                    empty = 1 if case == "bridge_remove" else 0
                    write(root / "etc/config/network", "config device\n option name 'br-test'\n option type 'bridge'\n" + f" option bridge_empty '{empty}'\n" + " option igmp_snooping '0'\n list ports 'veth1'\nconfig interface 'wan'\n option device 'br-test'\n option proto 'static'\n option ipaddr '10.90.0.1/24'\n")
                write(root / "etc/config/wireless", "")
                write(root / "lib/netifd/proto/probe.sh", TYPED_PROTO if case == "typed_config" else PROTO, True)
                write(root / "tmp/helper.sh", HELPER, True)
                write(root / "sbin/hotplug-call", HOTPLUG, True)
                with (destination / "driver.log").open("wb") as log:
                    command = ["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                               sys.executable, str(Path(__file__).resolve()), "--inner", str(root), side, case]
                    result = subprocess.run(["timeout", "-k", "3", "60", *command], stdout=log, stderr=log)
                shutil.copytree(root / "tmp/out", destination / "raw")
            observations = destination / "raw/result.json"
            values = json.loads(observations.read_text()) if observations.exists() else {}
            expected = ORIGINAL_CHECKS.get(case, {}) if side == "original" else {}
            row = {"side": side, "case": case, "exit": result.returncode, "checks": values,
                   "expected_original_difference": expected,
                   "passed": result.returncode == 0 and values.keys() == CHECKS[case]
                   and all(v is expected.get(k, True) for k, v in values.items())}
            rows.append(row)
            print(json.dumps(row), flush=True)
    write(args.output / "results.json", json.dumps(rows, indent=2) + "\n")
    passed = len(rows) == len(args.cases) * len(args.sides) and all(r["passed"] for r in rows)
    (args.output / ("COMPLETE" if passed else "FAILED")).touch()
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
