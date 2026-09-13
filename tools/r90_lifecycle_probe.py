#!/usr/bin/env python3
"""R90 lifecycle differential in disposable Linux mount/net/PID namespaces.

Compare the exact image's netifd/procd with a candidate. Each case starts from
the same image and requires a live daemon and a reached precondition. Raw
observations stay in OUTPUT; a missing case or failed fixture is a failure.
Usage: sudo python3 tools/r90_lifecycle_probe.py ROOTFS BINS OUTPUT
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

CASES = ("down_claim", "data_update", "setup_failed", "renew_teardown",
         "renew_abort", "task_restart", "reload_config", "reload_twice", "reload_proto", "remove", "available",
         "service_state")

# The pinned cbb83a18 C also retains proto_task_killed across helper starts.
# R90 deliberately improves that case; do not label the C result a pass by
# silently dropping the two timing/signal checks.
ORIGINAL_CHECKS = {"task_restart": {"second_helper_term": False,
                                    "down_without_deadline_kill": False,
                                    "eventual_cleanup": True}}
CHECKS = {
    "down_claim": {"released", "kernel_down"},
    "data_update": {"merged_data", "data_updated", "ifupdate_data", "identical_no_update", "down_data_preserved_without_ifup"},
    "setup_failed": {"autostart_preserved", "setup_retried"},
    "renew_teardown": {"no_stale_renew"},
    "renew_abort": {"no_stale_renew"},
    "task_restart": {"second_helper_term", "down_without_deadline_kill", "eventual_cleanup"},
    "reload_config": {"old_config_teardown", "new_config_setup", "old_helper_terminated"},
    "reload_twice": {"old_config_teardown", "new_config_setup", "old_helper_terminated", "no_intermediate_setup"},
    "reload_proto": {"old_config_teardown", "new_config_setup", "old_helper_terminated"},
    "remove": {"teardown_called", "helper_term"},
    "available": {"unavailable_torn_down", "available_restarts"},
    "service_state": {"same_child_after_state_stop", "delete_still_kills"},
}

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
    if [ -e /tmp/hold-setup ]; then
        trap '' TERM
        echo started > /tmp/out/setup-held
        sleep 60
        return
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
    [ ! -e /tmp/hold-teardown ] || sleep 2
    [ -e /tmp/skip-kill ] || proto_kill_command "$cfg"
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
    if case == "down_claim":
        # Keep the peer outside netifd's device discovery entirely. It must
        # remain administratively down throughout the no-carrier case.
        peer = subprocess.Popen(["unshare", "--net", "sleep", "120"])
        wait_for(lambda: os.readlink(f"/proc/{peer.pid}/ns/net") != os.readlink("/proc/self/ns/net"))
        run("ip", "link", "set", "veth0", "netns", str(peer.pid))
    else:
        run("ip", "link", "set", "veth0", "up")

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

    def text(name):
        path = output / name
        return path.read_text() if path.exists() else ""

    def snapshot(label):
        value = call("network.interface.wan", "status")
        write(output / (label + ".json"), json.dumps(value, indent=2) + "\n")
        return value

    def up():
        return call("network.interface.wan", "status").get("up")

    def down():
        s = call("network.interface.wan", "status")
        # TEARDOWN also reports up=false,pending=false. Require state cleanup
        # and reaping of the helper, not merely the status booleans.
        d = call("network.device", "status", {"name": "veth1"})
        write(output / "last-down-status.json", json.dumps({"interface": s, "device": d}))
        helper = text("helper-pid").strip()
        return (not s["up"] and not s["pending"] and not s.get("data")
                and (not helper or not Path('/proc/' + helper).exists()))

    def notify(**fields):
        return call("network.interface.wan", "notify_proto", fields)

    start("/sbin/ubusd")
    wait_for(lambda: (root / "tmp/run/ubus/ubus.sock").exists())
    component = "procd" if case == "service_state" else "netifd"
    binary = "/sbin/" + component if side == "original" else "/tmp/" + component + "-rs"
    daemon = start(binary, *( ["-S", "-I", "/tmp/initd", "-R", "/tmp/rcd"]
                             if component == "procd" else []))
    wait_for(lambda: ready("service" if component == "procd" else "network.interface.wan"))
    assert daemon.poll() is None
    assert Path(f"/proc/{daemon.pid}/exe").resolve() == root / binary.lstrip("/")
    result = {}
    if case == "service_state":
        call("service", "set", {"name": "stubborn", "instances": {"i": {
            "command": ["/bin/sh", "-c", "trap '' TERM; echo ready >/tmp/out/stubborn; while :; do sleep 1; done"],
            "term_timeout": 1}}})
        wait_for(lambda: text("stubborn"))
        pid = call("service", "list", {"name": "stubborn"})["stubborn"]["instances"]["i"]["pid"]
        call("service", "state", {"name": "stubborn", "spawn": False})
        time.sleep(2)
        s = call("service", "list", {"name": "stubborn"})["stubborn"]["instances"]["i"]
        result["same_child_after_state_stop"] = s.get("running") is True and s.get("pid") == pid
        call("service", "delete", {"name": "stubborn"})
        wait_for(lambda: not Path(f"/proc/{pid}").exists())
        result["delete_still_kills"] = True
    elif case == "down_claim":
        assert down()
        call("network.interface.wan", "up")
        wait_for(lambda: call("network.device", "status", {"name": "veth1"}).get("up"))
        time.sleep(0.3)
        claimed = snapshot("claimed")
        write(output / "claimed-dev.json", json.dumps(call("network.device", "status", {"name": "veth1"})))
        write(output / "claimed-links.json", run("ip", "-j", "link", "show", capture_output=True).stdout.decode())
        assert not claimed["up"] and not claimed["pending"]
        call("network.interface.wan", "down")
        time.sleep(0.3)
        result["released"] = not call("network.device", "status", {"name": "veth1"})["up"]
        links = json.loads(run("ip", "-j", "link", "show", "veth1", capture_output=True).stdout)
        result["kernel_down"] = "UP" not in links[0]["flags"]
    elif case == "renew_abort":
        wait_for(lambda: text("setup-held"))
        assert call("network.interface.wan", "status")["pending"]
        call("network.interface.wan", "down")
        call("network.interface.wan", "renew")
        wait_for(down)
        (root / "tmp/hold-setup").unlink()
        call("network.interface.wan", "up")
        wait_for(up)
        time.sleep(0.3)
        result["no_stale_renew"] = "renew\n" not in text("actions")
    else:
        wait_for(up)
        wait_for(lambda: text("helper-pid"))
        time.sleep(0.2)  # let the setup script exit before exercising S_IDLE
        snapshot("before")
        if case == "data_update":
            notify(action=0, **{"link-up": True, "keep": True, "data": {"lease": 2}})
            s = snapshot("changed")
            result["merged_data"] = s["data"] == {"lease": 2, "retained": "yes"}
            result["data_updated"] = "data" in s.get("updated", [])
            time.sleep(0.3)
            result["ifupdate_data"] = "wan:ifupdate:1\n" in text("hotplug")
            notify(action=0, **{"link-up": True, "keep": True, "data": {"lease": 2}})
            s = snapshot("identical")
            result["identical_no_update"] = not s.get("updated")
            call("network.interface.wan", "down")
            wait_for(down)
            notify(action=0, **{"link-up": True, "ifname": "veth1", "data": {"late": 3}})
            s = snapshot("data-while-down")
            result["down_data_preserved_without_ifup"] = not s["up"] and s["data"] == {"late": 3}
        elif case == "setup_failed":
            notify(action=7)
            time.sleep(1)
            s = snapshot("after-failure")
            result["autostart_preserved"] = s["autostart"]
            result["setup_retried"] = text("actions").count("setup:old\n") >= 2 and s["up"]
        elif case == "renew_teardown":
            write(root / "tmp/hold-teardown", "")
            call("network.interface.wan", "down")
            wait_for(lambda: "teardown:old\n" in text("actions"))
            call("network.interface.wan", "renew")
            wait_for(down)
            (root / "tmp/hold-teardown").unlink()
            call("network.interface.wan", "up")
            wait_for(up)
            time.sleep(0.3)
            result["no_stale_renew"] = "renew\n" not in text("actions")
        elif case == "task_restart":
            first_pid = text("helper-pid")
            call("network.interface.wan", "down")
            wait_for(down)
            call("network.interface.wan", "up")
            wait_for(lambda: text("helper-pid") != first_pid)
            wait_for(up)
            time.sleep(0.2)
            snapshot("second-up")
            write(output / "second-helper-alive", str(Path('/proc/' + text('helper-pid').strip()).exists()))
            write(output / "helper-signals", "")
            write(root / "tmp/skip-kill", "")
            started = time.monotonic()
            call("network.interface.wan", "down")
            try:
                wait_for(down, seconds=1)
            except AssertionError:
                pass
            snapshot("second-down")
            result["second_helper_term"] = "term\n" in text("helper-signals")
            result["down_without_deadline_kill"] = down()
            wait_for(down, seconds=8)
            result["eventual_cleanup"] = True
            write(output / "timing.json", json.dumps({"second_teardown_ms": (time.monotonic() - started) * 1000}))
        elif case in ("reload_config", "reload_twice", "reload_proto"):
            if case == "reload_twice":
                write(root / "tmp/hold-teardown", "")
            new_config = config("middle" if case == "reload_twice" else "new")
            if case == "reload_proto":
                new_config = "config interface 'wan'\n option device 'veth1'\n option proto 'static'\n option ipaddr '10.90.0.2/24'\n"
            write(root / "etc/config/network", new_config)
            call("network", "reload")
            if case == "reload_twice":
                wait_for(lambda: "teardown:" in text("actions"))
                write(root / "etc/config/network", config("new"))
                call("network", "reload")
            if case == "reload_proto":
                wait_for(lambda: call("network.interface.wan", "status")["proto"] == "static")
            else:
                wait_for(lambda: "setup:new\n" in text("actions"))
            wait_for(up)
            result["old_config_teardown"] = "teardown:old\n" in text("actions")
            result["new_config_setup"] = True
            result["old_helper_terminated"] = "term\n" in text("helper-signals")
            if case == "reload_twice":
                result["no_intermediate_setup"] = "setup:middle\n" not in text("actions")
        elif case == "remove":
            write(root / "etc/config/network", "")
            call("network", "reload")
            wait_for(lambda: not ready("network.interface.wan"))
            result["teardown_called"] = "teardown:old\n" in text("actions")
            result["helper_term"] = "term\n" in text("helper-signals")
        elif case == "available":
            notify(action=5, available=False)
            time.sleep(1)
            s = snapshot("unavailable")
            result["unavailable_torn_down"] = not s["up"] and not s["available"]
            notify(action=5, available=True)
            wait_for(up)
            result["available_restarts"] = text("actions").count("setup:old\n") >= 2
    assert daemon.poll() is None, "daemon died"
    call("service" if component == "procd" else "network", "list" if component == "procd" else "get_proto_handlers")
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
    p.add_argument("--component", choices=("netifd", "procd"))
    args = p.parse_args()
    if args.component:
        args.cases = [case for case in args.cases if (case == "service_state") == (args.component == "procd")]
    if not args.cases:
        p.error("no cases selected")
    if os.geteuid() != 0 or sys.platform != "linux":
        p.error("run as root on the Linux build host")
    args.output.mkdir(parents=True, exist_ok=False)
    components = sorted({"procd" if c == "service_state" else "netifd" for c in args.cases})
    identities = {name: hashlib.sha256((args.bins / (name + "-rs")).read_bytes()).hexdigest()
                  for name in components}
    write(args.output / "binaries.json", json.dumps(identities, indent=2) + "\n")
    rows = []
    for side in args.sides:
        for case in args.cases:
            destination = args.output / f"{side}-{case}"
            destination.mkdir()
            with tempfile.TemporaryDirectory(prefix="r90-lifecycle-") as temp:
                root = Path(temp) / "root"
                shutil.copytree(args.rootfs, root, symlinks=True)
                for directory in ("out", "run/ubus", "lock", "state", "resolv.conf.d", "initd", "rcd"):
                    (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
                for component in components:
                    shutil.copy2(args.bins / (component + "-rs"), root / "tmp" / (component + "-rs"))
                write(root / "etc/config/network", config())
                if case == "down_claim":
                    write(root / "etc/config/network", config() + " option auto '0'\n option force_link '0'\n")
                write(root / "etc/config/wireless", "")
                write(root / "lib/netifd/proto/probe.sh", PROTO, True)
                write(root / "tmp/helper.sh", HELPER, True)
                write(root / "sbin/hotplug-call", HOTPLUG, True)
                if case == "renew_abort":
                    write(root / "tmp/hold-setup", "")
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
