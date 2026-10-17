#!/usr/bin/env python3
"""R92 combined build-host validation; never invokes a physical router.

Run from the checked source snapshot. Runtime binaries may be development
or canonical, but their identities are recorded separately from native unit
tests and example probes. Raw outputs must remain outside Git.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def example_inputs(gate_names, examples):
    """Check selected fixtures before starting any expensive runtime gate."""
    required = {
        "procd-watchdog-status": ("watchdog_status",),
        "procd-r65": ("notifier",),
        "procd-r72": ("ptyhold",),
        "httpd-extended": ("notifier",),
        "rpcd-bytes": ("raw_bytes",),
        "ubusd-r83": ("wireprobe",),
        "ubusd-r42": ("fuzz",),
        "ubusd-r41": ("bench",),
        "netifd-suite": ("sysprobe", "devstatus", "ifstatus"),
        "r92-recovery": ("output_lifecycle",),
    }
    names = sorted({name for gate in gate_names for name in required.get(gate, ())})
    missing = [str(examples / name) for name in names
               if not (examples / name).is_file() or not os.access(examples / name, os.X_OK)]
    if missing:
        raise ValueError("missing or non-executable test examples: " + ", ".join(missing))
    return {name: digest(examples / name) for name in names}


def main():
    if sys.argv[1:2] == ["--namespace-command"]:
        if os.environ.get("OWRT_BENCH_NAMESPACE") != "1" or os.geteuid() != 0:
            raise SystemExit("runtime gates require the frozen namespace launcher")
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
        os.execvp(sys.argv[2], sys.argv[2:])
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rootfs", type=Path)
    p.add_argument("bins", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--baseline", type=Path, required=True, help="reference bundle (formal R89 by default)")
    p.add_argument("--httpd-fuzz-baseline-mode", choices=("r89-transition", "current-release"),
                   default="r89-transition", help="current-release requires full equality with the released HTTP baseline")
    p.add_argument("--examples", type=Path, required=True)
    p.add_argument("--fw4-source", type=Path, required=True)
    p.add_argument("--network-config", type=Path, required=True)
    p.add_argument("--wireless-config", type=Path, required=True)
    p.add_argument("--helpers", type=Path, required=True)
    p.add_argument("--target-dir", type=Path, required=True)
    p.add_argument("--reload-receiver", type=Path, help="benchmark containing reload-fault-service for protocol-level reload-config gates")
    p.add_argument("--groups", nargs="+", choices=("unit", "functional", "recovery", "compat"),
                   default=("unit", "functional", "recovery", "compat"))
    p.add_argument("--gates", nargs="+", help="explicit rerun selection; recorded as a partial scope")
    a = p.parse_args()
    if sys.platform != "linux" or Path("/etc/openwrt_release").exists():
        p.error("run only on a Linux build host")
    rootfs, bins, out, examples = [x.resolve() for x in (a.rootfs, a.bins, a.output, a.examples)]
    source = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PATH="/home/ubuntu/.cargo/bin:" + os.environ["PATH"],
               CARGO_TARGET_DIR=str(a.target_dir.resolve()), HELPERS=str(a.helpers.resolve()))
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    gates = []

    def add(group, name, cmd, extra_env=None, required=True):
        gates.append((group, name, [str(v) for v in cmd], extra_env or {}, required))

    for c in ("ubus", "uci", "reload-config", "ubusd", "procd", "netifd", "logd", "httpd", "rpcd", "fw4"):
        cargo = ["cargo", "+1.98.1"]
        add("unit", c + "-unit", cargo + ["test", "--locked", "--manifest-path", f"components/{c}/Cargo.toml"])
        add("unit", c + "-clippy", cargo + ["clippy", "--locked", "--manifest-path", f"components/{c}/Cargo.toml",
            "--all-targets", "--", "-D", "clippy::undocumented_unsafe_blocks"])
    add("unit", "python-gates", [sys.executable, "-m", "unittest", "discover", "-s", "tools", "-p", "test_*.py"])
    add("functional", "procd-watchdog-status", [examples / "watchdog_status"])
    add("functional", "procd-tick", ["sudo", "-n", "python3", "tools/r89_procd_tick_probe.py", rootfs, bins / "procd-rs", out / "procd-tick"])
    for side in ("original", "candidate"):
        add("functional", "procd-busy-" + side, ["sudo", "-n", "python3", "tools/r85_procd_busy_gate.py", rootfs,
            bins / "procd-rs", out / ("procd-busy-" + side), "--sides", side], required=side == "candidate")
    for label, script, args, more in (
        ("procd-r65", "r65_procd_diff.sh", [out / "procd-r65", examples], {}),
        ("procd-r83", "r83_procd_r81.sh", [out / "procd-r83"], {}),
        ("procd-r71-hotplug", "r71_pid1_probe.sh", [out / "procd-r71-hotplug"], {"R90_HOTPLUG_PROBE": "1"}),
        ("procd-r72", "r72_tty_probe.sh", [examples / "ptyhold", out / "procd-r72"], {}),
        ("procd-r75", "r75_sysupgrade_probe.sh", [out / "procd-r75"], {}),
    ):
        add("functional", label, ["sudo", "-n", "env", *[k + "=" + v for k, v in more.items()], "sh", "tools/" + script, rootfs, bins / "procd-rs", *args])
    add("functional", "procd-r90", ["sudo", "-n", "python3", "tools/r90_lifecycle_probe.py", rootfs, bins, out / "procd-r90", "--component", "procd"])
    http = bins / "httpd-rs"
    ns = a.baseline.resolve() / "ns-exec"
    add("functional", "httpd-resources", ["python3", "tools/r86_httpd_resources.py", rootfs, http, ns])
    add("functional", "httpd-static", ["python3", "tools/r85_httpd_static.py", rootfs, http, ns, "--memory-connections", "64"])
    add("functional", "httpd-extended", ["python3", "tools/r83_httpd_compat.py", rootfs, http, examples / "notifier"])
    add("functional", "httpd-r14", ["python3", "tools/r14_httpd_check.py", "--rootfs", rootfs, "--candidate", http,
        "--output", out / "httpd-r14.json", "--image-id", "ax3000t-stock-openwrt-25.12.5", "--recorded-at", now])
    add("functional", "httpd-fuzz", ["python3", "tools/r92_httpd_fuzz_gate.py", rootfs, a.baseline.resolve() / "httpd-rs", http, out / "httpd-fuzz",
        "--baseline-mode", a.httpd_fuzz_baseline_mode])
    add("functional", "httpd-cgi-stress", ["sudo", "-n", "env", "OWRT_HTTPD_CGI_STRESS=1", "sh", "tools/benchmark/isolated.sh", rootfs, bins, "httpd", "rs", out / "httpd-cgi-stress", "30000"])
    rpcd = bins / "rpcd-rs"
    for script in ("r13_rpcd_check", "r17_rpcd_core_check", "r18_rpcd_plugins_check", "r19_lucirpc_check"):
        add("functional", script, ["sudo", "-n", "python3", "tools/" + script + ".py", rootfs, rpcd, "--report", out / (script + ".json")])
    add("functional", "rpcd-busy", ["sudo", "-n", "python3", "tools/r85_rpcd_busy_gate.py", rootfs, rpcd, out / "rpcd-busy"])
    add("functional", "rpcd-r26", ["sudo", "-n", "python3", "tools/r26_rpcd_fuzz.py", rootfs, rpcd, "--cases-per-method", "10", "--seed", "26", "--keep", out / "rpcd-r26"])
    add("functional", "rpcd-real-features", ["sudo", "-n", "python3", "tools/r85_rpcd_features_check.py", rootfs, rpcd, out / "rpcd-real-features", "--calls", "32"])
    add("functional", "rpcd-bytes", ["sh", "tools/r83_rpcd_bytes.sh", rootfs, rpcd, examples / "raw_bytes", out / "rpcd-bytes"])
    add("functional", "rpcd-defer", ["sh", "tools/r83_rpcd_defer.sh", rootfs, rpcd])
    ubusd = bins / "ubusd-rs"
    add("functional", "ubusd-r36", ["sh", "tools/r36_ubusd_diff.sh", rootfs, ubusd, out / "ubusd-r36"])
    add("functional", "ubusd-r36-user", ["env", "DAEMON_USER=ubus", "sh", "tools/r36_ubusd_diff.sh", rootfs, ubusd, out / "ubusd-r36-user"])
    add("functional", "ubusd-r83", ["sh", "tools/r83_ubusd_acl.sh", rootfs, ubusd, examples / "wireprobe", out / "ubusd-r83"])
    add("functional", "ubusd-r42", ["sh", "tools/r42_ubusd_fuzz.sh", rootfs, examples / "fuzz", rootfs / "sbin/ubusd", ubusd, out / "ubusd-r42"])
    add("functional", "ubusd-r41", ["sh", "tools/r41_limits.sh", rootfs, examples / "bench", rootfs / "sbin/ubusd", ubusd, out / "ubusd-r41"])
    add("functional", "netifd-suite", ["sudo", "-n", "env", "NETWORK_CONFIG=" + str(a.network_config.resolve()), "WIRELESS_CONFIG=" + str(a.wireless_config.resolve()),
        "bash", "tools/netifd_suite.sh", rootfs, bins / "netifd-rs", out / "netifd-suite", examples])
    logd = bins / "logd-rs"
    add("functional", "logd-r15", ["sudo", "-n", "python3", "tools/r15_logd_check.py", "--rootfs", rootfs, "--candidate", logd,
        "--output", out / "logd-r15.json", "--image-id", "ax3000t-stock-openwrt-25.12.5", "--recorded-at", now])
    add("functional", "logd-r28", ["sudo", "-n", "python3", "tools/r28_logd_fuzz.py", "--rootfs", rootfs, "--candidate", logd])
    for script in ("r21_logd_reconnect_check", "r25_logd_stream_probe", "r83_logd_ring_wrap", "r83_logd_oversize_read"):
        add("functional", script, ["sh", "tools/" + script + ".sh", rootfs, logd])
    fw4 = bins / "fw4-rs"
    add("functional", "fw4-upstream", ["sudo", "-n", "python3", "tools/r09_fw4_check.py", a.fw4_source.resolve(), fw4])
    add("functional", "fw4-r29", ["sudo", "-n", "python3", "tools/r29_fw4_fuzz.py", a.fw4_source.resolve(), fw4, "--cases", "200", "--seed", "29", "--keep", out / "fw4-r29"])
    add("functional", "fw4-defaults", ["sudo", "-n", "sh", "tools/r83_fw4_defaults.sh", a.fw4_source.resolve(), fw4])
    add("functional", "fw4-image", ["sudo", "-n", "sh", "tools/benchmark/isolated.sh", rootfs, bins, "fw4", "rs", out / "fw4-image", "10"])
    add("functional", "uci-r16", ["sudo", "-n", "python3", "tools/r16_uci_check.py", rootfs, bins / "uci-rs", "--report", out / "uci-r16.json", "--keep", out / "uci-r16"])
    add("functional", "uci-r24", ["sudo", "-n", "python3", "tools/r24_uci_fuzz.py", rootfs, bins / "uci-rs", "--cases", "1000", "--seed", "92", "--keep", out / "uci-r24"])
    add("functional", "uci-r83", ["env", "R92_UCI_RENAME_REJECT=1", "sh", "tools/r83_uci_findings.sh", rootfs, bins / "uci-rs", out / "uci-r83"])
    add("functional", "reload-config-r1", ["sudo", "-n", "python3", "tools/r1_candidate_check.py", "--rootfs", rootfs, "--candidate", bins / "reload_config_rs",
        "--cases", "tests/reference/config-change-dispatch/cases", "--output", out / "reload-config-r1", "--image-id", "ax3000t-stock-openwrt-25.12.5", "--recorded-at", now,
        *(["--receiver", a.reload_receiver.resolve()] if a.reload_receiver else [])])
    add("recovery", "r92-recovery", ["sudo", "-n", "python3", "tools/r92_recovery_probe.py", rootfs, bins, out / "r92-recovery", "--output-helper", examples / "output_lifecycle"])
    add("compat", "r92-compat", ["sudo", "-n", "python3", "tools/r92_compat_probe.py", rootfs, bins, out / "r92-compat"])
    add("compat", "r92-fw4", ["sudo", "-n", "python3", "tools/r92_fw4_probe.py", rootfs, fw4, out / "r92-fw4"])
    selected = [g for g in gates if g[0] in a.groups and (not a.gates or g[1] in a.gates)]
    if not selected or (a.gates and set(a.gates) != {g[1] for g in selected}):
        p.error("empty selection or unknown gate")
    if {g[1] for g in selected} & {"httpd-cgi-stress", "fw4-image"}:
        missing = [str(bins / name) for name in ("ns-exec", "owrt-benchmark")
                   if not (bins / name).is_file() or not os.access(bins / name, os.X_OK)]
        if missing:
            p.error("isolated workloads require runtime tools in the candidate bundle: "
                    + ", ".join(missing))
    try:
        example_identity = example_inputs({g[1] for g in selected}, examples)
    except ValueError as error:
        p.error(str(error))
    helper_identity = None
    if {g[1] for g in selected} & {"ubusd-r36", "ubusd-r36-user", "ubusd-r41"}:
        helper_manifest = a.helpers / "manifest.json"
        if not helper_manifest.exists():
            p.error("rebuild test helpers with r36_build_helpers.sh; their source manifest is required")
        helper_identity = json.loads(helper_manifest.read_text())
        for name in ("asuser", "busprobe"):
            identity = helper_identity["helpers"][name]
            if (identity["source_sha256"] != digest(source / "tools/testsrc" / (name + ".c"))
                    or identity["binary_sha256"] != digest(a.helpers / name)):
                p.error("stale or modified test helper: " + name)
    binaries = {p.name: digest(p) for p in sorted(bins.iterdir()) if p.is_file()}
    out.mkdir(parents=True, exist_ok=False)
    result = {"started": now, "groups": a.groups, "gate_selection": a.gates, "driver_sha256": digest(Path(__file__)), "binary_sha256": binaries, "example_sha256": example_identity, "helper_identity": helper_identity, "results": []}
    for group, name, command, extra_env, required in selected:
        if group != "unit":
            # The namespace init outlives each gate and kills all descendants
            # when it exits, including setsid daemons left by old harnesses.
            # Its private loopback also contains the r18/r19 DNS fixtures.
            # sudo deliberately resets the inherited environment. Pass this
            # selected, source-verified helper directory as an explicit value.
            command = ["sudo", "-n", "env", "HELPERS=" + str(a.helpers.resolve()),
                       str(a.baseline.resolve() / "ns-exec"), sys.executable,
                       str(Path(__file__).resolve()), "--namespace-command", *command]
        print(json.dumps({"started": name, "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}), flush=True)
        log = out / (name + ".log")
        with log.open("xb") as stream:
            try:
                process = subprocess.Popen(command, cwd=source, env=dict(env, **extra_env),
                    stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                rc = process.wait(timeout=7200)
            except subprocess.TimeoutExpired:
                # ns-exec's parent-death gate tears down its init/descendants.
                # Kill the owned session too so sudo cannot retain the parent.
                import signal
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                rc = 124
        result["results"].append({"group": group, "name": name, "exit": rc, "required": required,
            "command": command, "log_sha256": digest(log), "original_busy_control": name == "procd-busy-original"})
        (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"finished": name, "exit": rc, "required": required}), flush=True)
    result["passed"] = all(r["exit"] == 0 for r in result["results"] if r["required"])
    result["finished"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    (out / ("COMPLETE" if result["passed"] else "FAILED")).touch()
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
