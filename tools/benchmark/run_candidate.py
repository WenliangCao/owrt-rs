#!/usr/bin/env python3
"""Component experiment: exact original image, frozen baseline, and candidate.

Physical use requires the already-authorized recovery gate. The production
stack stays active; each subject runs in the existing isolated harness. Every
download is checksummed before deleting its exact owned temporary directory.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import random
import shlex
import subprocess
import sys
import tarfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r84_device_probe import probe  # noqa: E402

ORDER = ("stock", "r84", "candidate", "candidate", "r84", "stock",
         "r84", "stock", "candidate", "candidate", "stock", "r84")
TWO_SIDE_BALANCED = ("stock", "candidate", "candidate", "stock")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--component", choices=("httpd", "rpcd", "procd", "ubusd", "netifd",
                                                "uci", "reload-config", "logd", "fw4"), default="httpd")
    parser.add_argument("output", type=Path)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--access", choices=("wired", "wifi"), default="wifi",
                        help="management path recorded with the measurements; both are authorized")
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--stack", choices=("rust", "stock"), default="rust",
                        help="production stack the device must be running (verified, never switched)")
    parser.add_argument("--baseline-bundle", default="/root/r84",
                        help="frozen comparison bundle on the router, including manifest.json")
    parser.add_argument("--baseline-label", default="r84", help="evidence label for that frozen bundle")
    parser.add_argument("--cpus", help="optional fixed taskset CPU list for every isolated subject/client")
    parser.add_argument("--repeats", type=int, default=4)
    parser.add_argument("--schedule", choices=("default", "two-side-balanced", "three-side-sequential", "calibration", "random-blocks"), default="default",
                        help="default interleaving, stock/candidate ABBA, or C then baseline then candidate; --repeats is windows per side for three-side-sequential")
    parser.add_argument("--seed", type=int, help="frozen seed for independent random three-side blocks")
    parser.add_argument("--guard", type=Path, help="router-side lifetime guard for each namespace (600 seconds)")
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--resume", action="store_true",
                        help="continue an interrupted collection with the same owned remote directory and identities")
    parser.add_argument("--matrix", action="store_true", help="expanded component workloads, including four clients")
    parser.add_argument("--netifd-scale", type=int, choices=(32, 64, 128), default=32)
    parser.add_argument("--netifd-fixture", type=Path, help="private wireless config, schema, stub and exact expected reply")
    parser.add_argument("--netifd-workloads", nargs="+", help="explicit subset of the netifd matrix")
    parser.add_argument("--netifd-warmup", type=int, default=20)
    parser.add_argument("--memory-probe", type=Path,
                        help="separate diagnostic binary with http-resident mode; measure 64 held connections only")
    parser.add_argument("--rpc-client-probe", type=Path,
                        help="separate diagnostic client: compare repeated JSON decoding with complete wire-byte validation")
    parser.add_argument("--sides", nargs="+", choices=("stock", "r84", "candidate"),
                        default=["stock", "r84", "candidate"])
    parser.add_argument("--bench", type=Path,
                        help="benchmark client uploaded into every selected temporary bundle")
    parser.add_argument("--extended", action="store_true",
                        help="ubusd: registration/event lanes and normalized daemon start")
    args = parser.parse_args()
    if not 1 <= args.repeats <= 64:
        parser.error("repeats must be in 1..64")
    if args.schedule in ("default", "two-side-balanced") and args.repeats not in (2, 4):
        parser.error("legacy schedules require 2 or 4 repeats")
    if args.schedule in ("calibration", "random-blocks") and not args.guard:
        parser.error("new experiments require a router-side lifetime guard")
    if (args.schedule == "random-blocks") != (args.seed is not None):
        parser.error("--seed is required only for random-blocks")
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", args.baseline_label) or args.baseline_label in ("stock", "candidate"):
        parser.error("invalid baseline label")
    if not args.baseline_bundle.startswith("/") or (args.cpus and not re.fullmatch(r"[0-9,-]+", args.cpus)):
        parser.error("baseline path must be absolute; CPU list must be numeric")
    if args.iterations <= 0:
        parser.error("iterations must be positive")
    if args.schedule == "calibration":
        if args.sides != ["candidate"]:
            parser.error("calibration requires exactly --sides candidate")
    elif len(set(args.sides)) != len(args.sides) or not {"stock", "candidate"}.issubset(args.sides):
        parser.error("sides must include stock and candidate, without duplicates")
    if args.component != "httpd" and args.memory_probe:
        parser.error("held-connection memory currently requires HTTPD")
    if args.matrix and args.component not in ("httpd", "rpcd", "procd", "ubusd", "netifd"):
        parser.error("expanded matrices are defined for the five main daemons")
    if args.netifd_scale != 32 and (args.component != "netifd" or not args.matrix):
        parser.error("--netifd-scale requires a netifd matrix")
    fixture_hashes = {}
    if args.netifd_workloads or args.netifd_warmup != 20:
        if args.component != "netifd" or not args.matrix:
            parser.error("netifd workload/warmup controls require its matrix")
    if not 0 <= args.netifd_warmup <= 100000:
        parser.error("netifd warmup must be in 0..100000")
    if args.netifd_workloads:
        lanes = ["interface_dump", "lan_status", "device_status", "wireless_status", "device_status_all",
                 f"interface_dump_{args.netifd_scale}", f"interface_named_{args.netifd_scale}"]
        allowed = {name + suffix for name in lanes for suffix in ("", "_c4")}
        if len(set(args.netifd_workloads)) != len(args.netifd_workloads) or not set(args.netifd_workloads) <= allowed:
            parser.error("invalid or duplicate netifd workload")
    if args.netifd_fixture:
        if args.component != "netifd" or not args.matrix or not args.bench:
            parser.error("--netifd-fixture requires a netifd matrix and --bench for private bundles")
        for name in ("wireless", "handler-schema.json", "mac80211.sh", "expected-wireless.json"):
            fixture_hashes[name] = hashlib.sha256((args.netifd_fixture / name).read_bytes()).hexdigest()
    if args.memory_probe and (args.matrix or "r84" in args.sides):
        parser.error("held-connection memory uses --sides stock candidate without --matrix")
    if args.rpc_client_probe and (args.component != "rpcd" or args.matrix or args.memory_probe or "r84" in args.sides):
        parser.error("RPC client diagnostics require rpcd, --sides stock candidate, and no other experiment mode")
    if args.bench and (args.memory_probe or args.rpc_client_probe):
        parser.error("--bench is not used with diagnostic probes")
    if args.bench and "r84" in args.sides and args.schedule not in ("three-side-sequential", "random-blocks"):
        parser.error("--bench with a frozen baseline requires three-side-sequential")
    if args.extended and args.component != "ubusd":
        parser.error("--extended is a ubusd mode")
    if args.schedule == "two-side-balanced" and args.sides != ["stock", "candidate"]:
        parser.error("two-side-balanced requires exactly --sides stock candidate")
    if args.schedule == "three-side-sequential" and args.sides != ["stock", "r84", "candidate"]:
        parser.error("three-side-sequential requires exactly --sides stock r84 candidate")
    if args.schedule == "random-blocks" and args.sides != ["stock", "r84", "candidate"]:
        parser.error("random-blocks requires exactly --sides stock r84 candidate")
    component = args.component
    binary = "reload_config_rs" if component == "reload-config" else component + "-rs"
    if args.resume and (not (args.output / "STARTED").exists() or (args.output / "COMPLETE").exists()):
        parser.error("resume requires an existing, incomplete collection")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=args.resume)
    out = args.output.resolve()
    (out / "STARTED").touch()
    ssh_args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4", "-o",
                "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", args.host]

    def ssh(command, timeout=30):
        return subprocess.run(ssh_args + [command], check=True, capture_output=True,
                              timeout=timeout).stdout

    def save(name, value):
        (out / name).write_text(json.dumps(value, indent=2) + "\n")

    def initial(name, value):
        if args.resume:
            assert json.loads((out / name).read_text()) == value, "resume settings changed: " + name
        else:
            save(name, value)

    current = probe(host=args.host, mode=args.stack, interface=args.interface)
    if args.resume:
        pre = json.loads((out / "health-before.json").read_text())
        assert current["boot_id"] == pre["boot_id"], "host rebooted before resume"
        save("resume-health-" + uuid.uuid4().hex[:12] + ".json", current)
    else:
        pre = current
        save("health-before.json", pre)
    identity = ssh("/bin/sh /root/r84/stack-switch.sh verify " + args.stack)
    config = ssh("sha256sum /etc/config/*")
    for name, value in (("host-running-hashes.txt", identity), ("config-before.sha256", config)):
        if args.resume:
            assert (out / name).read_bytes() == value, "host state changed before resume"
        else:
            (out / name).write_bytes(value)
    manifest = json.loads(ssh("cat /root/r84/manifest.json"))
    baseline = json.loads(ssh("cat " + shlex.quote(args.baseline_bundle + "/manifest.json")))
    hashes = {"stock": manifest["components"][component]["original"]["sha256"],
              args.baseline_label: baseline["components"][component]["rust"]["sha256"],
              "candidate": hashlib.sha256(args.candidate.read_bytes()).hexdigest()}
    for name in ("ns-exec", "owrt-benchmark"):
        if baseline["tools"][name]["sha256"] != manifest["tools"][name]["sha256"]:
            raise RuntimeError("frozen baseline and host benchmark tools differ")
    tool_hashes = {name: manifest["tools"][name]["sha256"] for name in ("ns-exec", "owrt-benchmark")}
    if args.bench:
        tool_hashes["owrt-benchmark"] = hashlib.sha256(args.bench.read_bytes()).hexdigest()
    initial("subjects.json", hashes)
    initial("host-manifest.json", manifest)
    initial("baseline-manifest.json", baseline)
    initial("tool-identities.json", {**tool_hashes, "driver": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    if args.schedule == "calibration":
        order = ("candidate",) * args.repeats
    elif args.schedule == "random-blocks":
        rng = random.Random(args.seed)
        order = tuple(side for _ in range(args.repeats)
                      for side in rng.sample(["stock", args.baseline_label, "candidate"], 3))
    elif args.schedule == "two-side-balanced":
        order = TWO_SIDE_BALANCED * args.repeats
    elif args.schedule == "three-side-sequential":
        order = tuple(args.baseline_label if side == "r84" else side
                      for side in (("stock",) * args.repeats + ("r84",) * args.repeats
                                   + ("candidate",) * args.repeats))
    else:
        order = tuple(args.baseline_label if side == "r84" else side
                      for side in ORDER[:args.repeats * 3] if side in args.sides)
    initial("order.json", list(order))
    settings = {"component": component, "iterations": args.iterations, "matrix": args.matrix,
                           "held_connections": 64 if args.memory_probe else None,
                           "rpc_client_diagnostic": bool(args.rpc_client_probe),
                           "baseline_label": args.baseline_label, "baseline_bundle": args.baseline_bundle,
                           "cpu_affinity": args.cpus,
                           "management_access": args.access, "workload_transport": "namespace loopback"}
    if args.schedule != "default":
        settings["schedule"] = args.schedule
    if args.seed is not None:
        settings["seed"] = args.seed
    if component == "netifd":
        settings["netifd_scale"] = args.netifd_scale
        settings["netifd_warmup"] = args.netifd_warmup
        if args.netifd_workloads:
            settings["netifd_workloads"] = args.netifd_workloads
        if fixture_hashes:
            settings["netifd_fixture_sha256"] = fixture_hashes
    if args.guard:
        settings["guard_sha256"] = hashlib.sha256(args.guard.read_bytes()).hexdigest()
        settings["namespace_timeout_seconds"] = 600
    if args.bench:
        settings["bench_sha256"] = tool_hashes["owrt-benchmark"]
    if args.extended:
        settings["extended"] = True
    initial("settings.json", settings)
    script = Path(__file__).with_name("isolated.sh")
    if args.resume:
        collector = json.loads((out / "collector.json").read_text())
        remote = collector["remote"]
        assert re.fullmatch("/tmp/r85-" + component + "-[a-f0-9]{12}", remote)
        assert collector["harness_sha256"] == hashlib.sha256(script.read_bytes()).hexdigest()
        assert ssh("sha256sum " + remote + "/isolated.sh").decode().split()[0] == collector["harness_sha256"]
    else:
        remote = "/tmp/r85-" + component + "-" + uuid.uuid4().hex[:12]
        ssh("test ! -e " + remote + " && mkdir -p " + remote + "/bundle")
        save("collector.json", {"remote": remote, "harness_sha256": hashlib.sha256(script.read_bytes()).hexdigest()})
    bundle = remote + "/bundle"
    if args.guard:
        if not args.resume:
            subprocess.run(["scp", "-O", str(args.guard.resolve()), args.host + ":" + remote + "/guard"], check=True)
        assert ssh("sha256sum " + remote + "/guard").decode().split()[0] == settings["guard_sha256"]
    # With --bench, use the same uploaded client in every selected bundle.
    # A three-side run gets a third temporary bundle containing the frozen
    # baseline ELF; the baseline directory itself remains untouched.
    stock_bundle = remote + "/stock-bundle" if args.bench else args.baseline_bundle + "/bins"
    baseline_bundle = remote + "/baseline-bundle" if args.bench and "r84" in args.sides else None
    if not args.resume:
        if args.bench:
            targets = [bundle, stock_bundle]
            if baseline_bundle:
                targets.append(baseline_bundle)
            ssh("mkdir -p " + " ".join(shlex.quote(target) for target in targets)
                + " && " + " && ".join("cp /root/r84/bins/ns-exec " + shlex.quote(target) + "/"
                                       for target in targets))
            for target in targets:
                subprocess.run(["scp", "-O", str(args.bench.resolve()), args.host + ":" + target + "/owrt-benchmark"], check=True)
            if baseline_bundle:
                ssh("cp " + shlex.quote(args.baseline_bundle + "/bins/" + binary)
                    + " " + shlex.quote(baseline_bundle + "/" + binary))
        else:
            ssh("cp /root/r84/bins/ns-exec /root/r84/bins/owrt-benchmark " + bundle + "/")
        for local, target in ((args.candidate, bundle + "/" + binary), (script, remote + "/isolated.sh")):
            subprocess.run(["scp", "-O", str(local.resolve()), args.host + ":" + target], check=True)
    if args.memory_probe:
        digest = hashlib.sha256(args.memory_probe.read_bytes()).hexdigest()
        if not args.resume:
            subprocess.run(["scp", "-O", str(args.memory_probe.resolve()), args.host + ":" + bundle + "/memory-probe"], check=True)
        if ssh("sha256sum " + bundle + "/memory-probe").decode().split()[0] != digest:
            raise RuntimeError("memory probe upload checksum mismatch")
        initial("memory-probe.json", {"sha256": digest})
    if args.rpc_client_probe:
        digest = hashlib.sha256(args.rpc_client_probe.read_bytes()).hexdigest()
        if not args.resume:
            subprocess.run(["scp", "-O", str(args.rpc_client_probe.resolve()), args.host + ":" + bundle + "/rpc-client-probe"], check=True)
        if ssh("sha256sum " + bundle + "/rpc-client-probe").decode().split()[0] != digest:
            raise RuntimeError("RPC client probe upload checksum mismatch")
        initial("client-probe.json", {"sha256": digest, "diagnostic_only": True})
    assert ssh("sha256sum " + remote + "/isolated.sh").decode().split()[0] == hashlib.sha256(script.read_bytes()).hexdigest()
    bundle_targets = (bundle, stock_bundle, baseline_bundle) if baseline_bundle else (bundle, stock_bundle)
    if fixture_hashes:
        for target in bundle_targets:
            directory = target + "/netifd-fixture"
            if not args.resume:
                ssh("mkdir " + shlex.quote(directory))
                for name in fixture_hashes:
                    subprocess.run(["scp", "-O", str((args.netifd_fixture / name).resolve()),
                                    args.host + ":" + directory + "/" + name], check=True)
                ssh("chmod 755 " + shlex.quote(directory + "/mac80211.sh"))
            for name, digest in fixture_hashes.items():
                assert ssh("sha256sum " + shlex.quote(directory + "/" + name)).decode().split()[0] == digest
    for name in ("ns-exec", "owrt-benchmark"):
        for where in bundle_targets:
            if ssh("sha256sum " + where + "/" + name).decode().split()[0] != tool_hashes[name]:
                raise RuntimeError("benchmark identity mismatch: " + name)
    if ssh("sha256sum " + bundle + "/" + binary).decode().split()[0] != hashes["candidate"]:
        raise RuntimeError("candidate upload checksum mismatch")
    if "r84" in args.sides and ssh("sha256sum " + (baseline_bundle or stock_bundle) + "/" + binary).decode().split()[0] != hashes[args.baseline_label]:
        raise RuntimeError("baseline upload checksum mismatch")
    monitors = ",".join(line.split()[1] for line in identity.decode().splitlines()
                        if line.split()[1] != "-")
    snapshot = "/root/r84/bins/owrt-benchmark snapshot " + monitors
    for index, side in enumerate(order, 1):
        local = out / f"{index:02d}-{side}"
        if args.resume and local.exists():
            raw = local / "raw"
            assert (local / "COMPLETE").exists() and (raw / "COMPLETE").exists(), (
                "incomplete sample requires explicit recovery or archival before resume", local.name)
            assert (raw / "binary-sha256.txt").read_text().split()[0] == hashes[side]
            assert (raw / "boot-id.txt").read_text().strip() == pre["boot_id"]
            assert (raw / "harness-sha256.txt").read_text().split()[0] == collector["harness_sha256"]
            for line in (local / "raw.sha256").read_text().splitlines():
                expected, name = line.split(None, 1)
                path = (raw / name).resolve()
                assert path.is_relative_to(raw.resolve()) and hashlib.sha256(path.read_bytes()).hexdigest() == expected
            print(json.dumps({"event": "preserved", "side": side, "index": index}), flush=True)
            continue
        local.mkdir(mode=0o700)
        run_out = remote + f"/run-{index:02d}"
        if side == "candidate" or args.memory_probe or args.rpc_client_probe:
            selected = bundle
        elif side == args.baseline_label and baseline_bundle:
            selected = baseline_bundle
        else:
            selected = stock_bundle
        impl = "c" if side == "stock" else "rs"
        (local / "host-before.json").write_bytes(ssh(snapshot))
        mounts = ssh("cat /proc/self/mountinfo")
        (local / "mounts-before.txt").write_bytes(mounts)
        for suffix, cmd in (("config-before.sha256", "sha256sum /etc/config/*"),
                            ("production-before.txt", "/bin/sh /root/r84/stack-switch.sh verify " + args.stack)):
            value = ssh(cmd)
            (local / suffix).write_bytes(value)
            assert value == (config if suffix.startswith("config") else identity), "production state changed"
        (local / "environment-before.txt").write_bytes(ssh("cat /proc/uptime /proc/loadavg; for f in /sys/class/thermal/thermal_zone*/temp; do test ! -f \"$f\" || cat \"$f\"; done"))
        print(json.dumps({"event": "started", "side": side, "index": index,
                          "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}), flush=True)
        command = (f"/bin/sh {remote}/isolated.sh /rom {shlex.quote(selected)} {component} {impl} "
                   f"{run_out} {args.iterations}")
        if args.cpus:
            command = "taskset -c " + shlex.quote(args.cpus) + " " + command
        if args.matrix:
            command = "OWRT_" + component.upper() + "_MATRIX=1 " + command
            if component == "netifd":
                command = ("OWRT_NETIFD_SCALE=" + str(args.netifd_scale)
                           + " OWRT_NETIFD_WARMUP=" + str(args.netifd_warmup) + " " + command)
                if args.netifd_workloads:
                    command = "OWRT_NETIFD_WORKLOADS=" + shlex.quote(" ".join(args.netifd_workloads)) + " " + command
        if args.guard:
            command = "OWRT_BENCH_GUARD=" + remote + "/guard " + command
        if args.extended:
            command = "OWRT_UBUSD_EXTENDED=1 OWRT_UBUSD_NORMALIZED=1 " + command
        if args.memory_probe:
            command = "OWRT_HTTPD_MEMORY=1 " + command
        if args.rpc_client_probe:
            mode_order = "tree-first" if index % 2 else "wire-first"
            command = "OWRT_RPCD_CLIENT_DIAGNOSTIC=1 OWRT_RPCD_CLIENT_ORDER=" + mode_order + " " + command
        failures = []
        run_exit = None
        try:
            with (local / "run.log").open("xb") as log:
                run_exit = subprocess.run(ssh_args + [command], stdout=log, stderr=subprocess.STDOUT, timeout=1800).returncode
            if run_exit != 0:
                failures.append(f"namespace exited {run_exit}")
        except Exception as exc:
            failures.append(f"launch: {type(exc).__name__}: {exc}")
        # Preserve a failed window before raising, including collection errors.
        # The router-side guard remains responsible for bounded termination.
        archive = local / "raw.tar.gz"
        raw = local / "raw"
        try:
            with archive.open("xb") as target:
                subprocess.run(ssh_args + ["tar -czf - -C " + shlex.quote(run_out) + " ."],
                               stdout=target, check=True, timeout=180)
            checksums = ssh("cd " + shlex.quote(run_out) + " && find . -type f -exec sha256sum '{}' ';'")
            (local / "raw.sha256").write_bytes(checksums)
            raw.mkdir(mode=0o700)
            with tarfile.open(archive) as tar:
                tar.extractall(raw, filter="data")
            for line in checksums.decode().splitlines():
                digest, name = line.split(None, 1)
                path = raw / name
                assert path.resolve().is_relative_to(raw) and hashlib.sha256(path.read_bytes()).hexdigest() == digest, "download checksum mismatch"
            assert (raw / "COMPLETE").exists(), "incomplete isolated run"
            assert (raw / "binary-sha256.txt").read_text().split()[0] == hashes[side], "subject identity mismatch"
            if (raw / "subject-sha256.txt").exists():
                assert (raw / "subject-sha256.txt").read_text().split()[0] == hashes[side], "live subject identity mismatch"
            assert (raw / "boot-id.txt").read_text().strip() == pre["boot_id"], "host boot changed"
            assert (raw / "harness-sha256.txt").read_text().split()[0] == hashlib.sha256(script.read_bytes()).hexdigest(), "harness identity mismatch"
            observed_tools = {Path(path).name: digest for digest, path in
                              (line.split() for line in (raw / "benchmark-sha256.txt").read_text().splitlines())}
            assert observed_tools == tool_hashes, "measured tool identities differ"
        except Exception as exc:
            failures.append(f"raw evidence: {type(exc).__name__}: {exc}")
        for filename, cmd, expected_value in (
                ("host-after.json", snapshot, None),
                ("environment-after.txt", "cat /proc/uptime /proc/loadavg; for f in /sys/class/thermal/thermal_zone*/temp; do test ! -f \"$f\" || cat \"$f\"; done", None),
                ("mounts-after.txt", "cat /proc/self/mountinfo", mounts),
                ("config-after.sha256", "sha256sum /etc/config/*", config),
                ("production-after.txt", "/bin/sh /root/r84/stack-switch.sh verify " + args.stack, identity)):
            try:
                value = ssh(cmd)
                (local / filename).write_bytes(value)
                assert expected_value is None or value == expected_value, filename + " changed"
            except Exception as exc:
                failures.append(f"{filename}: {type(exc).__name__}: {exc}")
        if failures:
            try:
                save(local.name + "/health-after-failure.json", probe(host=args.host, mode=args.stack, interface=args.interface))
            except Exception as exc:
                failures.append(f"health: {type(exc).__name__}: {exc}")
        save(local.name + "/result.json", {"command": command, "exit": run_exit, "failures": failures,
                                          "remote_evidence_retained": run_out if failures else None})
        if failures:
            raise RuntimeError("window failed; evidence preserved: " + "; ".join(failures))
        ssh("rm -rf -- " + shlex.quote(run_out))
        (local / "COMPLETE").touch()
        print(json.dumps({"event": "complete", "side": side, "index": index}), flush=True)
    post = probe(host=args.host, mode=args.stack, interface=args.interface)
    save("health-after.json", post)
    after = ssh("sha256sum /etc/config/*")
    (out / "config-after.sha256").write_bytes(after)
    if pre["boot_id"] != post["boot_id"] or config != after:
        raise RuntimeError("host boot/configuration changed")
    if ssh("/bin/sh /root/r84/stack-switch.sh verify " + args.stack) != identity:
        raise RuntimeError("host process identities changed")
    ssh("rm -rf -- " + remote)
    (out / "COMPLETE").touch()
    print(component + " comparison complete", flush=True)


if __name__ == "__main__":
    main()
