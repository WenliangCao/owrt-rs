#!/usr/bin/env python3
"""R85 component experiment: original image, frozen R84, and one candidate.

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
    parser.add_argument("--repeats", type=int, choices=(2, 4), default=4)
    parser.add_argument("--schedule", choices=("default", "two-side-balanced"), default="default",
                        help="use a fixed stock/candidate-only ABBA cycle; requires --sides stock candidate")
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--resume", action="store_true",
                        help="continue an interrupted collection with the same owned remote directory and identities")
    parser.add_argument("--matrix", action="store_true", help="expanded component workloads, including four clients")
    parser.add_argument("--memory-probe", type=Path,
                        help="separate diagnostic binary with http-resident mode; measure 64 held connections only")
    parser.add_argument("--rpc-client-probe", type=Path,
                        help="separate diagnostic client: compare repeated JSON decoding with complete wire-byte validation")
    parser.add_argument("--sides", nargs="+", choices=("stock", "r84", "candidate"),
                        default=["stock", "r84", "candidate"])
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", args.baseline_label) or args.baseline_label in ("stock", "candidate"):
        parser.error("invalid baseline label")
    if not args.baseline_bundle.startswith("/") or (args.cpus and not re.fullmatch(r"[0-9,-]+", args.cpus)):
        parser.error("baseline path must be absolute; CPU list must be numeric")
    if args.iterations <= 0:
        parser.error("iterations must be positive")
    if len(set(args.sides)) != len(args.sides) or not {"stock", "candidate"}.issubset(args.sides):
        parser.error("sides must include stock and candidate, without duplicates")
    if args.component != "httpd" and args.memory_probe:
        parser.error("held-connection memory currently requires HTTPD")
    if args.matrix and args.component not in ("httpd", "rpcd", "procd", "ubusd", "netifd"):
        parser.error("expanded matrices are defined for the five main daemons")
    if args.memory_probe and (args.matrix or "r84" in args.sides):
        parser.error("held-connection memory uses --sides stock candidate without --matrix")
    if args.rpc_client_probe and (args.component != "rpcd" or args.matrix or args.memory_probe or "r84" in args.sides):
        parser.error("RPC client diagnostics require rpcd, --sides stock candidate, and no other experiment mode")
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
    initial("subjects.json", hashes)
    if args.schedule == "two-side-balanced":
        if args.sides != ["stock", "candidate"]:
            parser.error("two-side-balanced requires exactly --sides stock candidate")
        order = TWO_SIDE_BALANCED * args.repeats
    else:
        order = tuple(args.baseline_label if side == "r84" else side
                      for side in ORDER[:args.repeats * 3] if side in args.sides)
    initial("order.json", list(order))
    initial("settings.json", {"component": component, "iterations": args.iterations, "matrix": args.matrix,
                           "held_connections": 64 if args.memory_probe else None,
                           "rpc_client_diagnostic": bool(args.rpc_client_probe),
                           "baseline_label": args.baseline_label, "baseline_bundle": args.baseline_bundle,
                           "schedule": args.schedule,
                           "cpu_affinity": args.cpus,
                           "management_access": args.access, "workload_transport": "namespace loopback"})
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
    if not args.resume:
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
    for name in ("ns-exec", "owrt-benchmark"):
        if ssh("sha256sum " + bundle + "/" + name).decode().split()[0] != manifest["tools"][name]["sha256"]:
            raise RuntimeError("benchmark identity mismatch: " + name)
    if ssh("sha256sum " + bundle + "/" + binary).decode().split()[0] != hashes["candidate"]:
        raise RuntimeError("candidate upload checksum mismatch")
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
        selected = bundle if side == "candidate" or args.memory_probe or args.rpc_client_probe else args.baseline_bundle + "/bins"
        impl = "c" if side == "stock" else "rs"
        (local / "host-before.json").write_bytes(ssh(snapshot))
        print(json.dumps({"event": "started", "side": side, "index": index,
                          "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}), flush=True)
        command = (f"/bin/sh {remote}/isolated.sh /rom {shlex.quote(selected)} {component} {impl} "
                   f"{run_out} {args.iterations}")
        if args.cpus:
            command = "taskset -c " + shlex.quote(args.cpus) + " " + command
        if args.matrix:
            command = "OWRT_" + component.upper() + "_MATRIX=1 " + command
        if args.memory_probe:
            command = "OWRT_HTTPD_MEMORY=1 " + command
        if args.rpc_client_probe:
            mode_order = "tree-first" if index % 2 else "wire-first"
            command = "OWRT_RPCD_CLIENT_DIAGNOSTIC=1 OWRT_RPCD_CLIENT_ORDER=" + mode_order + " " + command
        with (local / "run.log").open("xb") as log:
            run = subprocess.run(ssh_args + [command], stdout=log, stderr=subprocess.STDOUT, timeout=1800)
        (local / "host-after.json").write_bytes(ssh(snapshot))
        archive = local / "raw.tar.gz"
        with archive.open("xb") as target:
            subprocess.run(ssh_args + ["tar -czf - -C " + shlex.quote(run_out) + " ."],
                           stdout=target, check=True, timeout=180)
        checksums = ssh("cd " + shlex.quote(run_out) + " && find . -type f -exec sha256sum '{}' ';'")
        (local / "raw.sha256").write_bytes(checksums)
        raw = local / "raw"
        raw.mkdir(mode=0o700)
        with tarfile.open(archive) as tar:
            tar.extractall(raw, filter="data")
        for line in checksums.decode().splitlines():
            digest, name = line.split(None, 1)
            path = raw / name
            if not path.resolve().is_relative_to(raw) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError("download checksum mismatch")
        ssh("rm -rf -- " + shlex.quote(run_out))
        run.check_returncode()
        if not (raw / "COMPLETE").exists():
            raise RuntimeError("incomplete isolated run")
        if (raw / "binary-sha256.txt").read_text().split()[0] != hashes[side]:
            raise RuntimeError("subject identity mismatch")
        if (raw / "boot-id.txt").read_text().strip() != pre["boot_id"]:
            raise RuntimeError("host boot changed")
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
