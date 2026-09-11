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
import shlex
import subprocess
import sys
import tarfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r84_device_probe import probe  # noqa: E402

ORDER = ("stock", "r84", "candidate", "candidate", "r84", "stock",
         "r84", "stock", "candidate", "candidate", "stock", "r84")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--component", choices=("httpd", "rpcd", "procd", "ubusd", "netifd"), default="httpd")
    parser.add_argument("output", type=Path)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--access", choices=("wired", "wifi"), default="wired",
                        help="management path; wifi requires the user's explicit wireless-test authorization")
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--repeats", type=int, choices=(2, 4), default=4)
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--matrix", action="store_true", help="expanded HTTPD or rpcd workloads, including four clients")
    parser.add_argument("--memory-probe", type=Path,
                        help="separate diagnostic binary with http-resident mode; measure 64 held connections only")
    parser.add_argument("--rpc-client-probe", type=Path,
                        help="separate diagnostic client: compare repeated JSON decoding with complete wire-byte validation")
    parser.add_argument("--sides", nargs="+", choices=("stock", "r84", "candidate"),
                        default=["stock", "r84", "candidate"])
    args = parser.parse_args()
    if args.iterations <= 0:
        parser.error("iterations must be positive")
    if len(set(args.sides)) != len(args.sides) or not {"stock", "candidate"}.issubset(args.sides):
        parser.error("sides must include stock and candidate, without duplicates")
    if args.matrix and args.component not in ("httpd", "rpcd"):
        parser.error("expanded matrix currently supports HTTPD and rpcd")
    if args.component != "httpd" and args.memory_probe:
        parser.error("held-connection memory currently requires HTTPD")
    if args.memory_probe and (args.matrix or "r84" in args.sides):
        parser.error("held-connection memory uses --sides stock candidate without --matrix")
    if args.rpc_client_probe and (args.component != "rpcd" or args.matrix or args.memory_probe or "r84" in args.sides):
        parser.error("RPC client diagnostics require rpcd, --sides stock candidate, and no other experiment mode")
    component = args.component
    binary = component + "-rs"
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    out = args.output.resolve()
    (out / "STARTED").touch()
    ssh_args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4", "-o",
                "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", args.host]

    def ssh(command, timeout=30):
        return subprocess.run(ssh_args + [command], check=True, capture_output=True,
                              timeout=timeout).stdout

    def save(name, value):
        (out / name).write_text(json.dumps(value, indent=2) + "\n")

    # Wireless access is explicitly authorized for isolated component experiments.
    # This does not alter the recovery gate for stack switching or deployment.
    pre = probe(host=args.host, mode="rust", interface=args.interface, recovery=args.access == "wired")
    save("health-before.json", pre)
    identity = ssh("/bin/sh /root/r84/stack-switch.sh verify rust")
    (out / "host-running-hashes.txt").write_bytes(identity)
    config = ssh("sha256sum /etc/config/*")
    (out / "config-before.sha256").write_bytes(config)
    manifest = json.loads(ssh("cat /root/r84/manifest.json"))
    hashes = {"stock": manifest["components"][component]["original"]["sha256"],
              "r84": manifest["components"][component]["rust"]["sha256"],
              "candidate": hashlib.sha256(args.candidate.read_bytes()).hexdigest()}
    save("subjects.json", hashes)
    order = tuple(side for side in ORDER[:args.repeats * 3] if side in args.sides)
    save("order.json", order)
    save("settings.json", {"component": component, "iterations": args.iterations, "matrix": args.matrix,
                           "held_connections": 64 if args.memory_probe else None,
                           "rpc_client_diagnostic": bool(args.rpc_client_probe),
                           "management_access": args.access, "workload_transport": "namespace loopback"})
    remote = "/tmp/r85-" + component + "-" + uuid.uuid4().hex[:12]
    ssh("test ! -e " + remote + " && mkdir -p " + remote + "/bundle")
    bundle = remote + "/bundle"
    ssh("cp /root/r84/bins/ns-exec /root/r84/bins/owrt-benchmark " + bundle + "/")
    script = Path(__file__).with_name("isolated.sh")
    for local, target in ((args.candidate, bundle + "/" + binary), (script, remote + "/isolated.sh")):
        subprocess.run(["scp", "-O", str(local.resolve()), args.host + ":" + target], check=True)
    if args.memory_probe:
        digest = hashlib.sha256(args.memory_probe.read_bytes()).hexdigest()
        subprocess.run(["scp", "-O", str(args.memory_probe.resolve()), args.host + ":" + bundle + "/memory-probe"], check=True)
        if ssh("sha256sum " + bundle + "/memory-probe").decode().split()[0] != digest:
            raise RuntimeError("memory probe upload checksum mismatch")
        save("memory-probe.json", {"sha256": digest})
    if args.rpc_client_probe:
        digest = hashlib.sha256(args.rpc_client_probe.read_bytes()).hexdigest()
        subprocess.run(["scp", "-O", str(args.rpc_client_probe.resolve()), args.host + ":" + bundle + "/rpc-client-probe"], check=True)
        if ssh("sha256sum " + bundle + "/rpc-client-probe").decode().split()[0] != digest:
            raise RuntimeError("RPC client probe upload checksum mismatch")
        save("client-probe.json", {"sha256": digest, "diagnostic_only": True})
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
        local.mkdir(mode=0o700)
        run_out = remote + f"/run-{index:02d}"
        selected = bundle if side == "candidate" or args.memory_probe or args.rpc_client_probe else "/root/r84/bins"
        impl = "c" if side == "stock" else "rs"
        (local / "host-before.json").write_bytes(ssh(snapshot))
        print(json.dumps({"event": "started", "side": side, "index": index,
                          "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}), flush=True)
        command = (f"/bin/sh {remote}/isolated.sh /rom {selected} {component} {impl} "
                   f"{run_out} {args.iterations}")
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
    post = probe(host=args.host, mode="rust", interface=args.interface, recovery=args.access == "wired")
    save("health-after.json", post)
    after = ssh("sha256sum /etc/config/*")
    (out / "config-after.sha256").write_bytes(after)
    if pre["boot_id"] != post["boot_id"] or config != after:
        raise RuntimeError("host boot/configuration changed")
    if ssh("/bin/sh /root/r84/stack-switch.sh verify rust") != identity:
        raise RuntimeError("host process identities changed")
    ssh("rm -rf -- " + remote)
    (out / "COMPLETE").touch()
    print(component + " comparison complete", flush=True)


if __name__ == "__main__":
    main()
