#!/usr/bin/env python3
"""Run the nine isolated component comparisons on an authorized physical router.

Run after the whole-system windows, with a fixed healthy host stack. Raw
responses stay in the supplied private directory. Every router output is
downloaded and checksummed before its exact temporary directory is removed.
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r84_device_probe import probe  # noqa: E402

COMPONENTS = ("uci", "reload-config", "fw4", "logd", "httpd", "rpcd", "procd", "ubusd", "netifd")
ORDER = ("c", "rs", "rs", "c", "rs", "c", "c", "rs")


def event(name, **fields):
    print(json.dumps({"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "event": name, **fields}, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--host-mode", choices=("stock", "rust"), default="rust")
    parser.add_argument("--components", nargs="+", choices=COMPONENTS, default=list(COMPONENTS),
                        help="selected components, each with all eight runs; use a new output directory")
    args = parser.parse_args()
    if len(set(args.components)) != len(args.components):
        parser.error("duplicate component selection")
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    (out / "STARTED").touch(exist_ok=False)
    (out / "selection.json").write_text(json.dumps(args.components) + "\n")
    ssh_args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4",
                "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", args.host]

    def ssh(command, timeout=30):
        return subprocess.run(ssh_args + [command], check=True, capture_output=True,
                              timeout=timeout).stdout

    pre = probe(host=args.host, mode=args.host_mode, interface=args.interface, recovery=True)
    (out / "health-before.json").write_text(json.dumps(pre, indent=2) + "\n")
    identity = ssh("/bin/sh /root/r84/stack-switch.sh verify " + args.host_mode)
    (out / "host-running-hashes.txt").write_bytes(identity)
    monitors = ",".join(line.split()[1] for line in identity.decode().splitlines()
                        if line.split()[1] != "-")
    configs = ssh("sha256sum /etc/config/*")
    (out / "config-before.sha256").write_bytes(configs)
    manifest = json.loads(ssh("cat /root/r84/manifest.json"))
    for component in args.components:
        for index, impl in enumerate(ORDER, 1):
            local = out / component / f"{index:02d}-{impl}"
            local.mkdir(mode=0o700, parents=True)
            remote = f"/tmp/r84-component-{component}-{index:02d}-{impl}"
            ssh("test ! -e " + shlex.quote(remote))
            snapshot = "/root/r84/bins/owrt-benchmark snapshot " + monitors
            (local / "host-before.json").write_bytes(ssh(snapshot))
            event("component_started", component=component, implementation=impl, index=index)
            command = ("/bin/sh /root/r84/tools/benchmark/isolated.sh /rom /root/r84/bins "
                       + component + " " + impl + " " + shlex.quote(remote) + " 10000")
            with (local / "run.log").open("xb") as log:
                run = subprocess.run(ssh_args + [command], stdout=log,
                                     stderr=subprocess.STDOUT, timeout=1800)
            (local / "host-after.json").write_bytes(ssh(snapshot))
            archive = local / "raw.tar.gz"
            with archive.open("xb") as target:
                subprocess.run(ssh_args + ["tar -czf - -C " + shlex.quote(remote) + " ."],
                               stdout=target, check=True, timeout=180)
            hashes = ssh("cd " + shlex.quote(remote)
                         + " && find . -type f -exec sha256sum '{}' ';'")
            (local / "raw.sha256").write_bytes(hashes)
            raw = local / "raw"
            raw.mkdir(mode=0o700)
            with tarfile.open(archive) as tar:
                tar.extractall(raw, filter="data")
            for line in hashes.decode().splitlines():
                digest, name = line.split(None, 1)
                path = raw / name
                if not path.resolve().is_relative_to(raw.resolve()):
                    raise RuntimeError("invalid checksum path")
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise RuntimeError("download checksum mismatch")
            ssh("rm -rf -- " + shlex.quote(remote))
            run.check_returncode()
            if not (raw / "COMPLETE").exists():
                raise RuntimeError("component measurement did not complete")
            expected = manifest["components"][component]["rust" if impl == "rs" else "original"]["sha256"]
            if (raw / "binary-sha256.txt").read_text().split()[0] != expected:
                raise RuntimeError("measured component does not match the deployment manifest")
            if (raw / "boot-id.txt").read_text().strip() != pre["boot_id"]:
                raise RuntimeError("router rebooted during component measurement")
            (local / "COMPLETE").touch()
            event("component_complete", component=component, implementation=impl, index=index)
        post = probe(host=args.host, mode=args.host_mode, interface=args.interface, recovery=True)
        (out / component / "host-health.json").write_text(json.dumps(post, indent=2) + "\n")
        if post["boot_id"] != pre["boot_id"]:
            raise RuntimeError("host boot changed between component runs")
    if ssh("/bin/sh /root/r84/stack-switch.sh verify " + args.host_mode) != identity:
        raise RuntimeError("host process identities changed")
    after_configs = ssh("sha256sum /etc/config/*")
    (out / "config-after.sha256").write_bytes(after_configs)
    if after_configs != configs:
        raise RuntimeError("host configuration changed")
    (out / "COMPLETE").touch()
    event("all_components_complete" if tuple(args.components) == COMPONENTS else "selected_components_complete",
          components=args.components, runs=len(args.components) * len(ORDER))


if __name__ == "__main__":
    main()
