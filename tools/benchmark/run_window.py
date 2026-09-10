#!/usr/bin/env python3
"""Collect one authorized, already verified router benchmark window privately.

This does not switch stacks or reboot. Run after r84_window.py has completed.
The TLS CPU brackets include the explicitly counted warm-up requests and SSH
sampling overhead; HTTP latency and throughput exclude warm-up. No raw output
from this collector belongs in Git.
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r84_device_probe import probe  # noqa: E402


def event(name, **fields):
    print(json.dumps({"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "event": name, **fields}, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("stock", "rust"))
    parser.add_argument("window", type=Path, help="private directory containing health.json")
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--resume-live", action="store_true",
                        help="reuse valid TLS results from this same boot after an interrupted live run")
    args = parser.parse_args()
    window = args.window.resolve()
    if not re.fullmatch(r"(?:rust|stock)-[1-9][0-9]*", window.name):
        raise ValueError("window name must be rust-N or stock-N")
    health = json.loads((window / "health.json").read_text())
    if health["status"] != "healthy" or health["mode"] != args.mode:
        raise RuntimeError("window was not verified in the requested mode")
    out = window / "measurements"
    out.mkdir(mode=0o700, exist_ok=args.resume_live)
    if (out / "COMPLETE").exists():
        raise RuntimeError("refusing to overwrite a completed window")
    if any((out / name).exists() for name in ("live", "live.tar.gz", "live.sha256")):
        raise RuntimeError("preserve the previous live attempt separately before resuming")
    remote = "/tmp/r84-" + window.name + "-live"
    ssh_args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4",
                "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", args.host]

    def ssh(command, timeout=30):
        return subprocess.run(ssh_args + [command], check=True, capture_output=True,
                              timeout=timeout).stdout

    def write_json(name, value):
        (out / name).write_text(json.dumps(value, indent=2) + "\n")

    pre = probe(host=args.host, mode=args.mode, interface=args.interface, recovery=True)
    if pre["boot_id"] != health["post"]["boot_id"]:
        raise RuntimeError("boot changed since health verification")
    write_json("resume-preflight.json" if args.resume_live else "preflight.json", pre)
    ssh("test ! -e " + shlex.quote(remote))
    identity = ssh("/bin/sh /root/r84/stack-switch.sh verify " + args.mode)
    if args.resume_live and (out / "running-hashes.txt").read_bytes() != identity:
        raise RuntimeError("running identities changed since the TLS measurements")
    (out / "running-hashes.txt").write_bytes(identity)
    monitors = ",".join(line.split()[1] for line in identity.decode().splitlines()
                        if line.split()[1] != "-")
    for filename, command in {
        "boot-kernel.txt": "dmesg",
        "boot-system.txt": "logread",
        "packages.txt": "apk info -v",
        "nft-ruleset.txt": "nft list ruleset",
        "boot-services.json": "ubus call service list",
        "storage.txt": "df -k /overlay /tmp; du -sk /root/r84 /overlay/upper",
    }.items():
        if not args.resume_live:
            (out / filename).write_bytes(ssh(command))
    css = out / "expected-css.bytes"
    expected_css = ssh("cat /www/luci-static/bootstrap/cascade.css")
    if args.resume_live and css.read_bytes() != expected_css:
        raise RuntimeError("TLS response fixture changed")
    css.write_bytes(expected_css)
    http_client = Path(__file__).with_name("http_client.py")

    def measure_tls(label, fresh, concurrency, cipher=None):
        snapshot_command = "/root/r84/bins/owrt-benchmark snapshot " + monitors
        before = json.loads(ssh(snapshot_command))
        command = [sys.executable, str(http_client),
                   "https://192.168.1.1/luci-static/bootstrap/cascade.css",
                   "--insecure", "--tls12", "--expect-bytes", str(css),
                   "-n", "1000", "-c", str(concurrency), "--warmup", "10"]
        if fresh:
            # The image's firewall applies a global 25 SYN/s limit even
            # to LAN input. Measure handshake cost below that limit;
            # unrestricted persistent connections measure throughput.
            command.extend(["--fresh-connection", "--rate", "20"])
        if cipher:
            command.extend(["--cipher", cipher])
        measured = subprocess.run(command, capture_output=True, timeout=600)
        after = json.loads(ssh(snapshot_command))
        (out / (label + ".json")).write_bytes(measured.stdout)
        (out / (label + ".stderr")).write_bytes(measured.stderr)
        write_json(label + "-server.json", {
            "before": before, "after": after,
            "cpu_scope": "client invocation including warm-up and SSH sampling overhead",
            "successful_including_warmup": 1000 + 10 * concurrency,
            "measured_requests": 1000, "warmup_per_connection": 10,
        })
        measured.check_returncode()
        result = json.loads(measured.stdout)
        if cipher and result["tls_ciphers"] != [cipher]:
            raise RuntimeError("controlled TLS cipher did not match")
        if result["successful"] != 1000 or result["errors"] != 0:
            raise RuntimeError("invalid TLS result")
        if [(p["pid"], p["start_ticks"]) for p in before["processes"]] != [
                (p["pid"], p["start_ticks"]) for p in after["processes"]]:
            raise RuntimeError("process changed during TLS load")
        event("tls_complete", workload=label, successful=1000,
              mean_ms=result["mean_ms"], ops_per_s=result["ops_per_s"])

    event("load_started", mode=args.mode, window=window.name)
    for fresh in (False, True):
        for concurrency in (1, 4):
            label = "tls-" + ("fresh" if fresh else "keepalive") + "-c" + str(concurrency)
            if args.resume_live:
                prior = json.loads((out / (label + ".json")).read_text())
                if (prior.get("successful") != 1000 or prior.get("errors") != 0
                        or prior.get("concurrency") != concurrency
                        or prior.get("request_rate_limit_per_s") != (20 if fresh else None)
                        or prior.get("tls_versions") != ["TLSv1.2"]):
                    raise RuntimeError("cannot reuse an invalid or differently configured TLS result")
                continue
            measure_tls(label, fresh, concurrency)
    # Keep the SSH channel alive while the independent router workload runs.
    # Its stdout goes to this collector's private log, with one line per round.
    command = ("/bin/sh /root/r84/tools/benchmark/live.sh " + args.mode + " "
               + shlex.quote(remote) + " 10000 5 120")
    live = subprocess.run(ssh_args + [command], timeout=7200)
    event("live_exited", returncode=live.returncode)
    archive = out / "live.tar.gz"
    with archive.open("xb") as target:
        subprocess.run(ssh_args + ["tar -czf - -C " + shlex.quote(remote) + " ."],
                       stdout=target, check=True, timeout=180)
    hashes = ssh("cd " + shlex.quote(remote)
                 + " && find . -type f -exec sha256sum '{}' ';'")
    (out / "live.sha256").write_bytes(hashes)
    local_live = out / "live"
    local_live.mkdir(mode=0o700)
    with tarfile.open(archive) as tar:
        tar.extractall(local_live, filter="data")
    for line in hashes.decode().splitlines():
        digest, name = line.split(None, 1)
        path = local_live / name
        if not path.resolve().is_relative_to(local_live.resolve()):
            raise RuntimeError("invalid checksum path")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError("download checksum mismatch")
    # Delete only this invocation's exact owned directory after durable copy.
    ssh("rm -rf -- " + shlex.quote(remote))
    live.check_returncode()
    if not (local_live / "COMPLETE").exists():
        raise RuntimeError("whole-system run did not complete")
    # A supplemental common-cipher comparison uses one boot per side. It
    # runs only after the primary workload and idle snapshots are complete,
    # preserving the identical four-window protocol for the main results.
    if window.name in ("stock-2", "rust-2"):
        for fresh in (False, True):
            for concurrency in (1, 4):
                label = "tls-common-" + ("fresh" if fresh else "keepalive") + "-c" + str(concurrency)
                measure_tls(label, fresh, concurrency, "ECDHE-ECDSA-AES256-GCM-SHA384")
    post = probe(host=args.host, mode=args.mode, interface=args.interface, recovery=True)
    if post["boot_id"] != pre["boot_id"]:
        raise RuntimeError("router rebooted during benchmark")
    write_json("postflight.json", post)
    if ssh("/bin/sh /root/r84/stack-switch.sh verify " + args.mode) != identity:
        raise RuntimeError("component identity changed during benchmark")
    (out / "COMPLETE").touch()
    event("window_measured", mode=args.mode, window=window.name)


if __name__ == "__main__":
    main()
