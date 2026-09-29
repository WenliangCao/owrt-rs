#!/usr/bin/env python3
"""Measure one already verified whole-stack boot; never switch or reboot.

Raw files contain private responses and temporary session credentials. The
caller supplies a new private output directory and owns the whole-trial lease.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r84_device_probe import probe


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("stock", "rust"))
    p.add_argument("output", type=Path)
    p.add_argument("--host", default="openwrt")
    p.add_argument("--interface", default="en0")
    p.add_argument("--iterations", type=int, default=2000)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--idle", type=int, default=120)
    p.add_argument("--client-iterations", type=int, default=400)
    p.add_argument("--cycle-count", type=int, default=10)
    a = p.parse_args()
    if min(a.iterations, a.repeats, a.client_iterations, a.cycle_count) <= 0 or a.idle < 0:
        p.error("invalid workload size")
    out = a.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    ssh_args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", a.host]

    def ssh(command, timeout=30):
        return subprocess.check_output(ssh_args + [command], timeout=timeout)

    def save(name, value):
        (out / name).write_text(json.dumps(value, indent=2) + "\n")

    def emit(event, **fields):
        print(json.dumps({"event": event, **fields}), flush=True)

    started = time.monotonic()
    pre = probe(host=a.host, mode=a.mode, interface=a.interface)
    save("health-before.json", pre)
    if a.mode == "rust":
        ssh("test -s /root/r84/trial.pending && test -L /etc/rc.d/S98owrt-stack-trial")
    identity = ssh("sh /root/r84/stack-switch.sh verify " + a.mode)
    (out / "running-hashes.txt").write_bytes(identity)
    monitors = ",".join(line.split()[1] for line in identity.decode().splitlines() if line.split()[1] != "-")
    snapshot_cmd = "/root/r84/bins/owrt-benchmark snapshot " + monitors
    for name, command in {
        "config-before.sha256": "sha256sum /etc/config/*",
        "boot-kernel.txt": "dmesg", "boot-system.txt": "logread",
        "packages.txt": "apk info -v", "nft-ruleset-before.txt": "nft list ruleset",
        "storage-before.txt": "df -k /overlay /tmp; du -sk /root/r84 /overlay/upper",
        "execution-plane.txt": "for n in dnsmasq odhcpd hostapd wpa_supplicant; do for p in $(pidof $n 2>/dev/null); do printf '%s %s ' $n $p; sha256sum /proc/$p/exe; done; done",
    }.items():
        (out / name).write_bytes(ssh(command))
    css = "/luci-static/bootstrap/cascade.css"
    (out / "expected.css").write_bytes(ssh("cat /www" + css))
    sid = None
    try:
        sid = json.loads(ssh("ubus call session create '{\"timeout\":1800}'"))["ubus_rpc_session"]
        for scope, objects in [("ubus", [["uci", "get"]]), ("uci", [["network", "read"]])]:
            payload = {"ubus_rpc_session": sid, "scope": scope, "objects": objects}
            ssh("ubus call session grant " + shlex.quote(json.dumps(payload)))
        save("http-body.json", {"jsonrpc": "2.0", "id": 1, "method": "call",
             "params": [sid, "uci", "get", {"config": "network"}]})
        save("http-expect.json", {"id": 1, "result": [0, {"values": {"lan": {}}}]})
        client = Path(__file__).with_name("http_client.py")
        # Each mode uses the same LAN client and negotiated TLS 1.2. A separate
        # common-cipher lane exposes cipher-selection effects.
        lanes = [("http-static-c1", "http", False, 1, False, None),
                 ("https-static-c1", "https", False, 1, False, None),
                 ("https-static-c4", "https", False, 4, False, None),
                 ("https-rpc-c1", "https", True, 1, False, None),
                 ("https-rpc-c4", "https", True, 4, False, None),
                 ("https-fresh-c1", "https", False, 1, True, None),
                 ("https-common-c1", "https", False, 1, False, "ECDHE-ECDSA-AES256-GCM-SHA384")]
        for r in range(1, a.repeats + 1):
            for name, scheme, rpc, concurrency, fresh, cipher in lanes:
                n = min(100, a.client_iterations) if fresh else a.client_iterations
                warm = 4
                cmd = [sys.executable, str(client), f"{scheme}://192.168.1.1" + ("/ubus" if rpc else css),
                       "-n", str(n), "-c", str(concurrency), "--warmup", str(warm)]
                if scheme == "https": cmd += ["--insecure", "--tls12"]
                if rpc: cmd += ["--post", str(out / "http-body.json"), "--expect-json", str(out / "http-expect.json")]
                else: cmd += ["--expect-bytes", str(out / "expected.css")]
                if fresh: cmd += ["--fresh-connection", "--rate", "20"]
                if cipher: cmd += ["--cipher", cipher]
                before = json.loads(ssh(snapshot_cmd))
                result = subprocess.run(cmd, capture_output=True, timeout=180)
                after = json.loads(ssh(snapshot_cmd))
                label = f"lan-{r}-{name}"
                (out / (label + ".json")).write_bytes(result.stdout)
                (out / (label + ".stderr")).write_bytes(result.stderr)
                save(label + "-server.json", {"before": before, "after": after,
                     "successful_including_warmup": n + warm * concurrency,
                     "cpu_scope": "LAN client invocation including warmup and SSH snapshot boundaries"})
                result.check_returncode()
                d = json.loads(result.stdout)
                assert d["successful"] == n and d["errors"] == 0
            emit("lan_round_complete", round=r)
    finally:
        if sid:
            ssh("ubus -t 3 call session destroy " + shlex.quote(json.dumps({"ubus_rpc_session": sid})))

    def collect_remote(kind, script, arguments):
        remote = "/tmp/owrt-stack-" + out.name + "-" + kind
        ssh("test ! -e " + shlex.quote(remote))
        cmd = "sh /root/r84/tools/benchmark/" + script + " " + " ".join(
            shlex.quote(str(x)) for x in [a.mode, remote, *arguments])
        with (out / (kind + ".log")).open("wb") as log:
            result = subprocess.run(ssh_args + [cmd], stdout=log, stderr=subprocess.STDOUT, timeout=1000)
        archive = out / (kind + ".tar.gz")
        with archive.open("xb") as stream:
            subprocess.run(ssh_args + ["tar -czf - -C " + shlex.quote(remote) + " ."], stdout=stream, check=True, timeout=120)
        hashes = ssh("cd " + shlex.quote(remote) + " && find . -type f -exec sha256sum '{}' ';'")
        (out / (kind + ".sha256")).write_bytes(hashes)
        target = out / kind
        target.mkdir()
        with tarfile.open(archive) as tar:
            tar.extractall(target, filter="data")
        for line in hashes.decode().splitlines():
            digest, rel = line.split(None, 1)
            path = target / rel
            assert path.resolve().is_relative_to(target.resolve())
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        # Preserve remote evidence on any failed command or missing completion.
        result.check_returncode()
        assert (target / "COMPLETE").is_file()
        ssh("rm -rf -- " + shlex.quote(remote))
        emit("workload_complete", kind=kind)

    collect_remote("live", "live.sh", [a.iterations, a.repeats, a.idle])
    collect_remote("cycle", "stack_cycle.sh", [a.repeats, a.cycle_count])
    post = probe(host=a.host, mode=a.mode, interface=a.interface)
    save("health-after.json", post)
    assert pre["boot_id"] == post["boot_id"]
    config_after = ssh("sha256sum /etc/config/*")
    (out / "config-after.sha256").write_bytes(config_after)
    assert config_after == (out / "config-before.sha256").read_bytes()
    assert identity == ssh("sh /root/r84/stack-switch.sh verify " + a.mode)
    (out / "nft-ruleset-after.txt").write_bytes(ssh("nft list ruleset"))
    (out / "storage-after.txt").write_bytes(ssh("df -k /overlay /tmp"))
    save("settings.json", {**vars(a), "output": str(out), "elapsed_s": time.monotonic() - started})
    (out / "COMPLETE").touch()
    emit("window_complete", mode=a.mode, elapsed_s=time.monotonic() - started)


if __name__ == "__main__":
    main()
