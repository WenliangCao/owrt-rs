#!/usr/bin/env python3
"""Diagnose HTTP bridge costs against one live, unchanged R92 ubus/rpcd stack.

Use only after other timed router experiments. Temporary HTTP servers listen
on loopback; the active HTTP server is also measured without restarting it.
The active server's CLI flags are reused with loopback ports for fresh servers.
Raw command lines, session tokens and responses must remain private.
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
from analyze import native, timing  # noqa: E402

ORDER = ("stock", "r89", "candidate", "live", "live", "candidate", "r89", "stock",
         "r89", "stock", "live", "candidate", "candidate", "live", "stock", "r89")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def loopback_flags(argv):
    args = list(argv[1:])
    counts = {"-p": 0, "-s": 0}
    for index, flag in enumerate(args):
        if flag in counts:
            counts[flag] += 1
            spec = args[index + 1]
            host = "[::1]" if "[" in spec else "127.0.0.1"
            args[index + 1] = host + (":18080" if flag == "-p" else ":18443")
    assert counts["-p"] in (1, 2) and counts["-s"] in (1, 2), "unexpected active listener flags"
    assert len([arg for arg in args if arg.endswith(":18080")]) == counts["-p"]
    return args


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    p.add_argument("--recovery-gate", type=Path, required=True)
    p.add_argument("--host", default="openwrt")
    p.add_argument("--interface", default="en0")
    a = p.parse_args()
    gate = json.loads(a.recovery_gate.read_text())
    assert gate["offline_backup_verified"] and gate["configuration_matches_backup"]
    assert gate["automatic_rollback_seconds"] == 900
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    ssh = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
           "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=6", a.host]

    def remote(command, timeout=45):
        return subprocess.check_output(ssh + [command], timeout=timeout)

    def save(name, value):
        (a.output / name).write_text(json.dumps(value, indent=2) + "\n")

    before = probe(host=a.host, mode="rust", interface=a.interface)
    save("health-before.json", before)
    identity = remote("/bin/sh /root/r84/stack-switch.sh verify rust")
    config = remote("sha256sum /etc/config/*")
    manifest_bytes = remote("cat /root/r84/manifest.json")
    assert hashlib.sha256(manifest_bytes).hexdigest() == gate["candidate_manifest_sha256"]
    manifest = json.loads(manifest_bytes)
    baseline = json.loads(remote("cat /root/r89-before-r90/manifest.json"))
    pids = {}
    for line in identity.decode().splitlines():
        component, pid, digest = line.split()
        assert digest == manifest["components"][component]["rust"]["sha256"]
        if pid != "-":
            pids[component] = int(pid)
    benchmark = "/root/r84/bins/owrt-benchmark"
    assert remote("sha256sum " + benchmark).decode().split()[0] == manifest["tools"]["owrt-benchmark"]["sha256"]
    argv = remote(f"cat /proc/{pids['httpd']}/cmdline").rstrip(b"\0").decode().split("\0")
    save("active-argv.json", argv)
    flags = loopback_flags(argv)
    expected = {"stock": manifest["components"]["httpd"]["original"]["sha256"],
        "r89": baseline["components"]["httpd"]["rust"]["sha256"],
        "candidate": manifest["components"]["httpd"]["rust"]["sha256"],
        "live": manifest["components"]["httpd"]["rust"]["sha256"]}
    binaries = {"stock": "/rom/usr/sbin/uhttpd", "r89": "/root/r89-before-r90/bins/httpd-rs",
                "candidate": "/root/r84/bins/httpd-rs"}
    scratch = "/tmp/r92-http-live-" + uuid.uuid4().hex
    remote("mkdir " + scratch)
    save("owned-temporary.json", {"directory": scratch})

    def call(method, args):
        response = remote(" ".join(map(shlex.quote, ("ubus", "-S", "call", "session", method, json.dumps(args)))))
        # grant/destroy may return only a successful ubus status, without DATA.
        # check_output has already rejected nonzero status; create still needs JSON.
        return {} if not response.strip() and method in ("grant", "destroy") else json.loads(response)

    sid = call("create", {"timeout": 3600})["ubus_rpc_session"]
    save("owned-session.json", {"ubus_rpc_session": sid})
    try:
        call("grant", {"ubus_rpc_session": sid, "scope": "ubus", "objects": [["uci", "configs"], ["uci", "get"]]})
        call("grant", {"ubus_rpc_session": sid, "scope": "uci", "objects": [["network", "read"]]})
        for method, args in (("configs", {}), ("get", {"config": "network"})):
            request = {"jsonrpc": "2.0", "id": 1, "method": "call", "params": [sid, "uci", method, args]}
            response = json.loads(remote(" ".join(map(shlex.quote, ("ubus", "-S", "call", "uci", method,
                                  json.dumps(dict(args, ubus_rpc_session=sid)))))))
            for name, value in ((method + "-request.json", request),
                                (method + "-expected.json", {"jsonrpc": "2.0", "id": 1, "result": [0, response]})):
                save(name, value)
                subprocess.run(["scp", "-O", "-q", str(a.output / name), a.host + ":" + scratch + "/" + name], check=True)
                assert remote("sha256sum " + scratch + "/" + name).decode().split()[0] == sha(a.output / name)
        save("settings.json", {"environment": "AX3000T; shared live R92 ubusd/rpcd; separate loopback HTTP servers",
            "diagnostic_only": True, "order": ORDER, "iterations": 10000, "warmup": 30,
            "subjects": expected, "benchmark_sha256": manifest["tools"]["owrt-benchmark"]["sha256"],
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "driver_sha256": sha(Path(__file__)), "listeners_match_active_families": True})
        rows = []
        for index, side in enumerate(ORDER, 1):
            name = f"{index:02d}-{side}"
            folder = a.output / name
            folder.mkdir(mode=0o700)
            work = scratch + "/run"
            # Owned child only: no kill command ever targets the live HTTPD.
            start = (f"subject={pids['httpd']}\nport=80\n" if side == "live" else
                " ".join(map(shlex.quote, [binaries[side], *flags])) + f" >{work}/daemon.log 2>&1 &\nsubject=$!\n"
                + "trap 'kill \"$subject\" 2>/dev/null || true; wait \"$subject\" 2>/dev/null || true' EXIT HUP INT TERM\nport=18080\nsleep 1\nkill -0 \"$subject\"\n")
            script = "set -eu\numask 077\nmkdir " + work + "\n" + start
            script += f'sha256sum "/proc/$subject/exe" >{work}/identity.txt\n'
            for method in ("configs", "get"):
                script += (f'/root/r84/bins/owrt-benchmark http "127.0.0.1:$port" POST /ubus '
                    f'{scratch}/{method}-request.json {scratch}/{method}-expected.json 10000 30 '
                    f'"$subject,{pids["rpcd"]},{pids["ubusd"]}" json >{work}/{method}.json\n')
            script += f'printf "%s\\n" "$subject" >{work}/subject.pid\ntouch {work}/COMPLETE\n'
            (folder / "scenario.sh").write_text(script)
            subprocess.run(["scp", "-O", "-q", str(folder / "scenario.sh"), a.host + ":" + scratch + "/scenario.sh"], check=True)
            assert remote("sha256sum " + scratch + "/scenario.sh").decode().split()[0] == sha(folder / "scenario.sh")
            print(json.dumps({"started": name, "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}), flush=True)
            with (folder / "driver.log").open("xb") as log:
                completed = subprocess.run(ssh + ["sh " + scratch + "/scenario.sh"], stdout=log, stderr=log, timeout=180)
            archive = folder / "raw.tar.gz"
            with archive.open("xb") as stream:
                subprocess.run(ssh + ["tar -czf - -C " + work + " ."], stdout=stream, check=True, timeout=60)
            raw = folder / "raw"
            raw.mkdir()
            with tarfile.open(archive) as tar:
                tar.extractall(raw, filter="data")
            hashes = remote("cd " + work + " && find . -type f -exec sha256sum '{}' ';'")
            (folder / "raw.sha256").write_bytes(hashes)
            verified = set()
            for line in hashes.decode().splitlines():
                digest, file = line.split(None, 1)
                path = (raw / file).resolve()
                assert path.is_relative_to(raw.resolve()) and sha(path) == digest
                verified.add(path)
            assert verified == {p.resolve() for p in raw.rglob("*") if p.is_file()}
            completed.check_returncode()
            assert (raw / "COMPLETE").exists()
            assert (raw / "identity.txt").read_text().split()[0] == expected[side]
            subject = int((raw / "subject.pid").read_text())
            for method in ("configs", "get"):
                data = native(raw / (method + ".json"))
                assert data["successful"] == 10000 and data["warmup"] == 30
                own = {key: next(p["cpu_s"] for p in data["daemon_cpu"] if p["pid"] == pid) * 1e6 / data["successful"]
                       for key, pid in (("httpd", subject), ("rpcd", pids["rpcd"]), ("ubusd", pids["ubusd"]))}
                rows.append({"run": name, "side": side, "method": "uci." + method, **timing(data),
                    "cpu_us_per_op": own, "archive_sha256": sha(archive)})
            save("results.json", rows)
            remote("rm -rf -- " + work)
            print(json.dumps({"completed": name}), flush=True)
        after = probe(host=a.host, mode="rust", interface=a.interface)
        assert after["boot_id"] == before["boot_id"]
        assert remote("sha256sum /etc/config/*") == config
        assert remote("/bin/sh /root/r84/stack-switch.sh verify rust") == identity
        save("health-after.json", after)
    finally:
        call("destroy", {"ubus_rpc_session": sid})
        save("session-cleanup.json", {"destroy_succeeded": True})
    remote("rm -rf -- " + scratch)
    (a.output / "COMPLETE").touch()


if __name__ == "__main__":
    main()
