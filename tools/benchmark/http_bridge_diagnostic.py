#!/usr/bin/env python3
"""Compare configs/get-network on formal HTTP binaries and two dependency stacks.

Linux build host only, with private mount/net/PID namespaces. Optional network
input and raw responses stay private. This is a diagnostic, not a router matrix.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r92_compat_probe import Fixture  # noqa: E402
from r92_recovery_probe import digest, run, write  # noqa: E402
from analyze import native, timing  # noqa: E402
from analyze_diagnostics import syscalls  # noqa: E402


def inner(root, side, dependencies, count, traced):
    f = Fixture(root, "original" if side == "stock" else "candidate", "httpd")
    tracer = None
    try:
        bus_binary = "/sbin/ubusd" if dependencies == "original" else "/tmp/ubusd-rs"
        rpc_binary = "/sbin/rpcd" if dependencies == "original" else "/tmp/rpcd-rs"
        bus = f.start(bus_binary)
        assert f.wait(f.sock.exists)
        rpc = f.start(rpc_binary)
        assert f.wait(lambda: f.ready("session")) and f.wait(lambda: f.ready("uci"))
        f.start_subject("-f", "-h", "/www", "-u", "/ubus", "-t", "60", "-T", "30", "-k", "20",
                        "-A", "1", "-n", "3", "-N", "100", "-p", "127.0.0.1:18080")

        def listening():
            try:
                with socket.create_connection(("127.0.0.1", 18080), timeout=1):
                    return True
            except OSError:
                return False

        assert f.wait(listening) and f.checks["identity"]["passed"]
        if traced:
            tracer = subprocess.Popen([str(root / "tmp/strace"), "-f", "-c", "-w", "-S", "calls", "-o",
                str(f.output / "syscalls.txt"), "-p", str(f.subject.pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            assert f.wait(lambda: f"TracerPid:\t{tracer.pid}\n" in Path(f"/proc/{f.subject.pid}/status").read_text())
        sid = f.call("session", "create", {"timeout": 3600})["ubus_rpc_session"]
        f.call("session", "grant", {"ubus_rpc_session": sid, "scope": "ubus", "objects": [["uci", "configs"], ["uci", "get"]]})
        f.call("session", "grant", {"ubus_rpc_session": sid, "scope": "uci", "objects": [["network", "read"]]})
        monitors = ",".join(str(p.pid) for p in (f.subject, rpc, bus))
        rows = []
        for method, args in (("configs", {}), ("get", {"config": "network"})):
            response = f.call("uci", method, dict(args, ubus_rpc_session=sid))
            request = {"jsonrpc": "2.0", "id": 1, "method": "call", "params": [sid, "uci", method, args]}
            expected = {"jsonrpc": "2.0", "id": 1, "result": [0, response]}
            write(root / "tmp/request.json", json.dumps(request))
            write(root / "tmp/expected.json", json.dumps(expected))
            target = f.output / (method + ".json")
            with target.open("xb") as stream:
                run("chroot", root, "/tmp/owrt-benchmark", "http", "127.0.0.1:18080", "POST", "/ubus",
                    "/tmp/request.json", "/tmp/expected.json", str(count), "30", monitors, "json",
                    stdout=stream, timeout=120)
            data = native(target)
            assert data["successful"] == count and data["warmup"] == 30
            row = {"method": "uci." + method, "successful": count, "response_json_bytes": len(json.dumps(expected, separators=(",", ":")).encode())}
            if not traced:
                row.update(timing(data))
                row["cpu_us_per_op"] = {name: next(x["cpu_s"] for x in data["daemon_cpu"] if x["pid"] == process.pid) * 1e6 / count
                                        for name, process in (("httpd", f.subject), ("rpcd", rpc), ("ubusd", bus))}
            rows.append(row)
        result = {"side": side, "dependencies": dependencies, "traced": traced, "diagnostic_only": True,
            "subject_sha256": digest(Path(f"/proc/{f.subject.pid}/exe")),
            "dependency_sha256": {"ubusd": digest(Path(f"/proc/{bus.pid}/exe")), "rpcd": digest(Path(f"/proc/{rpc.pid}/exe"))},
            "benchmark_sha256": digest(root / "tmp/owrt-benchmark"), "rows": rows}
        if tracer:
            tracer.send_signal(signal.SIGINT)
            _, error = tracer.communicate(timeout=5)
            assert tracer.returncode in (0, -signal.SIGINT, 130)
            (f.output / "strace.log").write_bytes(error)
            result["syscalls"] = syscalls(f.output / "syscalls.txt")
        write(f.output / "result.json", json.dumps(result, indent=2) + "\n")
        (f.output / "COMPLETE").touch()
    finally:
        if tracer and tracer.poll() is None:
            tracer.kill()
            tracer.wait(timeout=5)
        f.close()


def main():
    if sys.argv[1:2] == ["--inner"]:
        root, side, dependencies, count, traced = sys.argv[2:]
        inner(Path(root), side, dependencies, int(count), traced == "1")
        return
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rootfs", type=Path)
    p.add_argument("baseline", type=Path)
    p.add_argument("candidate", type=Path, help="directory with formal httpd/rpcd/ubusd binaries")
    p.add_argument("benchmark", type=Path)
    p.add_argument("network", type=Path, help="private fixed UCI network file")
    p.add_argument("output", type=Path)
    p.add_argument("--strace", type=Path, required=True)
    a = p.parse_args()
    assert os.geteuid() == 0 and sys.platform == "linux" and not Path("/etc/openwrt_release").exists()
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    write(a.output / "settings.json", json.dumps({"environment": "Linux AArch64 build host, private namespaces",
        "driver_sha256": digest(Path(__file__)), "benchmark_sha256": digest(a.benchmark),
        "network_file_bytes": a.network.stat().st_size, "strace_sha256": digest(a.strace)}, indent=2) + "\n")
    experiments = [(side, dependencies, repeat, False) for repeat in (1, 2)
        for dependencies in (("original", "candidate") if repeat == 1 else ("candidate", "original"))
        for side in (("stock", "r89", "candidate") if repeat == 1 else ("candidate", "r89", "stock"))]
    experiments += [(side, "candidate", 1, True) for side in ("stock", "r89", "candidate")]
    for side, dependencies, repeat, traced in experiments:
        name = f"{len(rows) + 1:02d}-{side}-{dependencies}-r{repeat}" + ("-trace" if traced else "")
        destination = a.output / name
        destination.mkdir()
        print(json.dumps({"started": name}), flush=True)
        with tempfile.TemporaryDirectory(prefix="r92-http-bridge-") as temporary:
            root = Path(temporary) / "root"
            shutil.copytree(a.rootfs, root, symlinks=True)
            for directory in ("out", "run/ubus", "lock", "state"):
                (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
            files = {"httpd-rs": a.baseline if side == "r89" else a.candidate / "httpd-rs",
                     "rpcd-rs": a.candidate / "rpcd-rs", "ubusd-rs": a.candidate / "ubusd-rs",
                     "owrt-benchmark": a.benchmark, "strace": a.strace}
            for name_in_root, source in files.items():
                shutil.copy2(source, root / "tmp" / name_in_root)
            shutil.copy2(a.network, root / "etc/config/network")
            with (destination / "driver.log").open("xb") as log:
                proc = subprocess.run(["timeout", "-k", "3", "180", "unshare", "--mount", "--net", "--pid",
                    "--fork", "--kill-child", sys.executable, str(Path(__file__).resolve()), "--inner", str(root),
                    side, dependencies, "400" if traced else "10000", "1" if traced else "0"], stdout=log, stderr=log)
            shutil.copytree(root / "tmp/out", destination / "raw")
        proc.check_returncode()
        assert (destination / "raw/COMPLETE").exists()
        result = json.loads((destination / "raw/result.json").read_text())
        rows.append({"name": name, "repeat": repeat, "result_sha256": digest(destination / "raw/result.json"), **result})
        write(a.output / "results.json", json.dumps(rows, indent=2) + "\n")
        print(json.dumps({"completed": name}), flush=True)
    (a.output / "COMPLETE").touch()


if __name__ == "__main__":
    main()
