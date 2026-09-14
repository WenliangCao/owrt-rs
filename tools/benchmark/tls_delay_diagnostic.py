#!/usr/bin/env python3
"""Build-host-only HTTP/TLS fresh-connection diagnostic in private namespaces.

Uses the exact image, one fixed P-256 certificate per run, common TLS 1.2
cipher, four clients and a real loopback netem delay. Traced runs are separate
and export no timing statistics. Nothing changes the host management network.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r92_compat_probe import Fixture  # noqa: E402
from r92_recovery_probe import digest, run, write  # noqa: E402
from http_client import benchmark  # noqa: E402
from analyze_diagnostics import syscalls  # noqa: E402

CIPHER = "ECDHE-ECDSA-AES256-GCM-SHA384"


def sample(pid):
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return {"cpu_ticks": int(stat[11]) + int(stat[12]), "start_ticks": int(stat[19])}


def inner(root, side, protocol, delay, count, trace):
    f = Fixture(root, "original" if side == "stock" else "candidate", "httpd")
    tracer = None
    stop = threading.Event()
    observer = None
    result = {}
    try:
        expected = bytes(16384)
        (root / "www/r92-delay.dat").write_bytes(expected)
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "1", "-subj", "/CN=r92.invalid", "-keyout", root / "tmp/key.pem",
            "-out", root / "tmp/cert.pem", capture_output=True)
        run("openssl", "x509", "-in", root / "tmp/cert.pem", "-outform", "DER",
            "-out", root / "tmp/cert.der", capture_output=True)
        run("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", root / "tmp/key.pem",
            "-outform", "DER", "-out", root / "tmp/key.der", capture_output=True)
        f.start_bus()
        f.start_subject("-f", "-h", "/www", "-p", "127.0.0.1:18080", "-s", "127.0.0.1:18443",
                        "-C", "/tmp/cert.der", "-K", "/tmp/key.der", "-N", "100", "-T", "5", "-k", "20")

        def listening():
            try:
                with socket.create_connection(("127.0.0.1", 18080), timeout=1):
                    return True
            except OSError:
                return False

        assert f.wait(listening) and f.checks["identity"]["passed"]
        # Fixture has established private mount/net/PID namespaces before
        # this qdisc is installed. It never reaches the build host's lo.
        if delay:
            run("tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", f"{delay}ms")
        qdisc = run("tc", "-s", "qdisc", "show", "dev", "lo", capture_output=True).stdout
        (f.output / "qdisc-before.txt").write_bytes(qdisc)
        assert (b"netem" in qdisc) == (delay > 0)
        if trace:
            tracer = subprocess.Popen([str(trace), "-f", "-c", "-w", "-S", "calls", "-o",
                                       str(f.output / "syscalls.txt"), "-p", str(f.subject.pid)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

            def attached():
                return f"TracerPid:\t{tracer.pid}\n" in Path(f"/proc/{f.subject.pid}/status").read_text()

            assert f.wait(attached), "strace did not attach"
        else:
            seen = set()

            def observe():
                while not stop.wait(.002):
                    seen.update(p.name for p in Path(f"/proc/{f.subject.pid}/task").iterdir())

            observer = threading.Thread(target=observe)
            observer.start()
        before = sample(f.subject.pid)
        data = benchmark(f"{protocol}://127.0.0.1:{18443 if protocol == 'https' else 18080}/r92-delay.dat",
                         count, 4, 2, None, expected, insecure=True, fresh=True,
                         tls12=protocol == "https", cipher=CIPHER if protocol == "https" else None)
        after = sample(f.subject.pid)
        stop.set()
        if observer:
            observer.join(timeout=2)
            assert not observer.is_alive()
        assert before["start_ticks"] == after["start_ticks"] and f.subject.poll() is None
        assert data["successful"] == count and data["errors"] == 0
        if protocol == "https":
            assert data["tls_versions"] == ["TLSv1.2"] and data["tls_ciphers"] == [CIPHER]
            assert data["measured_tls_handshakes"] == count and data["resumed_tls_handshakes"] == 0
        result = {"side": side, "protocol": protocol, "one_way_delay_ms": delay,
                  "successful": count, "warmup": 8, "clients": 4, "fresh_connection": True,
                  "subject_sha256": f.checks["identity"]["actual"], "diagnostic_only": True,
                  "tls_versions": data["tls_versions"], "tls_ciphers": data["tls_ciphers"],
                  "resumed_tls_handshakes": data["resumed_tls_handshakes"],
                  "kernel": os.uname().release, "python_ssl": ssl.OPENSSL_VERSION,
                  "qdisc_sha256": hashlib.sha256(qdisc).hexdigest(), "traced": bool(trace)}
        if tracer:
            tracer.send_signal(signal.SIGINT)
            _, errors = tracer.communicate(timeout=5)
            (f.output / "strace.log").write_bytes(errors)
            assert tracer.returncode in (0, -signal.SIGINT, 130)
            result["syscalls"] = syscalls(f.output / "syscalls.txt")
            result["strace_sha256"] = digest(trace)
        else:
            ticks = after["cpu_ticks"] - before["cpu_ticks"]
            assert ticks >= 0
            result.update({k: data[k] for k in ("mean_ms", "p50_ms", "p95_ms", "p99_ms", "wall_s")})
            result.update(cpu_ticks=ticks, ticks_per_second=os.sysconf("SC_CLK_TCK"),
                          subject_cpu_us_per_op=ticks / os.sysconf("SC_CLK_TCK") * 1e6 / (count + 8),
                          sampled_tasks_lower_bound=len(seen))
            write(f.output / "timing.json", json.dumps(data) + "\n")
        write(f.output / "result.json", json.dumps(result, indent=2) + "\n")
        (f.output / "COMPLETE").touch()
    finally:
        stop.set()
        if observer:
            observer.join(timeout=2)
        if tracer and tracer.poll() is None:
            tracer.kill()
            tracer.wait(timeout=5)
        f.close()


def main():
    if sys.argv[1:2] == ["--inner"]:
        _, root, side, protocol, delay, count, trace = sys.argv[1:]
        inner(Path(root), side, protocol, int(delay), int(count), Path(trace) if trace else None)
        return
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rootfs", type=Path)
    p.add_argument("baseline", type=Path)
    p.add_argument("candidate", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--strace", type=Path, required=True)
    p.add_argument("--delays", nargs="+", type=int, default=[0, 20, 40, 100])
    p.add_argument("--repeats", type=int, choices=(1, 2), default=2)
    p.add_argument("--count", type=int, default=80)
    p.add_argument("--no-trace", action="store_true")
    a = p.parse_args()
    assert os.geteuid() == 0 and sys.platform == "linux" and not Path("/etc/openwrt_release").exists()
    assert a.count >= 4 and all(0 <= delay <= 500 for delay in a.delays)
    a.output.mkdir(parents=True, exist_ok=False)
    identities = {"stock": digest(a.rootfs / "usr/sbin/uhttpd"),
                  "r89": digest(a.baseline), "candidate": digest(a.candidate)}
    write(a.output / "settings.json", json.dumps({
        "environment": "Linux AArch64 build host; private loopback netem", "subjects": identities,
        "driver_sha256": digest(Path(__file__)), "client_sha256": digest(Path(__file__).with_name("http_client.py")),
        "fixture_sha256": digest(Path(__file__).parents[1] / "r92_compat_probe.py"),
        "cpu_affinity": sorted(os.sched_getaffinity(0)), "cipher": CIPHER,
        "count": a.count, "repeats": a.repeats, "delays": a.delays,
    }, indent=2) + "\n")
    rows = []

    def one(side, protocol, delay, repeat, traced):
        name = f"{len(rows)+1:03d}-{'trace-' if traced else ''}{protocol}-{delay}-{side}-r{repeat}"
        print(json.dumps({"started": name}), flush=True)
        out = a.output / name
        out.mkdir()
        with tempfile.TemporaryDirectory(prefix="r92-tls-delay-") as temporary:
            root = Path(temporary) / "root"
            shutil.copytree(a.rootfs, root, symlinks=True)
            for directory in ("out", "run/ubus", "lock", "state"):
                (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
            shutil.copy2(a.baseline if side == "r89" else a.candidate, root / "tmp/httpd-rs")
            with (out / "driver.log").open("xb") as stream:
                process = subprocess.run(["timeout", "-k", "3", "240", "unshare", "--mount", "--net",
                    "--pid", "--fork", "--kill-child", sys.executable, str(Path(__file__).resolve()),
                    "--inner", str(root), side, protocol, str(delay), str(a.count),
                    str(a.strace.resolve()) if traced else ""], stdout=stream, stderr=stream)
            shutil.copytree(root / "tmp/out", out / "raw")
        process.check_returncode()
        assert (out / "raw/COMPLETE").exists()
        row = json.loads((out / "raw/result.json").read_text())
        assert row["subject_sha256"] == identities[side]
        row.update(name=name, repeat=repeat, result_sha256=digest(out / "raw/result.json"))
        rows.append(row)
        write(a.output / "results.json", json.dumps(rows, indent=2) + "\n")
        print(json.dumps({"completed": name}), flush=True)

    for repeat in range(1, a.repeats + 1):
        order = ("stock", "r89", "candidate") if repeat == 1 else ("candidate", "r89", "stock")
        for delay in (a.delays if repeat == 1 else a.delays[::-1]):
            for protocol in ("http", "https"):
                for side in order:
                    one(side, protocol, delay, repeat, False)
    if not a.no_trace:
        for delay in (min(a.delays), max(a.delays)):
            for protocol in ("http", "https"):
                for side in ("stock", "r89", "candidate"):
                    one(side, protocol, delay, 1, True)
    (a.output / "COMPLETE").touch()
    print(json.dumps({"complete": True, "runs": len(rows)}), flush=True)


if __name__ == "__main__":
    main()
