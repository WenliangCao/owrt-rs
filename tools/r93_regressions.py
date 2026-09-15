#!/usr/bin/env python3
"""Run R93 fault regressions on a Linux build host, never a physical router.

This complements r92_validate.py's complete historical suite. Musl runtime
binaries and the GNU accept-injection binary have separate recorded identities.
Keep the output directory private: individual fixtures may copy image files.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("bins", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--ns-exec", type=Path, required=True)
    parser.add_argument("--gnu-ubusd", type=Path, required=True,
                        help="same-source dynamic build for LD_PRELOAD accept injection")
    args = parser.parse_args()
    if sys.platform != "linux" or Path("/etc/openwrt_release").exists():
        parser.error("run on a Linux build host, not OpenWrt")
    source = Path(__file__).resolve().parents[1]
    rootfs, bins, out, launcher, gnu = [p.resolve() for p in
        (args.rootfs, args.bins, args.output, args.ns_exec, args.gnu_ubusd)]
    for path in [rootfs / "sbin/ubusd", launcher, gnu,
                 *[bins / (c + "-rs") for c in ("httpd", "logd", "rpcd", "ubusd", "netifd", "procd")]]:
        if not path.is_file():
            parser.error("missing input: " + str(path))
    out.mkdir(parents=True, exist_ok=False)
    gates = [
        ("procd-watch", "r93_procd_watch_probe.py",
         [rootfs, bins / "procd-rs", out / "procd-watch"]),
        ("httpd-shared-cap", "r93_httpd_cap_probe.py",
         ["--binary", bins / "httpd-rs", "--rootfs", rootfs,
          "--output", out / "httpd-shared-cap.json"]),
        ("ubusd-accept", "r93_ubusd_accept_probe.py", [gnu, out / "ubusd-accept"]),
        ("logd-streams", "test_logd_stream_recovery.py",
         ["--ubusd", bins / "ubusd-rs", "--logd", bins / "logd-rs",
          "--output", out / "logd-streams.json"]),
        *[("rpcd-" + fault, "r93_rpcd_reconnect.py",
           [rootfs, bins / "rpcd-rs", out / ("rpcd-" + fault), "--fault", fault])
          for fault in ("disconnect", "half_header")],
        *[("netifd-" + fault, "r93_netifd_reconnect.py",
           [rootfs, bins / "netifd-rs", out / ("netifd-" + fault), "--fault", fault])
          for fault in ("network.device", "network.interface.loopback")],
    ]
    now = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = {
        "started": now(), "scope": "R93 new fault regressions; historical suite is separate",
        "binary_sha256": {p.name: digest(p) for p in sorted(bins.iterdir()) if p.is_file()},
        "gnu_ubusd_sha256": digest(gnu), "ns_exec_sha256": digest(launcher),
        "stock_ubusd_sha256": digest(rootfs / "sbin/ubusd"),
        "source_sha256": {str(p.relative_to(source)): digest(p) for p in sorted({
            Path(__file__).resolve(), source / "tools/r92_validate.py",
            source / "tools/r92_recovery_probe.py", source / "tools/r92_compat_probe.py",
            source / "tools/r14_httpd_check.py", *[source / "tools" / g[1] for g in gates]})},
        "results": [],
    }
    for name, script, arguments in gates:
        command = ["sudo", "-n", str(launcher), sys.executable,
                   str(source / "tools/r92_validate.py"), "--namespace-command",
                   sys.executable, str(source / "tools" / script), *map(str, arguments)]
        print(json.dumps({"started": name, "at": now()}), flush=True)
        log = out / (name + ".log")
        with log.open("xb") as stream:
            process = subprocess.Popen(command, cwd=source, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=300)
            except subprocess.TimeoutExpired:
                code = 124
            finally:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
        result["results"].append({"name": name, "exit": code, "command": command,
                                  "log_sha256": digest(log)})
        (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"finished": name, "exit": code}), flush=True)
    result.update(finished=now(), passed=all(r["exit"] == 0 for r in result["results"]))
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    (out / ("COMPLETE" if result["passed"] else "FAILED")).touch()
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
