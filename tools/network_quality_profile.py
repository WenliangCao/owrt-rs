#!/usr/bin/env python3
"""Profile the Mac's HTTPS Internet path using Apple's bounded networkQuality.

Results include Wi-Fi and the upstream network, not pure router forwarding.
Only reads router state. Raw endpoint identifiers stay under private/.
"""
import argparse
import concurrent.futures
import json
from pathlib import Path
import subprocess
import threading
import time

from network_profile import cpu_delta, probes, snapshot, write


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--interface", default="en0")
    parser.add_argument("--router", default="openwrt")
    parser.add_argument("--probe-host", required=True)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    private = Path(__file__).resolve().parent.parent / "private"
    assert args.output.resolve().is_relative_to(private) and 1 <= args.rounds <= 3
    args.output.mkdir(parents=True, exist_ok=False)
    write(args.output / "idle-probes.json", probes(args.probe_host, 10))
    summary = []
    for trial in range(1, args.rounds+1):
        prefix = args.output / f"{trial:02}"
        before = snapshot(args.router)
        prefix.with_suffix(".before.txt").write_text(before)
        stop = threading.Event()
        started = time.monotonic()
        print("START", trial, flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(probes, args.probe_host, 45, stop)
            try:
                result = subprocess.run(
                    ["networkQuality", "-M", "25", "-I", args.interface, "-c"],
                    text=True, capture_output=True, timeout=40)
            finally:
                stop.set()
            prefix.with_suffix(".json").write_text(result.stdout)
            prefix.with_suffix(".stderr").write_text(result.stderr)
            write(prefix.with_suffix(".probes.json"), future.result())
        after = snapshot(args.router)
        prefix.with_suffix(".after.txt").write_text(after)
        data = json.loads(result.stdout)
        if result.returncode or "error" in data:
            raise RuntimeError(f"networkQuality failed: {result.returncode}, {data.get('error')}")
        row = {"trial": trial, "duration_s": time.monotonic()-started,
               "download_mbps": data["dl_throughput"]/1e6,
               "upload_mbps": data["ul_throughput"]/1e6,
               "base_rtt_ms": data["base_rtt"], "responsiveness_rpm": data["responsiveness"],
               "router_cpu": cpu_delta(before, after)}
        summary.append(row)
        write(args.output / "summary.json", summary)
        print("DONE", json.dumps(row), flush=True)
        time.sleep(5)


if __name__ == "__main__":
    main()
