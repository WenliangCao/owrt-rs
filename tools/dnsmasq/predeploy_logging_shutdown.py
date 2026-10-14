#!/usr/bin/env python3
"""Exact-image shutdown logging comparison with delayed readers and peer loss.

Run through run_isolated.sh. Raw synthetic logs stay in a fresh private output.
The audit-overflow case repeats B6's 300 queries and partial drains. The tail
cases fill the kernel receive queue with fixture records, leaving dnsmasq's
25-record queue available for identified query and shutdown records.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

from audit_integration_resources import safe_dns
from m2_rootfs import STOCK_SHA256, bind_unix_socket, command, prepare, sha256


FILLER = b"predeploy-shutdown-fixture"
TAIL = "exiting on receipt of SIGTERM"


def drain(endpoint, packets, limit=None):
    received = 0
    while True:
        if limit is not None and received >= limit:
            return
        try:
            packets.append(endpoint.recv(65535).decode(errors="backslashreplace"))
            received += 1
        except BlockingIOError:
            return


def fill(endpoint_path):
    # /proc/self/fd avoids AF_UNIX's pathname limit without modifying the image.
    directory = os.open(endpoint_path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
            sender.setblocking(False)
            sender.connect(f"/proc/self/fd/{directory}/{endpoint_path.name}")
            count = 0
            while True:
                try:
                    sender.send(FILLER)
                    count += 1
                except BlockingIOError:
                    return count
    finally:
        os.close(directory)


def run(args, side, scenario):
    out = args.output / f"{scenario}-{side}"
    out.mkdir()
    root = prepare(args.image_root, None, out / "stage", args.rust)
    (root / "m2/hosts").write_text("192.0.2.42 initial.test\n")
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    endpoint.setblocking(False)
    endpoint_path = root / "dev/log"
    bind_unix_socket(endpoint, endpoint_path)
    argv = ["-k", "--conf-file=", "--no-resolv", "--no-hosts", "--no-ping",
            "--user=root", "--group=root", "--listen-address=127.0.0.1",
            "--port=15353", "--pid-file=/m2/pid",
            "--host-record=ready.test,192.0.2.41", "--addn-hosts=/m2/hosts",
            "--log-async=25", "--log-queries"]
    result = {"side": side, "scenario": scenario, "argv": argv,
              "binary_sha256": sha256(root / "usr/sbin" /
                                      ("dnsmasq" if side == "c" else "dnsmasq-rs")),
              "forced": False, "failures": []}
    packets = []
    process = None
    with (out / "stdout").open("wb") as stdout, (out / "stderr").open("wb") as stderr:
        try:
            process = subprocess.Popen(command(root, side, *argv), stdout=stdout, stderr=stderr)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"startup exit {process.returncode}")
                if safe_dns()["ok"]:
                    break
            else:
                raise TimeoutError("DNS startup")
            if scenario == "audit-overflow":
                answers = [safe_dns()["ok"] for _ in range(300)]
                result["queries"] = {"sent": 300, "answered": sum(answers)}
                # Bound each partial drain: draining until EAGAIN races the
                # service refilling the kernel queue and can empty it entirely.
                drain(endpoint, packets, 11)
                result["first_drain_records"] = len(packets)
                result["recovered"] = safe_dns()["ok"]
                time.sleep(.2)
                drain(endpoint, packets, 11)
            else:
                # Ensure startup and readiness logs drained before saturation.
                end = time.monotonic() + .2
                while time.monotonic() < end:
                    drain(endpoint, packets)
                    time.sleep(.005)
                result["fixture_records"] = fill(endpoint_path)
                if not result["fixture_records"]:
                    raise AssertionError("receive queue was not empty before fixture fill")
                result["query"] = safe_dns()["ok"]
            result["records_before_term"] = len(packets)
            term = time.monotonic()
            process.send_signal(signal.SIGTERM)
            # The old Rust cap was 100ms. Observe before allowing any progress.
            time.sleep(.35)
            result["held_after_term_seconds"] = time.monotonic() - term
            result["alive_before_release"] = process.poll() is None
            release = time.monotonic()
            if scenario == "peer-close":
                endpoint.close()
                endpoint = None
                endpoint_path.unlink()
                process.wait(3)
            else:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    drain(endpoint, packets)
                    if process.poll() is not None:
                        drain(endpoint, packets)
                        break
                    time.sleep(.002)
                else:
                    raise TimeoutError("shutdown did not finish after reader resumed")
            result["exit_after_release_seconds"] = time.monotonic() - release
            result["exit"] = process.returncode
            result["captured_records"] = len(packets)
            result["shutdown_records"] = sum(TAIL in packet for packet in packets)
            result["query_records_after_term"] = sum("query[A] ready.test" in packet
                                                     for packet in packets[result["records_before_term"]:])
            result["answer_records_after_term"] = sum("config ready.test is 192.0.2.41" in packet
                                                      for packet in packets[result["records_before_term"]:])
            result["tail_messages"] = [packet.split(": ", 1)[1]
                                       for packet in packets[result["records_before_term"]:]
                                       if packet != FILLER.decode() and ": " in packet]
            if not result["alive_before_release"]:
                result["failures"].append("exited while connected logger was still blocked")
            if result["exit"] != 0:
                result["failures"].append("shutdown failed after sink release/loss")
            if scenario == "audit-overflow":
                if result["queries"]["answered"] != 300 or not result["recovered"]:
                    result["failures"].append("DNS failed under logging backpressure")
            elif not result["query"]:
                result["failures"].append("DNS failed while log receive queue was full")
            if scenario == "tail-drain" and any(result[key] != 1 for key in (
                    "shutdown_records", "query_records_after_term", "answer_records_after_term")):
                result["failures"].append("queued query/answer/shutdown records were not preserved exactly once")
            if scenario == "tail-drain" and result["tail_messages"] != [
                    "query[A] ready.test from 127.0.0.1", "config ready.test is 192.0.2.41", TAIL]:
                result["failures"].append("queued tail record content/order changed")
        except Exception as error:
            result["failures"].append(repr(error))
        finally:
            if process is not None and process.poll() is None:
                result["forced"] = True
                process.kill()
                process.wait()
            if process is not None:
                result["exit"] = process.returncode
            if endpoint is not None:
                endpoint.close()
    (out / "syslog.json").write_text(json.dumps(packets, indent=2) + "\n")
    result["raw"] = {name: {"path": str(out / name), "sha256": sha256(out / name)}
                     for name in ("syslog.json", "stdout", "stderr")}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-root", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--rust-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sha256(args.rust) == args.rust_sha256, "candidate identity mismatch"
    assert not args.output.exists() and "private" in args.output.resolve().parts
    args.output.mkdir(parents=True)
    result = {"source_commit": args.source_commit, "rust_sha256": args.rust_sha256,
              "c_sha256": STOCK_SHA256, "driver_sha256": sha256(Path(__file__)),
              "image_root": str(args.image_root), "scenarios": []}
    for scenario in ("audit-overflow", "tail-drain", "peer-close"):
        for side in ("c", "rust"):
            row = run(args, side, scenario)
            result["scenarios"].append(row)
            print(json.dumps(row), flush=True)
    result["failures"] = [{"side": row["side"], "scenario": row["scenario"], "error": failure}
                          for row in result["scenarios"] for failure in row["failures"]]
    (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return int(bool(result["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
