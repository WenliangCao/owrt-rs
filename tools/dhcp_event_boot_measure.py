#!/usr/bin/env python3
"""One explicitly authorized reboot; all subsequent router access is read-only.

Run on the Mac LAN client. Private output contains device/client identifiers.
The durable request marker prevents accidentally submitting a second reboot.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from native_client_dhcp import capture as capture_dhcp
from r84_device_probe import probe


SSH = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=2",
       "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=3",
       "-o", "ServerAliveCountMax=1"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--interface", default="en0")
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    out = args.directory.resolve()
    gate = json.loads((out / "reboot-gate.json").read_text())
    assert gate["passed"] is True and gate["authorized_reboots"] == 1
    assert hashlib.sha256((out / "config-before-reboot.tar.gz").read_bytes()).hexdigest() == gate["config_sha256"]
    assert json.loads((out / "client-preflight.json").read_text())["boot_id"] == gate["boot_id"]
    assert gate["client_direct_https_passed"] is True
    streams = []
    stopped = threading.Event()
    events = (out / "events.jsonl").open("x", buffering=1)

    def event(name, **fields):
        row = dict(event=name, unix=time.time(), monotonic=time.monotonic(), **fields)
        events.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)
        return row

    def remote(command, timeout=8):
        return subprocess.run(SSH + [args.host, command], capture_output=True, timeout=timeout)

    def client_loop():
        with (out / "client-https.jsonl").open("x", buffering=1) as log:
            while not stopped.is_set():
                start = time.monotonic()
                try:
                    reply = subprocess.run([
                        "curl", "--interface", args.interface, "--noproxy", "*", "-4", "-sS",
                        "--connect-timeout", "1", "--max-time", "2",
                        "-w", "\n%{http_code} %{local_ip} %{remote_ip}", "https://example.com/"],
                        capture_output=True, timeout=3)
                    body, _, trailer = reply.stdout.rpartition(b"\n")
                    fields = trailer.decode(errors="replace").split()
                    passed = reply.returncode == 0 and fields[:1] == ["200"] and b"Example Domain" in body
                    row = dict(start_monotonic=start, end_monotonic=time.monotonic(), unix=time.time(),
                               passed=passed, returncode=reply.returncode, transfer=fields,
                               body_sha256=hashlib.sha256(body).hexdigest())
                except subprocess.TimeoutExpired:
                    row = dict(start_monotonic=start, end_monotonic=time.monotonic(), unix=time.time(),
                               passed=False, error="client curl timed out")
                log.write(json.dumps(row) + "\n")
                stopped.wait(max(0, 1 - (time.monotonic() - start)))

    def stream(name, command):
        stdout = (out / (name + ".txt")).open("xb")
        stderr = (out / (name + ".stderr")).open("xb")
        process = subprocess.Popen(SSH + [args.host, command], stdout=stdout, stderr=stderr)
        streams.append((process, stdout, stderr))
        event("stream_started", name=name)

    def health(label):
        try:
            result = probe(args.host, "native", args.interface, native_manifest=args.manifest)
            result["passed"] = True
        except Exception as error:
            result = dict(passed=False, error=str(error))
        (out / (label + ".json")).write_text(json.dumps(result, indent=2) + "\n")
        event(label, passed=result["passed"])
        return result

    thread = threading.Thread(target=client_loop)
    try:
        current = remote("cat /proc/sys/kernel/random/boot_id")
        assert current.returncode == 0 and current.stdout.decode().strip() == gate["boot_id"]
        thread.start()
        event("client_observer_started")
        request = dict(unix=time.time(), monotonic=time.monotonic(), previous_boot_id=gate["boot_id"])
        # Persist BEFORE submission. An interrupted run may be resumed manually,
        # but this program must never retry the reboot command.
        with (out / "reboot-request.json").open("x") as marker:
            json.dump(request, marker)
            marker.flush()
            os.fsync(marker.fileno())
        event("reboot_submitted_once")
        try:
            response = remote("reboot", timeout=8)
            event("reboot_command_return", returncode=response.returncode)
        except subprocess.TimeoutExpired:
            event("reboot_command_timeout_no_retry")
        deadline = request["monotonic"] + 180
        while time.monotonic() < deadline:
            start = time.monotonic()
            try:
                response = remote("cat /proc/sys/kernel/random/boot_id; cat /proc/uptime", timeout=4)
                end = time.monotonic()
                fields = response.stdout.decode().splitlines()
                if response.returncode == 0 and len(fields) == 2 and fields[0] != gate["boot_id"]:
                    uptime = float(fields[1].split()[0])
                    boot = dict(boot_id=fields[0], uptime=uptime, start_monotonic=start,
                                end_monotonic=end, unix=time.time(),
                                boot_zero_monotonic_lower=start - uptime - .01,
                                boot_zero_monotonic_upper=end - uptime + .01)
                    (out / "boot-anchor.json").write_text(json.dumps(boot, indent=2) + "\n")
                    break
            except subprocess.TimeoutExpired:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("new boot not reachable in 180 seconds; reboot is not retried")
        event("new_boot_reachable", uptime=uptime)
        stream("logread-ms", "logread -t -f -l 100000")
        stream("ubus-monitor", "ubus monitor")
        health("health-first")
        try:
            result = capture_dhcp(args.interface, out / "client-dhcp", request["unix"])
            event("fresh_client_dhcp", passed=result["passed"])
        except Exception as error:
            event("fresh_client_dhcp", passed=False, error=str(error))
        # End passive streams at 300 seconds of the measured boot, not 300
        # seconds after SSH reconnects. There is no per-event router polling.
        end_at = boot["boot_zero_monotonic_lower"] + 300
        next_notice = time.monotonic() + 40
        while time.monotonic() < end_at:
            for process, _, _ in streams:
                if process.poll() is not None:
                    raise RuntimeError("read-only stream exited before the observation ended")
            if time.monotonic() >= next_notice:
                event("observing", boot_seconds=round(time.monotonic() - boot["boot_zero_monotonic_lower"], 2))
                next_notice = time.monotonic() + 40
            time.sleep(min(1, max(0, end_at - time.monotonic())))
        event("five_minute_window_finished")
        final = health("health-final")
        response = remote("cat /proc/sys/kernel/random/boot_id; cat /proc/uptime; sha256sum /etc/config/*; ubus -S call network.interface.wan status; ubus -S call network.interface.wan6 status")
        (out / "after.txt").write_bytes(response.stdout)
        assert response.returncode == 0 and response.stdout.decode().splitlines()[0] == boot["boot_id"]
        assert final["passed"], "final health failed"
        event("completed")
    finally:
        stopped.set()
        if thread.is_alive():
            thread.join(timeout=5)
        for process, stdout, stderr in streams:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            stdout.close()
            stderr.close()
        events.close()


if __name__ == "__main__":
    main()
