#!/usr/bin/env python3
"""Detached Mac orchestrator for an already prepared, authorized cold switch.

Run only after recovery artifacts and offline backups have been verified.
Wi-Fi management is authorized; no LAN cable is required. This checks preflight, stages the chosen stack,
requires a new boot and 180 seconds of continuous client health, and confirms
Rust before its all-stock rollback deadline. It never restarts a live ubusd.
"""
import argparse
import datetime
import http.client
import json
from pathlib import Path
import subprocess
import time

from r84_device_probe import probe, ssh


def log(event, **fields):
    print(json.dumps({"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "event": event, **fields}, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("stock", "rust"))
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--static-client", action="store_true")
    parser.add_argument("--ipv4-only", action="store_true")
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    if args.result.exists():
        raise RuntimeError("refusing to overwrite a previous window result")
    health_args = dict(host=args.host, interface=args.interface, ipv6=not args.ipv4_only,
                       static_client=args.static_client)
    pre = probe(mode="existing", **health_args)
    log("preflight_passed", probe=pre)
    # A failed stage raises here; it can never fall through into reboot.
    stage = ssh(args.host, "/bin/sh /root/r84/stack-switch.sh stage " + args.mode, timeout=180)
    log("staged", mode=args.mode, result=stage)
    started = time.monotonic()
    try:
        ssh(args.host, "reboot")
    except (RuntimeError, OSError, subprocess.TimeoutExpired):
        pass  # An orderly reboot may close SSH before sending its exit code.
    log("reboot_requested", old_boot_id=pre["boot_id"])
    held_since = None
    first_ssh = None
    verified_boot = None
    while time.monotonic() - started < 840:
        time.sleep(10)
        elapsed = time.monotonic() - started
        try:
            identity = ssh(args.host, "cat /proc/sys/kernel/random/boot_id; cut -d' ' -f1 /proc/uptime").splitlines()
            if identity[0] == pre["boot_id"]:
                raise RuntimeError("still on the previous boot")
            if first_ssh is None:
                first_ssh = elapsed
                log("new_boot_reachable", elapsed_s=elapsed, uptime_s=float(identity[1]), boot_id=identity[0])
            health = probe(mode=args.mode, **health_args)
            if verified_boot != health["boot_id"]:
                held_since = None
                verified_boot = health["boot_id"]
            if held_since is None:
                held_since = time.monotonic()
            held = time.monotonic() - held_since
            log("health_pass", elapsed_s=time.monotonic() - started, continuous_s=held, probe=health)
            if held >= 180:
                if time.monotonic() - started >= 870:
                    raise RuntimeError("confirmation deadline exceeded")
                time.sleep(30)
                post = probe(mode=args.mode, **health_args)
                if post["boot_id"] != verified_boot:
                    raise RuntimeError("boot changed during final observation")
                if time.monotonic() - started >= 870:
                    raise RuntimeError("confirmation deadline exceeded")
                if args.mode == "rust":
                    log("confirmed", output=ssh(args.host, "/bin/sh /root/r84/stack-switch.sh confirm " + pre["boot_id"], timeout=120))
                result = {"status": "healthy", "mode": args.mode, "first_ssh_s": first_ssh,
                          "elapsed_s": time.monotonic() - started, "pre": pre, "post": post}
                args.result.write_text(json.dumps(result, indent=2) + "\n")
                log("window_complete", result=result)
                return 0
        except (RuntimeError, OSError, ValueError, KeyError, http.client.HTTPException,
                subprocess.TimeoutExpired) as exc:
            held_since = None
            log("health_not_confirmed", elapsed_s=time.monotonic() - started, error=str(exc))
    result = {"status": "not_confirmed", "mode": args.mode, "first_ssh_s": first_ssh,
              "pre": pre, "elapsed_s": time.monotonic() - started}
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    log("window_failed_canary_left_armed", result=result)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
