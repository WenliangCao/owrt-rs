#!/usr/bin/env python3
"""Differentially test logd-rs against the exact image's logd.

Runs each daemon (original, then candidate) inside a disposable copy of the
exact rootfs under a private mount namespace with the exact ubusd, logger,
ubus and logread binaries, feeds identical inputs, and compares the observable
outputs after masking timestamps and pids.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SCENARIO = r"""
set -eu
root=$1
impl=$2
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t tmpfs tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
trap 'umount "$root/dev" 2>/dev/null || true; umount "$root/proc" 2>/dev/null || true' EXIT
timeout 240 chroot "$root" /bin/sh -s "$impl" <<'CHROOT_TEST'
set -u
impl=$1
mkdir -p /var/run/ubus /tmp/out
exec 2>/tmp/out/trace.txt
set -x
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
ubusd_pid=$!
logd_pid=
trap 'kill $logd_pid $ubusd_pid 2>/dev/null || true' EXIT
for i in 1 2 3 4 5; do [ -S /var/run/ubus/ubus.sock ] && break; sleep 1; done
if [ "$impl" = original ]; then
  /sbin/logd -S 1 >/tmp/out/logd.log 2>&1 &
else
  /tmp/logd-rs -S 1 --kmsg none >/tmp/out/logd.log 2>&1 &
fi
logd_pid=$!
for i in 1 2 3 4 5 6 7 8; do ubus list log >/dev/null 2>&1 && break; sleep 1; done
step() { echo "step=$1 rc=$2" >>/tmp/out/steps.txt; }
ubus -v list log > /tmp/out/signature.txt 2>&1; step signature $?
logger -t t1 -p daemon.info "msg one"; step l1 $?
logger -t t1 -p user.err "error   with   spaces   "; step l2 $?
logger -p local7.debug "dropped local7 line"; step l3 $?
ubus call log write '{"event":"<14>direct write"}'; step w1 $?
ubus call log write '{"event":"no priority write"}'; step w2 $?
logger -t t1 "$(printf 'x%.0s' $(seq 1 900))"; step long $?
logger -t nl "line with
embedded newline"; step nl $?
logread > /tmp/out/read-all-before-wrap.txt; step r1 $?
ubus call log read '{"lines":3,"stream":false}' > /tmp/out/ubus-read-3.json; step u1 $?
i=0; while [ $i -lt 120 ]; do logger -t ring "ring message number $i padding padding padding"; i=$((i+1)); done; step ring $?
logread > /tmp/out/read-all-after-wrap.txt; step r2 $?
logread -l 5 > /tmp/out/read-last-5.txt; step r3 $?
logread -e 'ring message number 11[0-9]' > /tmp/out/read-regex.txt; step r4 $?
ubus call log read '{"lines":4,"stream":false}' > /tmp/out/ubus-read-4.json; step u2 $?
ubus call log read '{"lines":0,"stream":false}' > /tmp/out/ubus-read-0.json; step u3 $?
logread -f -l 0 > /tmp/out/follow.txt 2>&1 &
follow_pid=$!
sleep 1
logger -t follow "follow one"; step f1 $?
ubus call log write '{"event":"follow two"}'; step f2 $?
sleep 1
kill $follow_pid 2>/dev/null || true
sleep 1
kill $logd_pid; wait $logd_pid 2>/dev/null || true
kill $ubusd_pid; wait $ubusd_pid 2>/dev/null || true
trap - EXIT
CHROOT_TEST
"""

TS = re.compile(r"^[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \d{4} ")
PID = re.compile(r"\[\d+\]")
JSON_TIME = re.compile(r'"time": \d+')
JSON_ID = re.compile(r'"id": \d+')


def run(command: list[str], *, input_text: str | None = None, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, input=input_text, capture_output=True, text=True, timeout=timeout, check=False)


def normalize_text(text: str, kind: str) -> list[str]:
    lines = []
    for line in text.splitlines():
        if kind == "logread":
            line = TS.sub("", line)
            line = PID.sub("[PID]", line)
            if "kernel:" in line:
                continue
        elif kind == "json":
            line = JSON_TIME.sub('"time": T', line)
            line = JSON_ID.sub('"id": N', line)
        lines.append(line)
    return lines


@contextlib.contextmanager
def disposable_rootfs(source: Path, candidate: Path | None):
    temp = Path(tempfile.mkdtemp(prefix="owrt-r15-")).resolve()
    root = temp / "rootfs"
    try:
        shutil.copytree(source, root, symlinks=True)
        (root / "tmp").mkdir(exist_ok=True)
        if candidate is not None:
            shutil.copy2(candidate, root / "tmp/logd-rs")
            (root / "tmp/logd-rs").chmod(0o755)
        yield root
    finally:
        cleanup = run(["sudo", "-n", "rm", "-rf", "--", str(temp)])
        if cleanup.returncode != 0:
            raise RuntimeError(f"cannot remove {temp}: {cleanup.stderr}")


def run_scenario(rootfs: Path, candidate: Path, impl: str) -> dict[str, list[str]]:
    with disposable_rootfs(rootfs, candidate if impl == "candidate" else None) as root:
        script = root.parent / "scenario.sh"
        script.write_text(SCENARIO)
        log = root.parent / f"{impl}.log"
        print(f"[{impl}] running scenario in {root}", flush=True)
        # stdout/stderr go to a file so lingering daemons can never hold a pipe
        with log.open("w") as sink:
            result = subprocess.run(
                ["sudo", "-n", "setsid", "-w", "unshare", "--mount", "--fork", "/bin/bash", str(script), str(root), impl],
                stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT, timeout=300, check=False,
            )
        if result.returncode != 0:
            trace = (root / "tmp/out/trace.txt")
            logd_log = (root / "tmp/out/logd.log")
            detail = trace.read_text(errors="replace")[-3000:] if trace.exists() else "(no trace)"
            daemon = logd_log.read_text(errors="replace")[-1000:] if logd_log.exists() else "(no logd log)"
            raise RuntimeError(f"scenario failed for {impl} ({result.returncode})\n{log.read_text(errors='replace')[-2000:]}\ntrace:\n{detail}\nlogd:\n{daemon}")
        out: dict[str, list[str]] = {}
        for name in ("logd.log", "ubusd.log"):
            path = root / "tmp/out" / name
            if path.exists():
                print(f"[{impl}] {name}: {path.read_text(errors='replace')[-800:]!r}", flush=True)
        for path in sorted((root / "tmp/out").iterdir()):
            if path.name in ("trace.txt", "ubusd.log", "logd.log"):
                continue
            if path.name == "steps.txt":
                out[path.name] = path.read_text().splitlines()
                continue
            kind = "json" if path.suffix == ".json" else "logread"
            if path.name == "signature.txt":
                kind = "raw"
            text = path.read_text(errors="replace")
            out[path.name] = normalize_text(text, kind) if kind != "raw" else text.splitlines()
        print(f"[{impl}] outputs: {sorted(out)}", flush=True)
        return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()

    original = run_scenario(args.rootfs.resolve(), args.candidate.resolve(), "original")
    candidate = run_scenario(args.rootfs.resolve(), args.candidate.resolve(), "candidate")
    comparisons: list[dict[str, Any]] = []
    for name in sorted(set(original) | set(candidate)):
        a = original.get(name, [])
        b = candidate.get(name, [])
        # the object id differs per registration; compare signature body only
        if name == "signature.txt":
            a = [re.sub(r"@[0-9a-f]+", "@ID", line) for line in a]
            b = [re.sub(r"@[0-9a-f]+", "@ID", line) for line in b]
        comparisons.append({
            "output": name,
            "original_lines": len(a),
            "candidate_lines": len(b),
            "identical": a == b,
            "first_difference": next(((i, x, y) for i, (x, y) in enumerate(zip(a, b)) if x != y), None) if a != b else None,
        })
    passed = all(item["identical"] for item in comparisons)
    payload = {
        "schema_version": 1,
        "stage": "2-r15-logd",
        "status": "complete" if passed else "failed",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "method": {
            "device_access": False,
            "rootfs_copy_is_disposable": True,
            "ubusd_logger_ubus_logread": "exact image binaries",
            "kmsg": "disabled for the candidate; kernel lines filtered from comparisons",
            "masked": ["logread timestamp prefix", "[pid]", "json time", "json id", "object id"],
        },
        "candidate": {
            "sha256": hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
            "size_bytes": args.candidate.stat().st_size,
        },
        "comparisons": comparisons,
        "gate": {"all_outputs_identical": passed},
    }
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"passed": passed, "outputs": len(comparisons)}, indent=2))
    if not passed:
        for item in comparisons:
            if not item["identical"]:
                print(item["output"], item["first_difference"])
        raise SystemExit(1)


if __name__ == "__main__":
    main()
