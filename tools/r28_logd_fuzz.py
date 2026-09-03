#!/usr/bin/env python3
"""Malformed-input fuzzing of logd-rs against the exact image's logd.

Same sandbox as r15 (exact rootfs, ubusd + the daemon under test in a chroot
inside a private mount namespace). The daemons are started once; every input
is then delivered from the host through `nsenter` into that namespace:

  * raw datagrams on /dev/log: missing / malformed / out-of-range <PRI>, empty,
    NUL bytes, invalid UTF-8, control characters, embedded newlines, RFC3164
    and RFC5424 shaped lines, very long lines (up to the 64 KiB datagram limit),
    bursts that wrap the ring;
  * `ubus call log write` with events of the wrong type, empty, huge, or with
    unknown parameters;
  * `ubus call log read` with negative, zero, huge and wrongly typed `lines`.

Afterwards `logread`, `logread -l N` and `ubus call log read` dumps are
compared (timestamps, pids and ids masked, the way r15 does).

Usage: r28_logd_fuzz.py --rootfs DIR --candidate logd-rs
Exit code 1 when any output differs.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

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
chroot "$root" /bin/sh -s "$impl" <<'CHROOT'
set -u
impl=$1
mkdir -p /var/run/ubus /tmp/out
exec 2>/tmp/out/trace.txt
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
ubusd_pid=$!
for i in 1 2 3 4 5; do [ -S /var/run/ubus/ubus.sock ] && break; sleep 1; done
if [ "$impl" = original ]; then
  /sbin/logd -S 64 >/tmp/out/logd.log 2>&1 &
else
  /tmp/logd-rs -S 64 --kmsg none >/tmp/out/logd.log 2>&1 &
fi
logd_pid=$!
for i in 1 2 3 4 5 6 7 8; do ubus list log >/dev/null 2>&1 && break; sleep 1; done
echo $$ > /tmp/out/pid
echo "$logd_pid" > /tmp/out/logd.pid
while [ ! -e /tmp/out/stop ]; do sleep 1; done
kill $logd_pid $ubusd_pid 2>/dev/null || true
sleep 1
CHROOT
"""

SENDER = r"""
import socket, sys, base64, time
path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
for enc in sys.argv[2:]:
    payload = base64.b64decode(enc)
    try:
        s.sendto(payload, path)
    except OSError as e:
        print("sendto failed len=%d: %s" % (len(payload), e))
    time.sleep(0.002)
"""


def datagrams():
    D = []
    D += [b"", b"<13>", b"<13>msg", b"<13> msg", b"<13>tag: msg", b"<13>tag[123]: msg", b"<13>tag[abc]: msg", b"<13>tag:", b"<13>: msg",
          b"<999>msg", b"<-1>msg", b"<abc>msg", b"<>msg", b"<13", b"13>msg", b"<13><14>msg", b"msg without pri", b"< 13>msg",
          b"<013>msg", b"<0>emerg", b"<7>debug", b"<191>local7.debug", b"<192>facility 24", b"<1000000000000>huge pri",
          b"\x00", b"<13>a\x00b", b"<13>\x00", b"<13>\xff\xfe\xfd", b"<13>caf\xc3\xa9", b"<13>\xed\xa0\x80 surrogate",
          b"<13>\x1b[31mred\x1b[0m", b"<13>line1\nline2", b"<13>\ttab\t", b"<13>trailing newline\n", b"<13>\r\n", b"\r\n", b"\n",
          b"<13>" + b" " * 100, b"<13>" + b" " * 100 + b"x",
          b"<13>Jan  1 00:00:00 host tag: with timestamp", b"<13>Sep  3 22:00:00 tag[1]: rfc3164",
          b"<134>1 2026-09-03T00:00:00Z host app 1 - - rfc5424 msg", b"<13>1 - - - - - -",
          b"<13>" + b"x" * 1000, b"<13>" + b"x" * 4000, b"<13>" + b"x" * 4095, b"<13>" + b"x" * 4096, b"<13>" + b"x" * 4097,
          b"<13>" + b"x" * 8192, b"<13>" + b"x" * 20000, b"<13>" + b"x" * 60000,
          b"<13>" + b"\xc3\xa9" * 3000, b"<13>%s%s%n", b"<13>$(id)", b"<13>{\"json\":true}", b"<13>tag with space: msg",
          b"<13>a" * 1 + b":" * 500, b"<13>" + b"[" * 200 + b"]" * 200, b"<13>\x7f\x7f", b"<13>" + bytes(range(1, 32))]
    D += [b"<13>burst %d padding padding padding padding" % i for i in range(700)]   # wraps a 64 KiB ring
    D += [b"<13>after wrap"]
    return D


def ubus_writes():
    return [{}, {"event": 1}, {"event": None}, {"event": True}, {"event": ["a"]}, {"event": {"a": 1}}, {"event": ""},
            {"event": "<13>x"}, {"event": "<999>x"}, {"event": "x" * 5000}, {"event": "a\nb"}, {"event": "\u0000"},
            {"event": "caf\u00e9 \u540d"}, {"other": "x"}, {"event": "x", "extra": 1}, {"event": "tag[1]: y"}]


def ubus_reads():
    return [{"lines": -1, "stream": False}, {"lines": 0, "stream": False}, {"lines": 100000, "stream": False}, {"lines": "5", "stream": False},
            {"lines": True, "stream": False}, {"stream": False}, {}, {"lines": 3, "stream": False, "oneshot": True}, {"lines": 3, "stream": "x"},
            {"lines": 2147483647, "stream": False}, {"lines": -2147483648, "stream": False}]


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, check=False, **kw)


TS = re.compile(r"^[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \d{4} ")
PID = re.compile(r"\[\d+\]")


def norm_logread(text):
    return [PID.sub("[<pid>]", TS.sub("<ts> ", l)) for l in text.splitlines()]


def norm_json(text):
    text = re.sub(r'"time": \d+', '"time": <t>', text)
    text = re.sub(r'"id": \d+', '"id": <n>', text)
    return text.splitlines()


def run_side(rootfs, candidate, impl):
    temp = Path(tempfile.mkdtemp(prefix="owrt-r28-")).resolve()
    root = temp / "rootfs"
    try:
        shutil.copytree(rootfs, root, symlinks=True)
        (root / "tmp").mkdir(exist_ok=True)
        if impl == "candidate":
            shutil.copy2(candidate, root / "tmp/logd-rs")
            (root / "tmp/logd-rs").chmod(0o755)
        (temp / "scenario.sh").write_text(SCENARIO)
        (temp / "sender.py").write_text(SENDER)
        log = temp / f"{impl}.log"
        with log.open("w") as sink:
            proc = subprocess.Popen(["sudo", "-n", "setsid", "-w", "unshare", "--mount", "--fork", "/bin/bash", str(temp / "scenario.sh"), str(root), impl],
                                    stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT)
        pidfile = root / "tmp/out/pid"
        for _ in range(60):
            if pidfile.exists() and pidfile.read_text().strip():
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("%s: sandbox did not come up\n%s" % (impl, log.read_text(errors="replace")[-2000:]))
        pid = pidfile.read_text().strip()
        ns = ["sudo", "-n", "nsenter", "-t", pid, "-m", "--"]
        inside = ns + ["chroot", str(root)]
        out = {}
        # 1. raw datagrams, in batches (argv size)
        import base64
        ds = datagrams()
        for i in range(0, len(ds), 100):
            r = run(ns + [sys.executable, str(temp / "sender.py"), str(root / "dev/log")] + [base64.b64encode(d).decode() for d in ds[i:i + 100]])
            if r.stdout.strip():
                out.setdefault("sendto", []).extend(r.stdout.decode(errors="replace").splitlines())
        time.sleep(1)
        out["after_datagrams"] = norm_logread(run(inside + ["/sbin/logread"]).stdout.decode(errors="replace"))
        # 2. ubus writes
        for k, ev in enumerate(ubus_writes()):
            r = run(inside + ["ubus", "call", "log", "write", json.dumps(ev)])
            out["write%02d" % k] = ["rc=%d" % r.returncode] + r.stdout.decode(errors="replace").splitlines() + r.stderr.decode(errors="replace").splitlines()
        time.sleep(0.5)
        # 3. ubus reads
        for k, args in enumerate(ubus_reads()):
            r = run(inside + ["ubus", "-t", "10", "call", "log", "read", json.dumps(args)])
            out["read%02d" % k] = ["rc=%d" % r.returncode] + norm_json(r.stdout.decode(errors="replace")) + r.stderr.decode(errors="replace").splitlines()
        out["logread_full"] = norm_logread(run(inside + ["/sbin/logread"]).stdout.decode(errors="replace"))
        out["logread_l5"] = norm_logread(run(inside + ["/sbin/logread", "-l", "5"]).stdout.decode(errors="replace"))
        out["logread_l0"] = norm_logread(run(inside + ["/sbin/logread", "-l", "0"]).stdout.decode(errors="replace"))
        out["logread_e"] = norm_logread(run(inside + ["/sbin/logread", "-e", "burst 6[0-9][0-9]"]).stdout.decode(errors="replace"))
        alive = run(ns + ["kill", "-0", (root / "tmp/out/logd.pid").read_text().strip()]).returncode == 0
        out["alive"] = [str(alive)]
        run(["sudo", "-n", "touch", str(root / "tmp/out/stop")])
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
        daemon = (root / "tmp/out/logd.log")
        out["_daemon_log"] = daemon.read_text(errors="replace")[-1500:].splitlines() if daemon.exists() else []
        return out
    finally:
        run(["sudo", "-n", "rm", "-rf", "--", str(temp)])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rootfs", required=True, type=Path)
    ap.add_argument("--candidate", required=True, type=Path)
    a = ap.parse_args()
    orig = run_side(a.rootfs.resolve(), a.candidate.resolve(), "original")
    cand = run_side(a.rootfs.resolve(), a.candidate.resolve(), "candidate")
    bad = 0
    for name in sorted(set(orig) | set(cand)):
        if name.startswith("_"):
            continue
        o, n = orig.get(name, []), cand.get(name, [])
        if o == n:
            continue
        bad += 1
        print("DIFF %s: %d vs %d lines" % (name, len(o), len(n)))
        for i in range(max(len(o), len(n))):
            x, y = (o[i] if i < len(o) else "<missing>"), (n[i] if i < len(n) else "<missing>")
            if x != y:
                print("   line %d\n     orig=%r\n     cand=%r" % (i, x[:300], y[:300]))
                break
    for impl, d in (("original", orig), ("candidate", cand)):
        if d.get("_daemon_log"):
            print("== %s daemon log: %r" % (impl, d["_daemon_log"][-5:]))
    print("outputs=%d differing=%d" % (len([k for k in orig if not k.startswith('_')]), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
