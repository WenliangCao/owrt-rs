#!/usr/bin/env python3
"""R92 fw4 CLI/ucode edge differential in exact-image namespaces.

Only private rootfs copies are written. nft is a recorder in that image;
ruleset generation, UCI, ucode and include execution remain the exact image.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from r92_compat_probe import Fixture
from r92_recovery_probe import digest, write

DEFAULTS = "config defaults\n option input 'ACCEPT'\n option output 'ACCEPT'\n option forward 'DROP'\n option auto_includes '0'\n"
ZONE = "config zone\n option name 'r92'\n list device 'lo'\n option input 'DROP'\n option output 'ACCEPT'\n option forward 'DROP'\n"
CASES = ["usage", "abort_print", "abort_start", "abort_reload", "no_bus", "set_missing", "set_directory", "set_notdir", "set_loop", "fractional_log", "any_device", "month_nan", "month_fraction", "include_signal", "include_timeout", "write_state_directory"]


def inner(root, side, case):
    f = Fixture(root, side, "fw4")
    try:
        nft = root / "usr/sbin/nft"
        if nft.is_symlink():
            nft.unlink()
        write(nft, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> /tmp/out/nft-args\ncase \" $* \" in *' --json '*) printf '{\"nftables\":[]}\\n';; *' -f '*) cat > /tmp/out/nft-input;; esac\nexit 0\n")
        nft.chmod(0o755)
        cfg = DEFAULTS
        action = "print"
        if case == "usage":
            action = "bogus"
        elif case.startswith("abort_"):
            cfg = "config defaults\n option input 'BOGUS'\n"
            action = case.removeprefix("abort_")
            if action == "reload":
                write(root / "var/run/fw4.state", "{}")
        elif case.startswith("set_"):
            filename = {"set_missing": "/tmp/missing", "set_directory": "/tmp/load-dir", "set_notdir": "/tmp/notdir/child", "set_loop": "/tmp/loop"}[case]
            (root / "tmp/load-dir").mkdir()
            write(root / "tmp/notdir", "regular")
            (root / "tmp/loop").symlink_to("loop")
            cfg += f"config ipset\n option name 'r92'\n list match 'src_ip'\n option loadfile '{filename}'\n"
        elif case == "fractional_log":
            cfg += ZONE + " option log '0.5'\nconfig rule\n option name 'r92-drop'\n option src 'r92'\n option proto 'all'\n option target 'DROP'\n"
        elif case == "any_device":
            cfg += ZONE + " list device '*'\nconfig rule\n option name 'r92-mark'\n option src 'r92'\n option proto 'all'\n option target 'MARK'\n option set_mark '1'\n"
        elif case.startswith("month_"):
            value = "foo" if case == "month_nan" else "1.5"
            cfg += ZONE + f"config rule\n option name 'r92-month'\n option src 'r92'\n option proto 'all'\n option target 'ACCEPT'\n option monthdays '{value}'\n"
        elif case.startswith("include_"):
            cfg += "config include\n option path '/tmp/include.sh'\n option fw4_compatible '1'\n"
            write(root / "tmp/include.sh", "kill -TERM $$\n" if case == "include_signal" else "exec sleep 60\n")
            action = "start"
        elif case == "write_state_directory":
            (root / "var/run/fw4.state").mkdir()
            # The shell start guard only checks regular files; this case
            # reaches fs.open(..., 'w') on a directory.
            action = "start"
        write(root / "etc/config/firewall", cfg)
        executable = root / f.binary[1:]
        identity = digest(executable)
        result = subprocess.run(["chroot", str(root), f.binary, action], capture_output=True, timeout=40)
        stdout = result.stdout.replace(f.binary.encode(), b"<fw4>")
        (f.output / "stdout.bin").write_bytes(stdout)
        (f.output / "stderr.bin").write_bytes(result.stderr)
        # ucode's interpreter backtrace is intentionally not fabricated by
        # the native implementation. Keep it raw; compare operational
        # warnings for aborts and state parse errors instead.
        stderr = result.stderr
        if case.startswith("abort_") or case == "write_state_directory":
            stderr = b"\n".join(line for line in stderr.splitlines() if line.startswith((b"[!] Section ", b"Unable to connect to ubus", b"Unable to read firewall state", b"Unable to write", b"The fw4 firewall")))
        diagnostic_ok = True
        # Exact ucode fs.open leaves fs.last_error stale on open failure;
        # the candidate intentionally reports the operation's actual errno.
        diagnostics = {
            "set_notdir": (b"/tmp/notdir/child' for set 'r92': ", b"Not a directory"),
            "set_loop": (b"/tmp/loop' for set 'r92': ", b"Symbolic link loop"),
            "write_state_directory": (b"/var/run/fw4.state': ", b"Is a directory"),
        }
        if case in diagnostics:
            prefix, actual_error = diagnostics[case]
            expected_error = b"No such file or directory" if side == "original" else actual_error
            line = next((s for s in stderr.splitlines() if prefix in s), b"")
            diagnostic_ok = line.endswith(prefix + expected_error)
            stderr = stderr.replace(prefix + expected_error, prefix + b"<verified errno disposition>")
        record = {"case": case, "side": side, "binary_sha256": identity, "action": action,
                  "exit": result.returncode, "diagnostic_ok": diagnostic_ok, "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                  "stderr_compared_hex": stderr.hex(), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}
        write(f.output / "result.json", json.dumps(record, indent=2) + "\n")
    finally:
        f.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        return inner(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cases", nargs="+", choices=CASES, default=CASES)
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.platform != "linux":
        parser.error("run as root on Linux")
    args.output.mkdir(parents=True, exist_ok=False)
    write(args.output / "probe.sha256", digest(Path(__file__)) + "\n")
    rows = []
    for case in args.cases:
        observed = {}
        for side in ("original", "candidate"):
            destination = args.output / f"{case}-{side}"
            destination.mkdir()
            with tempfile.TemporaryDirectory(prefix="r92-fw4-") as temporary:
                root = Path(temporary) / "root"
                shutil.copytree(args.rootfs, root, symlinks=True)
                for directory in ("out", "run/ubus", "lock", "state"):
                    (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
                shutil.copy2(args.candidate, root / "tmp/fw4-rs")
                with (destination / "driver.log").open("wb") as log:
                    result = subprocess.run(["timeout", "-k", "2", "45", "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child", sys.executable, str(Path(__file__).resolve()), "--inner", str(root), side, case], stdout=log, stderr=log)
                shutil.copytree(root / "tmp/out", destination / "raw")
            path = destination / "raw/result.json"
            if result.returncode == 0 and path.exists():
                observed[side] = json.loads(path.read_text())
        compared = ("exit", "stdout_sha256", "stderr_compared_hex")
        same = len(observed) == 2 and all(o["diagnostic_ok"] for o in observed.values()) and all(observed["original"][k] == observed["candidate"][k] for k in compared)
        rows.append({"case": case, "passed": same, "observations": observed})
        write(args.output / "results.json", json.dumps(rows, indent=2) + "\n")
        print(json.dumps({"case": case, "passed": same, "differing": [k for k in compared if len(observed) == 2 and observed["original"][k] != observed["candidate"][k]]}), flush=True)
    passed = len(rows) == len(args.cases) and all(row["passed"] for row in rows)
    (args.output / ("COMPLETE" if passed else "FAILED")).touch()
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
