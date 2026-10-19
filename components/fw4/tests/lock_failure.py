#!/usr/bin/env python3
"""Oracle-only: lock-open failures must not execute nft or remove state.

Run as root with --binary FW4 --stock-root ROOT --output JSON. The stock
OpenWrt BusyBox wrapper runs via qemu-aarch64. All writes are mount-isolated.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--stock-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inner", type=Path)
    parser.add_argument("--side")
    parser.add_argument("--action")
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0
    if args.inner:
        fixture = args.inner
        subprocess.run(["mount", "--make-rprivate", "/"], check=True)
        subprocess.run(["mount", "--bind", str(fixture / "run"), "/var/run"], check=True)
        env = dict(os.environ, FW4_MOCK_DIRS=str(fixture / "mock"),
                   FW4_MARKER=str(fixture / "nft-calls"),
                   PATH=str(fixture / "bin") + ":" + os.environ["PATH"])
        command = [str(args.binary)] if args.side == "rust" else [
            "qemu-aarch64", "-L", str(args.stock_root),
            str(args.stock_root / "bin/busybox"), "sh", str(args.stock_root / "sbin/fw4")]
        result = subprocess.run(command + [args.action], env=env, capture_output=True, timeout=5)
        marker = fixture / "nft-calls"
        print(json.dumps({"exit": result.returncode,
                          "stderr": result.stderr.decode(errors="replace"),
                          "nft_calls": marker.read_text() if marker.exists() else "",
                          "state_exists": (fixture / "run/fw4.state").exists()}))
        return
    rows = []
    for action in ["start", "reload", "stop", "flush"]:
        for bad in [True, False]:
            for side in ["stock", "rust"] if bad else ["rust"]:
                for repeat in range(4):
                    with tempfile.TemporaryDirectory(prefix="fw4-lock-") as tmp:
                        fixture = Path(tmp)
                        for directory in ["run", "mock/uci", "mock/fs", "bin"]:
                            (fixture / directory).mkdir(parents=True, exist_ok=True)
                        if bad:
                            (fixture / "run/fw4.lock").mkdir()
                        if action != "start":
                            (fixture / "run/fw4.state").write_text('{"includes":[]}')
                        (fixture / "mock/uci/firewall.json").write_text(
                            '{"defaults":{"input":"DROP","output":"ACCEPT",'
                            '"forward":"DROP","auto_includes":"0"}}')
                        (fixture / "mock/fs/open~_var_run_fw4_state.txt").write_text('{"includes":[]}')
                        nft = fixture / "bin/nft"
                        nft.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$FW4_MARKER"\ncat >/dev/null\n')
                        nft.chmod(0o755)
                        result = subprocess.run([
                            "unshare", "--mount", sys.executable, __file__,
                            "--binary", str(args.binary), "--stock-root", str(args.stock_root),
                            "--output", str(args.output), "--inner", tmp,
                            "--side", side, "--action", action,
                        ], capture_output=True, timeout=8, check=True)
                        row = json.loads(result.stdout)
                        row.update(action=action, side=side, bad=bad, repeat=repeat)
                        row["passed"] = (row["exit"] == 1 and not row["nft_calls"]
                                         and row["state_exists"] == (action != "start")) if bad else (
                                             row["exit"] == 0 and bool(row["nft_calls"]))
                        rows.append(row)
    identities = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in [args.binary, args.stock_root / "sbin/fw4", args.stock_root / "bin/busybox"]}
    args.output.write_text(json.dumps({"identities": identities, "rows": rows}, indent=2) + "\n")
    failures = [row for row in rows if not row["passed"]]
    print(f"{len(rows) - len(failures)}/{len(rows)} passed; evidence: {args.output}")
    raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
