#!/usr/bin/env python3
"""Linux-only CLI regression: commit_cleanup_failure.py UCI_BINARY OUTPUT.

Use strace syscall injection on private files; no router or mount changes.
A cleanup failure must restore the original config before a retry. If that
restoration also fails, retain its backup and report an uncertain commit.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    if sys.platform != "linux" or len(sys.argv) != 3:
        raise SystemExit(__doc__)
    binary = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    rename = "renameat" if os.uname().machine == "aarch64" else "rename"
    rows = []
    for fault in ("none", "cleanup", "install", "restore"):
        for repeat in range(4):
            with tempfile.TemporaryDirectory(prefix="uci-cleanup-") as directory:
                root = Path(directory)
                config, delta = root / "config", root / "delta"
                config.mkdir()
                delta.mkdir()
                path = config / "sample"
                original = b"config test 's'\n list names 'old'\n"
                path.write_bytes(original)
                command = [str(binary), "-c", str(config), "-t", str(delta)]
                subprocess.run(command + ["add_list", "sample.s.names=new"], check=True,
                               capture_output=True)
                draft = (delta / "sample").read_bytes()
                trace = output / f"{fault}-{repeat}.trace"
                inject = ["strace", "-o", str(trace)]
                if fault in ("cleanup", "restore"):
                    inject += ["-e", "inject=ftruncate:error=EIO:when=1"]
                if fault in ("install", "restore"):
                    when = 1 if fault == "install" else 2
                    inject += ["-e", f"inject={rename}:error=EIO:when={when}"]
                first = subprocess.run(inject + command + ["commit", "sample"],
                                       capture_output=True)
                saved = (delta / "sample").read_bytes()
                backups = list(config.glob(".sample.uci-backup-*"))
                row = {"fault": fault, "repeat": repeat, "exit": first.returncode,
                       "stderr": first.stderr.decode(), "config_unchanged": path.read_bytes() == original,
                       "draft_retained": saved == draft, "backups": len(backups)}
                if fault == "restore":
                    row["passed"] = (first.returncode == 1 and b"Unknown error" in first.stderr
                                     and not row["config_unchanged"] and row["draft_retained"]
                                     and len(backups) == 1 and backups[0].read_bytes() == original)
                    # An uncertain commit is deliberately not retried blindly.
                else:
                    expected = first.returncode == (0 if fault == "none" else 1)
                    expected &= (saved == b"" if fault == "none" else row["config_unchanged"] and row["draft_retained"])
                    retry = subprocess.run(command + ["commit", "sample"], capture_output=True)
                    row.update(retry_exit=retry.returncode,
                               new_items=path.read_text().count("'new'"))
                    row["passed"] = (expected and retry.returncode == 0 and row["new_items"] == 1
                                     and not list(config.glob(".sample.uci-*"))
                                     and (delta / "sample").read_bytes() == b"")
                rows.append(row)
    result = {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "rows": rows}
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if all(row["passed"] for row in rows) else 1)


if __name__ == "__main__":
    main()
