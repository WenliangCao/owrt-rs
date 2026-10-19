#!/usr/bin/env python3
"""Compare CLI and saved-delta reorder positions with the pinned C uci."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--stock-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.stock_root
    commands = {"c": [str(root / "lib/ld-musl-aarch64.so.1"), "--library-path",
                      str(root / "lib"), str(root / "sbin/uci")], "rust": [str(args.binary)]}
    values = ["0", "1", "-1", "  +1tail", "4294967297", "18446744073709551615",
              "18446744073709551616", "18446744073709551617",
              "-18446744073709551615", "-18446744073709551616",
              "-18446744073709551617", "9" * 128]
    rows = []
    for repeat in range(4):
        for mode in ["cli", "delta"]:
            for value in values:
                sides = {}
                for side, command in commands.items():
                    with tempfile.TemporaryDirectory(prefix="uci-reorder-") as tmp:
                        base = Path(tmp)
                        config, delta = base / "config", base / "delta"
                        config.mkdir()
                        delta.mkdir()
                        (config / "test").write_text("config x 'a'\nconfig x 'b'\nconfig x 'c'\n")
                        def run(*extra):
                            result = subprocess.run(command + ["-c", str(config), "-C", "", "-t", str(delta), *extra],
                                                    capture_output=True, timeout=5)
                            return {"exit": result.returncode, "stdout": result.stdout.decode(),
                                    "stderr": result.stderr.decode()}
                        if mode == "delta":
                            (delta / "test").write_text(f"^test.c='{value}'\n")
                        reordered = run("reorder", "test.c=" + value) if mode == "cli" else None
                        sides[side] = {"reorder": reordered, "show": run("show", "test"),
                                       "delta": (delta / "test").read_text()}
                rows.append({"repeat": repeat, "mode": mode, "value": value,
                             "passed": sides["c"] == sides["rust"], **sides})
    paths = [args.binary, root / "sbin/uci", root / "lib/libuci.so.20250120", root / "lib/libc.so"]
    args.output.write_text(json.dumps({"identities": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
                                      "rows": rows}, indent=2) + "\n")
    failed = sum(not row["passed"] for row in rows)
    print(f"{len(rows) - failed}/{len(rows)} C/Rust comparisons passed; evidence: {args.output}")
    raise SystemExit(bool(failed))


if __name__ == "__main__":
    main()
