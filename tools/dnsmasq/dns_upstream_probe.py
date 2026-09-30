#!/usr/bin/env python3
"""Run the isolated Rust upstream-transport regression set.

The tests bind only 127.0.0.1 and use no resolver configuration, physical
router, or external network. Raw test output is kept in ``private/`` so it is
available as evidence without entering Git. This probe does not claim that
the local development binary is an upstream daemon.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import time


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "components/dnsmasq/Cargo.toml"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "private/dnsmasq-rs/upstream/probe-20260930",
        help="ignored evidence directory; it must not already exist",
    )
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to((ROOT / "private").resolve()):
        parser.error("--out must stay below private/")
    if out.exists():
        parser.error("choose a new evidence directory")
    out.mkdir(parents=True)
    started = time.time()
    command = [
        args.cargo,
        "test",
        "--manifest-path",
        str(MANIFEST),
        "--lib",
        "dns::upstream::tests",
        "--",
        "--nocapture",
    ]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    (out / "stdout.log").write_text(result.stdout)
    (out / "stderr.log").write_text(result.stderr)
    summary = {
        "command": command,
        "returncode": result.returncode,
        "elapsed_seconds": round(time.time() - started, 3),
        "scope": [
            "loopback UDP peer authentication",
            "failed first-send fallback",
            "all-server REFUSED wait without resend",
            "fixed timeout and socket cleanup",
            "duplicate coalescing and cancellation",
            "explicit fast retry and cancellation",
        ],
        "network": "loopback only; no external or physical-router access",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
