#!/usr/bin/env python3
"""Use unchanged R132 ACK-controlled stat collection with R138 subject roles."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import r132_registration_profile as base


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-host-only", action="store_true", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    base.require(plan["mode"] == "stat", "R138 wrapper only permits stat")
    base.require(plan["r138_wrapper_sha256"] == base.sha(__file__), "R138 wrapper identity changed")
    base.LABELS = ("c", "r136", "remove")
    base.main()
