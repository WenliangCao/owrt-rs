#!/usr/bin/env python3
"""Strict compiler-warning gate for the release image and core recipes.

Usage: ci_check_core.py warnings <output.json> <log>...
Exits 1 when any compiler or unclassified warning remains.
"""
import argparse
import json
from pathlib import Path
import re

from dnsmasq.compiler_warnings import scan

REPO = Path(__file__).resolve().parent.parent


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def warnings(output, logs):
    result = scan([path for path in logs if path.is_file()])
    # The unmodified ImageBuilder checks its local repository before generating
    # the initial index. Keep that one known metadata message separate, only
    # in its image log; the common compiler scanner stays unchanged.
    initial_index = re.compile(
        r"^WARNING: opening /[^\s]+/openwrt-imagebuilder-[0-9]+\.[0-9]+\.[0-9]+-"
        r"[^/\s]+/packages/packages\.adb: No such file or directory$")
    compiler = []
    for entry in result["compiler_or_unclassified"]:
        if entry["log"] == "image.log" and initial_index.fullmatch(entry["text"]):
            result["sdk_metadata"].append(entry)
        else:
            compiler.append(entry)
    result["compiler_or_unclassified"] = compiler
    result["strict_compiler_warnings_zero"] = not compiler
    write(output, result)
    print(f"compiler/unclassified warnings: {len(result['compiler_or_unclassified'])}; "
          f"SDK metadata warnings: {len(result['sdk_metadata'])}", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    warning_parser = sub.add_parser("warnings")
    warning_parser.add_argument("output", type=Path)
    warning_parser.add_argument("logs", nargs="+", type=Path)
    args = parser.parse_args()
    return 0 if warnings(args.output, args.logs)["strict_compiler_warnings_zero"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
