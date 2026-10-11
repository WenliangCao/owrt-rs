#!/usr/bin/env python3
"""Select static PIE startup objects for the pinned Rust musl target."""
import os
from pathlib import Path
import sys


def main():
    cc = os.environ.get("DNSMASQ_STATIC_PIE_CC", "")
    if not Path(cc).is_absolute() or not os.access(cc, os.X_OK) or Path(cc).resolve() == Path(__file__).resolve():
        raise SystemExit("DNSMASQ_STATIC_PIE_CC must name the actual SDK compiler")
    args = sys.argv[1:]
    if args.count("-static") != 1 or any(arg in ("-pie", "-static-pie", "-shared") or arg.startswith("@") for arg in args):
        raise SystemExit("expected one explicit -static link without PIE/shared flags or response files")
    replacements = {"crt1.o": "rcrt1.o", "crtbegin.o": "crtbeginS.o", "crtend.o": "crtendS.o"}
    seen, output = set(), []
    for arg in args:
        if arg == "-static":
            arg = "-static-pie"
        elif arg == "-no-pie":
            continue
        else:
            path = Path(arg)
            if path.name in replacements:
                if path.name in seen or path.parent.parts[-4:] != ("rustlib", "aarch64-unknown-linux-musl", "lib", "self-contained") or not path.is_file():
                    raise SystemExit("expected one of each pinned Rust self-contained startup object")
                replacement = path.with_name(replacements[path.name])
                if not replacement.is_file():
                    raise SystemExit(f"missing static PIE startup object: {replacement}")
                seen.add(path.name)
                arg = str(replacement)
        output.append(arg)
    if seen != replacements.keys():
        raise SystemExit("missing pinned Rust crt1/crtbegin/crtend inputs")
    os.execv(cc, [cc, *output])


if __name__ == "__main__":
    main()
