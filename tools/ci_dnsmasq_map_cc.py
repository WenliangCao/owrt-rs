#!/usr/bin/env python3
"""Retain a linker map without changing Cargo/rustc code-generation flags."""
import os
from pathlib import Path
import sys


def command(args, env):
    cc = Path(env["PERF_SDK_CC"])
    if not cc.is_absolute() or not cc.is_file():
        raise ValueError("expected actual SDK compiler")
    result = [str(cc), *args]
    if "-static-pie" in args:
        output = Path(env["PERF_LINK_MAP"])
        if not output.is_absolute() or "private" not in output.parts:
            raise ValueError("linker map must be a private absolute output path")
        result.append("-Wl,-Map=" + str(output))
    return result


if __name__ == "__main__":
    argv = command(sys.argv[1:], os.environ)
    os.execv(argv[0], argv)
