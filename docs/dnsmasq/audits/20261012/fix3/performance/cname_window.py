#!/usr/bin/env python3
"""Pure cached CNAME workload using unchanged M6a native loadgen/runner.

The wrapper changes only the synthetic name bank and loadgen qtype. There are
2048 CNAME owners and one shared A terminal in a 4096-slot cache; every owner
is proved with the upstream disabled before timing. Product code is untouched.
"""
from pathlib import Path
import sys

source = Path(sys.argv.pop(1))
sys.path.insert(0, str(source / "tools/dnsmasq"))
import m6a_window as window

window.bank_question = lambda index, mixed: (f"cname-q{index:04x}.{window.PREFIX}", 1)
original_fill = window.fill_and_prove
window.fill_and_prove = lambda out, count, disable, upstream_pid, daemon_pid, mixed=False: original_fill(
    out, 2048, disable, upstream_pid, daemon_pid, mixed)
original_command = window.load_command


def load_command(args):
    command = original_command(args)
    command[command.index("--qtype") + 1] = "cname"
    return command


window.load_command = load_command
raise SystemExit(window.main())
