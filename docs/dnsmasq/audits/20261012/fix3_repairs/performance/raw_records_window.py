#!/usr/bin/env python3
"""Cached A control with N unrelated, valid dns-rr configuration entries."""
from pathlib import Path
import sys

source = Path(sys.argv.pop(1))
count = int(sys.argv.pop(1))
sys.path.insert(0, str(source / 'tools/dnsmasq'))
import m6a_window as window

original_config = window.config_for


def config_for(scenario, tcp_profile='hit'):
    return original_config(scenario, tcp_profile) + ''.join(
        f'dns-rr=unused{i}.audit.test,65401,abcd\n' for i in range(count))


window.config_for = config_for
raise SystemExit(window.main())
