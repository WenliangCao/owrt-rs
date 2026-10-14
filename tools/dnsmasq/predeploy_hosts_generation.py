#!/usr/bin/env python3
"""Replay hosts generation/cursor cases with the exact image loader.

Usage: SOURCE IMAGE_ROOT RUST PRIVATE_OUTPUT MATCHING_NATIVE_C_BUILD
The native build supplies only the source-derived inventory/rotation fixtures;
all DNS queries execute the image C ELF through its original libraries.
"""
import sys
from pathlib import Path
source, image, rust, output, reference = map(Path, sys.argv[1:])
sys.path.insert(0, str(source/'tools/dnsmasq'))
import dns_hosts_generation_diff as suite
from m2_rootfs import image_elf_command
stock = image/'usr/sbin/dnsmasq'
suite.ROOT = output.parent.parent
original = suite.subprocess.Popen
def popen(argv, *args, **kwargs):
    if isinstance(argv, list) and argv and str(argv[0]) == str(stock):
        argv = image_elf_command(image, stock) + argv[1:]
    return original(argv, *args, **kwargs)
suite.subprocess.Popen = popen
sys.argv = [str(source/'tools/dnsmasq/dns_hosts_generation_diff.py'), '--c', str(stock), '--rust', str(rust), '--out', str(output), '--reference-build', str(reference)]
suite.main()
