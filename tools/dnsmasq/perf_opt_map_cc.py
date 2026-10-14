#!/usr/bin/env python3
"""Add only a linker map, after rustc/Cargo code-generation identities exist."""
import os
from pathlib import Path
import sys

cc=Path(os.environ['PERF_SDK_CC'])
assert cc.is_absolute() and cc.is_file()
args=sys.argv[1:]
if '-static-pie' in args:
    output=Path(os.environ['PERF_LINK_MAP'])
    assert output.is_absolute() and 'private' in output.parts
    args += ['-Wl,-Map='+str(output)]
os.execv(str(cc),[str(cc),*args])
