#!/usr/bin/env python3
"""Reproduce the R92 stale-poll-index bug without running a daemon or device.

Usage: python3 run_logd_probe.py PATH_TO_R92_CHECKOUT
Requires cargo/rustc on PATH. Builds only in a temporary directory.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).resolve()
evidence = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix="owrt-logd-poll-review-") as directory:
    root = Path(directory)
    (root / "src").mkdir()
    shutil.copyfile(evidence / "logd_poll_index.rs", root / "src/main.rs")
    shutil.copyfile(source / "components/logd/src/ring.rs", root / "src/ring.rs")
    dependency = json.dumps(str(source / "components/ubus"))
    (root / "Cargo.toml").write_text(
        '[package]\nname="logd-poll-review"\nversion="0.1.0"\nedition="2021"\n'
        '[dependencies]\nowrt-ubus={path=' + dependency + '}\n'
    )
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(root / "target")
    subprocess.run(["cargo", "run", "--offline", "--quiet", "--manifest-path",
                    str(root / "Cargo.toml")], cwd=source, env=environment, check=True)
