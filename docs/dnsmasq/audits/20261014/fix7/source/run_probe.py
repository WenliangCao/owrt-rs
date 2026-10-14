#!/usr/bin/env python3
"""Compile and execute the audit probe against the actual local wire.rs."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
WIRE = ROOT / "components/dnsmasq/src/dns/wire.rs"
SOURCE = ROOT / "components/dnsmasq/src/dns/cache_engine.rs"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix="dnsmasq-fix7-wire-probe-") as temporary:
    directory = Path(temporary)
    source = directory / "probe.rs"
    source.write_text((HERE / "wire_probe.rs").read_text().replace("__WIRE_PATH__", json.dumps(str(WIRE))))
    command = ["rustc", "--edition=2024", str(source), "-o", str(directory / "probe")]
    subprocess.run(command, check=True)
    run = subprocess.run([str(directory / "probe")], text=True, capture_output=True, check=True)
    result = {
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "compiler": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "command_template": ["rustc", "--edition=2024", "<temporary>/probe.rs", "-o", "<temporary>/probe"],
        "exit": run.returncode,
        "result": json.loads(run.stdout),
        "inputs": {str(p.relative_to(ROOT)): sha(p) for p in (WIRE, SOURCE, HERE / "wire_probe.rs", Path(__file__))},
        "generated_probe_sha256": sha(source),
    }
(HERE / "probe-result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
