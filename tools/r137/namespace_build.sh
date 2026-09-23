#!/bin/bash
# Called only inside a private mount/PID namespace by build_batch.py.
set -euo pipefail
builder=$1 src=$2 out=$3 fixed=$4 private=$5 host_namespace=$6
parent=$(dirname "$fixed")
[[ $(id -u) == 0 && "$fixed" == /tmp/owrt-build/r135/r136-combined-01 ]]
[[ $(readlink /proc/self/ns/mnt) != "$host_namespace" ]]
[[ $(findmnt --noheadings --output PROPAGATION /) == private ]]
[[ -d "$private" && -d "$parent" && ! -e "$out" ]]
mount --bind "$private" "$parent"
trap 'umount "$parent"' EXIT
cd /home/ubuntu
sudo -n -u ubuntu -- bash "$builder" "$src" "$out" "$fixed"
sudo -n -u ubuntu -- python3 - "$out" "$fixed" <<'PY'
import json
import os
from pathlib import Path
import sys

out, fixed = map(Path, sys.argv[1:])
fingerprints = {}
for path in sorted((out / "target").rglob("lib-owrt_ubus.json")):
    fingerprints[str(path.relative_to(out))] = json.loads(path.read_text())
with (out / "namespace.json").open("x") as stream:
    json.dump({"mount_namespace": os.readlink("/proc/self/ns/mnt"),
               "build_uid": os.geteuid(), "canonical_source_root": str(fixed.resolve()),
               "cargo_dependency_fingerprints": fingerprints}, stream, indent=2)
    stream.write("\n")
PY
