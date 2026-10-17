#!/bin/sh
# Preparation only: compile the five exact original workload sources on Oracle.
# Usage: sh rebuild-workload.sh SDK_DIRECTORY NEW_OUTPUT_DIRECTORY
set -eu
sdk=$1
out=$2
sources=$(CDPATH= cd -- "$(dirname -- "$0")/workload-original" && pwd)
test ! -e "$out"
export STAGING_DIR="$sdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl"
cc="$STAGING_DIR/bin/aarch64-openwrt-linux-musl-gcc"
test -x "$cc"
mkdir "$out"
python3 - "$sources" <<'PY'
from pathlib import Path
import hashlib, json, sys
root = Path(sys.argv[1])
for item in json.loads((root / 'source-identity.json').read_text())['sources'].values():
    source = root / item['local_filename']
    assert hashlib.sha256(source.read_bytes()).hexdigest() == item['source_sha256'], source
PY
for name in m6a_loadgen m6a_upstream device_perf_resource_probe device_perf_netns nice10; do
    source=$name.c
    if [ "$name" = nice10 ]; then source=perf_opt_nice10.c; fi
    "$cc" -O2 -std=c11 -Wall -Wextra -Werror -static "$sources/$source" -o "$out/$name" > "$out/$name.build.stdout" 2> "$out/$name.build.stderr"
done
sha256sum "$cc" > "$out/compiler.sha256"
sha256sum "$out/m6a_loadgen" "$out/m6a_upstream" "$out/device_perf_resource_probe" "$out/device_perf_netns" "$out/nice10" > "$out/binaries.sha256"
