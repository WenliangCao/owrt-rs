#!/bin/sh
# Build the two test-only helpers r36 copies into the sandbox rootfs, using the
# OpenWrt SDK's target toolchain. OWRT_TEST_CC may explicitly select another
# Linux target compiler for these test-only helpers. The manifest records it.
# Output: $OUT/asuser, $OUT/busprobe and $OUT/manifest.json.
set -eu
OUT=${1:-/tmp/r36-helpers}
mkdir -p "$OUT"
here=$(cd "$(dirname "$0")" && pwd)
SDK=
if [ -n "${OWRT_TEST_CC:-}" ]; then
    test_cc=$(command -v "$OWRT_TEST_CC")
else
    SDK=$(ls -d /tmp/rustcp-sdk/extracted/openwrt-sdk-*/staging_dir ~/sdk/openwrt-sdk-*/staging_dir 2>/dev/null | head -1)
    [ -n "$SDK" ] || { echo "no OpenWrt SDK staging_dir found" >&2; exit 1; }
    test_cc=$(ls "$SDK"/toolchain-*/bin/aarch64-openwrt-linux-musl-gcc | head -1)
fi
for t in asuser busprobe; do
	env -u LD_PRELOAD STAGING_DIR="$SDK" "$test_cc" -static -O2 -o "$OUT/$t" "$here/testsrc/$t.c"
	echo "built $OUT/$t"
done
python3 - "$here" "$OUT" "$test_cc" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
source, out, compiler = map(Path, sys.argv[1:])
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
manifest = {"compiler": str(compiler), "compiler_sha256": sha(compiler),
            "compiler_version": subprocess.check_output([str(compiler), "--version"], text=True).splitlines()[0],
            "flags": ["-static", "-O2"], "test_only": True,
            "helpers": {name: {"source_sha256": sha(source / "testsrc" / (name + ".c")),
                               "binary_sha256": sha(out / name)} for name in ("asuser", "busprobe")}}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY
