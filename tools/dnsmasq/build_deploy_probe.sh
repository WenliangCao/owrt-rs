#!/bin/sh
# Oracle only: build a static helper with the exact image's SDK musl toolchain.
# Usage: sh build_deploy_probe.sh SOURCE_ROOT FRESH_PRIVATE_OUTPUT
set -eu
[ "$#" = 2 ] || exit 2
source_dir=$(realpath "$1")
output_dir=$(realpath -m "$2")
case "$output_dir" in /home/ubuntu/*/private/*) ;; *) echo 'private output required' >&2; exit 2;; esac
[ ! -e "$output_dir" ] || { echo 'fresh output required' >&2; exit 2; }
toolchain=/home/ubuntu/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl
export STAGING_DIR="$toolchain"
compiler="$toolchain/bin/aarch64-openwrt-linux-musl-gcc"
mkdir -p "$output_dir"
"$compiler" -std=c11 -Os -static -s -Wall -Wextra -Werror \
    -D_FORTIFY_SOURCE=2 -fstack-protector-strong -ffunction-sections -fdata-sections \
    -Wl,--gc-sections,-z,relro,-z,now,-z,max-page-size=4096 \
    "$source_dir/tools/dnsmasq/deploy_probe.c" -o "$output_dir/dnsmasq-deploy-probe" \
    >"$output_dir/build.stdout" 2>"$output_dir/build.log"
"$compiler" --version >"$output_dir/compiler-version"
python3 - "$source_dir" "$output_dir" <<'PY'
import hashlib, json, pathlib, sys
source, output = map(pathlib.Path, sys.argv[1:])
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
artifact = output / 'dnsmasq-deploy-probe'
report = {
    'source_sha256': sha(source / 'tools/dnsmasq/deploy_probe.c'),
    'build_script_sha256': sha(source / 'tools/dnsmasq/build_deploy_probe.sh'),
    'compiler': (output / 'compiler-version').read_text().splitlines()[0],
    'target': 'aarch64-openwrt-linux-musl', 'static': True,
    'artifact_sha256': sha(artifact), 'artifact_bytes': artifact.stat().st_size,
}
(output / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
PY
