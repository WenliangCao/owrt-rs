#!/bin/sh
# Companion to ci_build_image.sh: canonical standalone procd/ubusd/netifd.
# OWRT_CORE_INCLUDE_ODHCPD=1 adds an independent diagnostic candidate. Default
# output remains the three inputs required by the qualified native-ten image.
# Building an ELF does not qualify it for release integration or deployment.
set -eu
ver=${OPENWRT_VERSION:?set OPENWRT_VERSION}
case ${OWRT_CORE_INCLUDE_ODHCPD:-0} in
    0) components='procd ubusd netifd' ;;
    1) components='procd ubusd netifd odhcpd' ;;
    *) echo 'OWRT_CORE_INCLUDE_ODHCPD must be 0 or 1' >&2; exit 2 ;;
esac
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(cd "${1:?usage: ci_build_core.sh WORKDIR}" && pwd)
out=$work/out
mkdir -p "$out/core-binaries"
finish_core_build() {
    core_build_status=$?
    trap - EXIT
    python3 "$repo/tools/ci_check_core.py" warnings "$out/core-recipe-warnings.json" "$out"/*.log || core_build_status=1
    exit "$core_build_status"
}
trap finish_core_build EXIT
set -- "$work"/openwrt-sdk-"$ver"-*/staging_dir
[ "$#" = 1 ] && [ -d "$1" ] || { echo 'expected one verified SDK' >&2; exit 1; }
staging=$1
set -- "$staging"/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc
[ "$#" = 1 ] && [ -x "$1" ] || { echo 'expected one target compiler' >&2; exit 1; }
linker=$1
channel=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
export RUSTUP_TOOLCHAIN=$channel
export CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
identity=$(sh "$repo/tools/toolchain_identity.sh")
printf '%s\n' "$identity" > "$out/core-toolchain.log"
SDK=$staging sh "$repo/tools/check_abi.sh" > "$out/core-abi.log" 2>&1
commit=$(git -C "$repo" rev-parse HEAD)
epoch=$(git -C "$repo" show -s --format=%ct HEAD)

for component in $components; do
    # Cargo includes path-dependency identities in its metadata. Keep these
    # source locations fixed across CI runs, independently of the checkout.
    build=/tmp/owrt-core-release/$component
    mkdir -p "$build"
    dependencies="$component ubus uci platform"
    # odhcpd reuses netifd's reviewed netlink boundary through a path dependency.
    [ "$component" != odhcpd ] || dependencies="$dependencies netifd"
    for dependency in $dependencies; do
        mkdir -p "$build/$dependency"
        rsync -a --delete --exclude target "$repo/components/$dependency/" "$build/$dependency/"
    done
    target=$work/core-target/$component
    CARGO_BUILD_TARGET=aarch64-unknown-linux-musl \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$linker" \
    STAGING_DIR="$staging" \
    RUSTFLAGS="-Dwarnings --remap-path-prefix=$build=/build --remap-path-prefix=$CARGO_HOME=/cargo -Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs" \
    cargo build --locked --release --bins --manifest-path "$build/$component/Cargo.toml" \
        --target-dir "$target" > "$out/build-core-$component.log" 2>&1 \
        || { tail -40 "$out/build-core-$component.log"; exit 1; }
    install -m 755 "$target/aarch64-unknown-linux-musl/release/$component-rs" "$out/core-binaries/$component-rs"
done
set --
for component in $components; do set -- "$@" "$component-rs"; done
(cd "$out/core-binaries" && sha256sum "$@") > "$out/core-binary-sha256.txt"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
    -cf "$work/core-binaries.tar" -C "$out/core-binaries" "$@"
gzip -n -c "$work/core-binaries.tar" > "$out/core-binaries.tar.gz"
python3 - "$out" "$commit" "$ver" "$staging" "$@" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import tarfile

out, commit, version, staging, *binaries = sys.argv[1:]
out = Path(out)
image = json.loads((out / "manifest.json").read_text())
assert image["source_commit"] == commit and image["openwrt"] == version
expected = set(binaries)
hashes = {name: digest for digest, name in
          (line.split() for line in (out / "core-binary-sha256.txt").read_text().splitlines())}
assert set(hashes) == expected
archive = out / "core-binaries.tar.gz"
with tarfile.open(archive) as tar:
    members = tar.getmembers()
    assert len(members) == len(expected) and {m.name for m in members} == expected
    for member in members:
        assert member.isfile() and member.mode & 0o111
        assert hashlib.sha256(tar.extractfile(member).read()).hexdigest() == hashes[member.name]
manifest = {
    "source_commit": commit,
    "openwrt": version,
    "target": "aarch64-unknown-linux-musl",
    "sdk": Path(staging).parent.name,
    "binary_sha256": hashes,
    "archive": {"file": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()},
    "image_manifest_sha256": hashlib.sha256((out / "manifest.json").read_bytes()).hexdigest(),
    "toolchain_identity_sha256": hashlib.sha256((out / "core-toolchain.log").read_bytes()).hexdigest(),
    "deployment": "Standalone binaries; not activated by the generated image or by artifact creation.",
    "flashed": False,
}
(out / "core-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest, indent=2))
PY
