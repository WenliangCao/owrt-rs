#!/bin/sh
# Build the seven owrt-* apks and the xiaomi_mi-router-ax3000t sysupgrade image
# for one OpenWrt release, on any x86_64 Linux host (GitHub Actions or a laptop).
# Same recipe as tools/release.sh, but self-contained: no build host, no router.
#
#   OPENWRT_VERSION=25.12.5 sh tools/ci_build_image.sh [workdir]
#
# Needs: curl, tar+zstd, make, gcc, python3, rsync, file, device-tree-compiler,
# u-boot-tools, rustup with the
# toolchain in RUST_TOOLCHAIN (default: channel from rust-toolchain.toml) and
# target aarch64-unknown-linux-musl.
# Output: <workdir>/out/{owrt-*.apk, *-sysupgrade.bin, SHA256SUMS, manifest.json, *.log}
set -eu
ver=${OPENWRT_VERSION:?set OPENWRT_VERSION, e.g. 25.12.5}
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(cd "$(mkdir -p "${1:-$REPO/work}" && echo "${1:-$REPO/work}")" && pwd)
OUT=$WORK/out
TARGET=mediatek/filogic; ARCH=aarch64_cortex-a53; PROFILE=xiaomi_mi-router-ax3000t
BASE="https://downloads.openwrt.org/releases/$ver/targets/$TARGET"
PKGS="owrt-uci owrt-reload-config owrt-logd owrt-httpd owrt-fw4 owrt-rpcd owrt-switch"
PKGLIST=$REPO/packaging/image/packages-$ver.txt
RUST_TOOLCHAIN=${RUST_TOOLCHAIN:-$(sed -n 's/^channel = "\(.*\)"/\1/p' "$REPO/rust-toolchain.toml")}
CARGO=${CARGO:-"env RUSTUP_TOOLCHAIN=$RUST_TOOLCHAIN cargo"}
NPROC=$(nproc 2>/dev/null || echo 2)

log() { printf '\n== %s\n' "$*"; }
[ -f "$PKGLIST" ] || { echo "no package list for $ver: $PKGLIST (capture it with: ssh router 'apk info' | sort)" >&2; exit 1; }
mkdir -p "$WORK/dl" "$OUT"
rm -f "$OUT/sdk-downloads-verified"
finish_image_build() {
    image_build_status=$?
    trap - EXIT
    python3 "$REPO/tools/ci_check_core.py" warnings "$OUT/image-recipe-warnings.json" "$OUT"/*.log || image_build_status=1
    exit "$image_build_status"
}
trap finish_image_build EXIT

# Prove the compiler before downloading an SDK: a version problem should not
# surface an hour into a build. Same script the Makefile check uses, and its
# output is what the manifest records -- verified identity == recorded identity.
log "toolchain"
TOOLCHAIN_ID=$(CARGO="$CARGO" sh "$REPO/tools/toolchain_identity.sh")
echo "$TOOLCHAIN_ID"
tc() { echo "$TOOLCHAIN_ID" | sed -n "s/^$1=//p"; }
[ "$(tc official)" = yes ] || echo "WARNING: unofficial toolchain ($(tc override))" >&2

log "fetch SDK + ImageBuilder $ver"
cd "$WORK/dl"
curl -sSfLO "$BASE/sha256sums"
for f in $(grep -oE "openwrt-(sdk|imagebuilder)-$ver-[^ ]*\.tar\.(zst|xz)" sha256sums | sort -u); do
	[ -f "$f" ] || curl -sSfL -o "$f" "$BASE/$f"
done
grep -E 'openwrt-(sdk|imagebuilder)-' sha256sums | sha256sum -c
: > "$OUT/sdk-downloads-verified"
cd "$WORK"
for f in dl/openwrt-sdk-$ver-*.tar.* dl/openwrt-imagebuilder-$ver-*.tar.*; do
	d=$(basename "${f%.tar.*}")
	[ -d "$d" ] || tar -xf "$f"
done
SDK=$(ls -d "$WORK"/openwrt-sdk-$ver-*/ | head -1); SDK=${SDK%/}
IB=$(ls -d "$WORK"/openwrt-imagebuilder-$ver-*/ | head -1); IB=${IB%/}

# Only the AN8855 hardware revision is supported by this image. Keep the
# upstream DTB untouched; ImageBuilder consumes the prebuilt FIT, not that DTB.
# Run before compiling packages so changed upstream inputs fail immediately.
log "disable the absent MT7531 and append the AX3000T console level (AN8855 only)"
python3 - "$ver" "$IB" "$WORK" "$OUT" "$REPO" > "$OUT/ax3000t-fit.log" 2>&1 <<'FITPY' || { cat "$OUT/ax3000t-fit.log"; exit 1; }
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ver, ib, work, out, repo = sys.argv[1:]
ib, work, out = Path(ib), Path(work), Path(out)
linux = ib / "build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic"
fit = linux / "xiaomi_mi-router-ax3000t-kernel.bin"
dtb = linux / "image-mt7981b-xiaomi-mi-router-ax3000t.dtb"
its = fit.with_suffix(".bin.its")
node = "/soc/ethernet@15100000/mdio-bus/switch@1f"
# OpenWrt's fdt.c uses strlcat without adding a separator.
bootargs_append = " loglevel=4"

def require(condition, message):
    if not condition:
        raise SystemExit(message)

def sha(path, algorithm="sha256"):
    return hashlib.new(algorithm, path.read_bytes()).hexdigest()

def run(*args, env=None):
    return subprocess.check_output([str(arg) for arg in args], text=True, env=env)

versions = json.loads((Path(repo) / "packaging/image/ax3000t-fit-inputs.json").read_text())
require(ver in versions, "unqualified OpenWrt version for the AX3000T FIT patch")
inputs = versions[ver]
original_dtb = inputs["original_dtb_sha256"]
original_fit = inputs["original_fit_sha256"]
require(sha(dtb) == original_dtb, "unqualified AX3000T input DTB")
require(sha(fit) == original_fit, "unqualified AX3000T input FIT; use a fresh ImageBuilder")
require(sha(its) == inputs["original_its_sha256"],
        "unqualified AX3000T input ITS")
for tool in ("dumpimage", "fdtget", "fdtput", "dtc"):
    require(shutil.which(tool), f"missing {tool}: install device-tree-compiler and u-boot-tools")
require(run("fdtget", "-t", "s", dtb, node, "compatible").strip() == "mediatek,mt7531",
        "unexpected switch compatible")
require("status" not in run("fdtget", "-p", dtb, node).split(), "switch already has status")
require(not {"bootargs-append", "bootargs-override"}.intersection(
        run("fdtget", "-p", dtb, "/chosen").split()), "chosen already has a command-line override")
# Read the timestamp from the hash-pinned FIT itself, never from a copied file's mtime.
epoch = int(run("fdtget", "-t", "u", fit, "/", "timestamp").strip())
require(epoch == inputs["source_date_epoch"], "unexpected original FIT timestamp")
env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch))
mkimage = ib / "staging_dir/host/bin/mkimage"
with tempfile.TemporaryDirectory(prefix="ax3000t-fit-", dir=work) as tmp:
    tmp = Path(tmp)
    kernel, extracted, changed = tmp / "kernel.lzma", tmp / "original.dtb", tmp / "disabled.dtb"
    run("dumpimage", "-T", "flat_dt", "-p", "0", "-o", kernel, fit)
    run("dumpimage", "-T", "flat_dt", "-p", "1", "-o", extracted, fit)
    require(extracted.read_bytes() == dtb.read_bytes(), "FIT DTB differs from the pinned input DTB")
    kernel_sha1 = sha(kernel, "sha1")
    require(kernel_sha1 == inputs["kernel_payload_sha1"], "unexpected kernel payload")
    shutil.copyfile(extracted, changed)
    run("fdtput", "-t", "s", changed, node, "status", "disabled")
    run("fdtput", "-t", "s", changed, "/chosen", "bootargs-append", bootargs_append)
    require(run("fdtget", "-t", "s", changed, node, "status").strip() == "disabled",
            "switch was not disabled")
    require(run("fdtget", "-t", "s", changed, "/chosen", "bootargs-append").rstrip("\n") == bootargs_append,
            "console level was not appended with a separator")
    before = run("dtc", "-q", "-I", "dtb", "-O", "dts", extracted).splitlines(keepends=True)
    after = run("dtc", "-q", "-I", "dtb", "-O", "dts", changed).splitlines(keepends=True)
    changes = [op for op in difflib.SequenceMatcher(a=before, b=after, autojunk=False).get_opcodes()
               if op[0] != "equal"]
    expected_insertions = {("switch@1f {", 'status = "disabled";'),
                           ("chosen {", 'bootargs-append = " loglevel=4";')}
    require(len(changes) == 2, "DTB must have exactly two property insertions")
    actual_insertions = set()
    for kind, old_start, old_end, new_start, new_end in changes:
        require(kind == "insert" and old_start == old_end and new_end == new_start + 1,
                "DTB diff contains more than a property insertion")
        actual_insertions.add((before[old_start - 1].strip(), after[new_start].strip()))
    require(actual_insertions == expected_insertions, "unexpected DTB property insertion")
    print("".join(difflib.unified_diff(before, after, fromfile="original.dts", tofile="disabled.dts")))
    # The pinned upstream ITS supplies all FIT metadata. Replace only its two incbin paths.
    source = its.read_text()
    includes = re.findall(r'/incbin/\("([^"\n]+)"\)', source)
    require(len(includes) == 2, "unexpected ITS payload count")
    for original, replacement in zip(includes, (kernel, changed)):
        source = source.replace(f'/incbin/("{original}")', f'/incbin/("{replacement}")')
    new_its, new_fit = tmp / "disabled.its", tmp / "disabled.bin"
    new_its.write_text(source)
    print(run(mkimage, "-f", new_its, new_fit, env=env))
    print(run(mkimage, "-l", new_fit))
    require(int(run("fdtget", "-t", "u", new_fit, "/", "timestamp")) == epoch,
            "repacked FIT timestamp changed")
    kernel_check, dtb_check = tmp / "kernel-check.lzma", tmp / "dtb-check.dtb"
    run("dumpimage", "-T", "flat_dt", "-p", "0", "-o", kernel_check, new_fit)
    run("dumpimage", "-T", "flat_dt", "-p", "1", "-o", dtb_check, new_fit)
    require(kernel_check.read_bytes() == kernel.read_bytes() and sha(kernel_check, "sha1") == kernel_sha1,
            "repacked FIT changed the kernel payload")
    require(dtb_check.read_bytes() == changed.read_bytes(), "repacked FIT has the wrong DTB")
    record = dict(openwrt=ver, change="disable-absent-mt7531-and-quiet-console", hardware_variant="AN8855-only", node=node,
                  bootargs_append=bootargs_append,
                  status="disabled", source_date_epoch=epoch, kernel_payload_sha1=kernel_sha1,
                  original_dtb_sha256=original_dtb, original_fit_sha256=original_fit,
                  dtb_sha256=sha(changed), fit_sha256=sha(new_fit))
    # Install only after every check succeeds. Preserve the source epoch explicitly.
    new_fit.chmod(fit.stat().st_mode & 0o777)
    os.utime(new_fit, (epoch, epoch))
    os.replace(new_fit, fit)
    (out / "ax3000t-fit.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
FITPY
cat "$OUT/ax3000t-fit.log"

log "toolchain"
rustup toolchain list | grep -q "^$RUST_TOOLCHAIN" || rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
rustup target add --toolchain "$RUST_TOOLCHAIN" aarch64-unknown-linux-musl
$CARGO --version

log "build apks in $SDK"
for p in $PKGS; do rsync -a --delete "$REPO/packaging/openwrt/$p/" "$SDK/package/$p/"; done
cd "$SDK"
[ -f .config ] || make defconfig >"$OUT/sdk-defconfig.log" 2>&1 || true
for p in $PKGS; do
	echo "-- $p"
	make "package/$p/compile" V=s -j1 \
		V1_CARGO="$CARGO" V1_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" V1_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
		OWRT_COMPONENTS_SOURCE="$REPO/components" RELOAD_CONFIG_RS_SOURCE="$REPO/components/reload-config" \
		${V1_PACKAGE_RELEASE:+V1_PACKAGE_RELEASE=$V1_PACKAGE_RELEASE} > "$OUT/build-$p.log" 2>&1 \
		|| { tail -40 "$OUT/build-$p.log"; exit 1; }
done
cp "$SDK/bin/packages/$ARCH/base"/owrt-*.apk "$OUT/"
ls -la "$OUT"/owrt-*.apk

log "image in $IB"
rm -rf "$WORK/files"; mkdir -p "$WORK/files/etc"
for c in uci reload-config logd httpd fw4 rpcd; do : > "$WORK/files/etc/owrt-$c.boot-enable"; done
mkdir -p "$IB/packages"; rm -f "$IB/packages"/owrt-*.apk "$IB/packages/packages.adb"
cp "$OUT"/owrt-*.apk "$IB/packages/"
pkgs=$(tr '\n' ' ' < "$PKGLIST")
cd "$IB"
make image PROFILE="$PROFILE" PACKAGES="$pkgs" FILES="$WORK/files" \
	DISABLED_SERVICES='rpcd uhttpd log' ADD_LOCAL_KEY=1 BIN_DIR="$WORK/bin" -j"$NPROC" > "$OUT/image.log" 2>&1 \
	|| { tail -60 "$OUT/image.log"; exit 1; }
img=$(ls "$WORK/bin"/*"$PROFILE"*-squashfs-sysupgrade.bin)
cp "$img" "$OUT/"
[ -f "$WORK/bin/profiles.json" ] && cp "$WORK/bin/profiles.json" "$OUT/" || true

log "offline validation"
cd "$WORK"; rm -rf verify; mkdir verify; cd verify
tar -xf "$img"
# the sysupgrade tar unpacks into sysupgrade-<profile>/{CONTROL,kernel,root}
sq=$(find . -type f -name root | head -1)
[ -n "$sq" ] || { echo "no root squashfs inside the sysupgrade tar"; find . -type f; exit 1; }
ls -la "$(dirname "$sq")"
UNSQ=$(command -v unsquashfs || ls "$IB"/staging_dir/host/bin/unsquashfs4 2>/dev/null | head -1 || true)
if [ -n "$UNSQ" ]; then
	# device nodes in the rootfs need root to recreate; GitHub runners have passwordless sudo
	SUDO=""; [ "$(id -u)" = 0 ] || ! command -v sudo >/dev/null || SUDO="sudo -n"
	$SUDO "$UNSQ" -n -d rootfs "$sq" >/dev/null || $SUDO "$UNSQ" -n -ig -d rootfs "$sq" >/dev/null
	fail=0
	for p in $PKGS; do ls rootfs/lib/apk/packages/ 2>/dev/null | grep -q "^$p\.list$" || { echo "MISSING package $p"; fail=1; }; done
	for c in uci reload-config logd httpd fw4 rpcd; do [ -f "rootfs/etc/owrt-$c.boot-enable" ] || { echo "MISSING marker $c"; fail=1; }; done
	for s in rpcd uhttpd log; do ls rootfs/etc/rc.d/ | grep -q "^S..$s$" && { echo "service $s NOT disabled"; fail=1; }; done
	for b in uci-rs fw4-rs reload_config_rs logd-rs httpd-rs rpcd-rs; do [ -x "rootfs/usr/sbin/$b" ] || { echo "MISSING binary $b"; fail=1; }; done
	ls rootfs/etc/apk/keys/ | grep -q . || { echo "MISSING local apk key"; fail=1; }
	ls rootfs/etc/rc.d/ | grep -E "owrt" | tr "\n" " "; echo
	[ $fail = 0 ] && echo "image content OK: 7 packages, 6 markers, 3 services disabled, local key present"
	[ $fail = 0 ] || exit 1
	# Provenance anchor: hash the shipped binaries themselves. APK and image
	# hashes also cover packaging metadata; these six are the code that runs.
	# Reproducible only on the canonical builder (decision 0018) -- cargo hashes
	# the host triple into build-script crates' -C metadata, which reaches symbol
	# names and therefore the layout of anything linking ring/rustls.
	(cd rootfs/usr/sbin && sha256sum uci-rs fw4-rs reload_config_rs logd-rs httpd-rs rpcd-rs) > "$OUT/binary-sha256.txt"
	cat "$OUT/binary-sha256.txt"
else
	echo "unsquashfs not available; content check skipped"
fi

log "manifest"
cd "$OUT"
sha256sum owrt-*.apk *-sysupgrade.bin > SHA256SUMS
# Identity comes from the verified TOOLCHAIN_ID above, not from a fresh lookup
# of whatever happens to be on PATH after the build.
gcc=$(ls "$SDK"/staging_dir/toolchain-*/bin/*-openwrt-linux-*gcc 2>/dev/null | head -1)
gcc_id=$([ -n "$gcc" ] && "$gcc" --version 2>/dev/null | head -1 || echo unknown)
lockhash=$(cd "$REPO/components" && sha256sum */Cargo.lock 2>/dev/null | sha256sum | cut -d" " -f1)
python3 - "$ver" "$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)" \
	"$(tc rustc_verbose)" "$(tc cargo_version)" "$gcc_id" "$lockhash" "$RUST_TOOLCHAIN" \
	"$(tc official)" "$(tc override)" <<'EOF'
import json, os, sys, hashlib, re
ver, commit, rustc_id, cargo_id, gcc_id, lockhash, toolchain, official, override = sys.argv[1:10]
sums = dict(line.split()[::-1] for line in open("SHA256SUMS") if line.strip())
# the six shipped binaries, when the rootfs could be unpacked (see decision 0018)
binsums = {}
if os.path.exists("binary-sha256.txt"):
    binsums = {n: h for h, n in (l.split() for l in open("binary-sha256.txt") if l.strip())}
pkgs = {}
for f in sorted(sums):
    m = re.match(r"(owrt-[a-z0-9-]+)-(\d+\.\d+\.\d+-r\d+)\.apk$", f)
    if m:
        pkgs[m.group(1)] = m.group(2)
expected_pkgs = {"owrt-uci", "owrt-fw4", "owrt-reload-config", "owrt-logd",
                 "owrt-httpd", "owrt-rpcd", "owrt-switch"}
if set(pkgs) != expected_pkgs:
    raise SystemExit(f"incomplete package version manifest: {sorted(pkgs)}")
img = [f for f in sums if f.endswith("-sysupgrade.bin")][0]
json.dump({"openwrt": ver, "profile": "xiaomi_mi-router-ax3000t", "source_commit": commit,
           "ax3000t_fit": json.load(open("ax3000t-fit.json")),
           "packages": pkgs, "image": {"file": img, "size": os.path.getsize(img), "sha256": sums[img]},
           "apk_sha256": {f: s for f, s in sums.items() if f.endswith(".apk")},
           "binary_sha256": binsums,
           "imagebuilder_args": {"DISABLED_SERVICES": "rpcd uhttpd log", "ADD_LOCAL_KEY": 1,
                                 "FILES": "etc/owrt-{uci,reload-config,logd,httpd,fw4,rpcd}.boot-enable"},
           "toolchain": {"requested": toolchain, "rustc": rustc_id.strip("; "),
                         "cargo": cargo_id, "target_gcc": gcc_id,
                         "target": "aarch64-unknown-linux-musl",
                         "cargo_lock_sha256": lockhash,
                         "official": official == "yes",
                         "override": override or None},
           "flashed": False}, open("manifest.json", "w"), indent=1)
print(open("manifest.json").read())
EOF
cat SHA256SUMS
