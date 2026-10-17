#!/bin/sh
# Build an immutable source snapshot using a shared, locked Oracle cache.
# Usage: sh oracle_build.sh SOURCE FRESH_PRIVATE_OUTPUT [release|tests|ubus-tests|probe-tests|primitive-probes|fuzz]
# ORACLE_BUILD_TARGET_DIR may explicitly select a different absolute cache path.
set -eu
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || exit 2
source_dir=$(realpath "$1")
output_dir=$(realpath -m "$2")
build_kind=${3:-release}
case "$output_dir" in /home/ubuntu/*/private/*) ;; *) echo 'private output required' >&2; exit 2;; esac
[ ! -e "$output_dir" ] || { echo 'fresh output required' >&2; exit 2; }
[ -f "$source_dir/components/dnsmasq/Cargo.toml" ] || exit 2
case "$source_dir" in *' '*) echo 'source path contains whitespace' >&2; exit 2;; esac
case "$build_kind" in release|tests|ubus-tests|probe-tests|primitive-probes|fuzz) ;; *) exit 2;; esac
package_name=dnsmasq-rs
manifest_path="$source_dir/components/dnsmasq/Cargo.toml"
if [ "$build_kind" = ubus-tests ]; then
    package_name=owrt-ubus
    manifest_path="$source_dir/components/ubus/Cargo.toml"
fi
case ${ORACLE_BUILD_TARGET_DIR-/home/ubuntu/dnsmasq-cargo-target} in
    /*) ;;
    *) echo 'ORACLE_BUILD_TARGET_DIR must be an absolute path' >&2; exit 2;;
esac
export CARGO_TARGET_DIR=$(realpath -m "${ORACLE_BUILD_TARGET_DIR-/home/ubuntu/dnsmasq-cargo-target}")
mkdir -p "$CARGO_TARGET_DIR" "$output_dir"
# Keep artifact copying inside the lock: another build must not replace a
# shared output between Cargo returning and the immutable copy being saved.
exec 9>"$CARGO_TARGET_DIR/.dnsmasq-build.lock"
flock 9
if [ "$build_kind" = fuzz ]; then
    # Instrumented fuzz ELFs are separate native artifacts from the same source.
    # Build in an output-owned copy so Cargo.lock/corpus never alter the freeze.
    mkdir -p "$output_dir/input/components"
    cp -R "$source_dir/components/dnsmasq" "$source_dir/components/ubus" "$output_dir/input/components/"
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
    unset CARGO_BUILD_TARGET RUSTUP_TOOLCHAIN
    export CARGO_PROFILE_RELEASE_OPT_LEVEL=3
    cargo=/home/ubuntu/.cargo/bin/cargo
    fuzz_manifest="$output_dir/input/components/dnsmasq/fuzz/Cargo.toml"
    "$cargo" +nightly clean --manifest-path "$fuzz_manifest" \
        --package dnsmasq-rs --package dnsmasq-fuzz --package owrt-ubus \
        --target aarch64-unknown-linux-gnu --release \
        >"$output_dir/clean.stdout" 2>"$output_dir/clean.log"
    for fuzz_target in dns_wire dhcp_packet config_line; do
        "$cargo" +nightly fuzz build "$fuzz_target" --fuzz-dir "$(dirname "$fuzz_manifest")" \
            --target aarch64-unknown-linux-gnu --target-dir "$CARGO_TARGET_DIR" \
            >"$output_dir/$fuzz_target.build.stdout" 2>"$output_dir/$fuzz_target.build.log"
        cp "$CARGO_TARGET_DIR/aarch64-unknown-linux-gnu/release/$fuzz_target" "$output_dir/$fuzz_target"
    done
    "$cargo" +nightly -V >"$output_dir/cargo-version"
    "$cargo" +nightly fuzz -V >"$output_dir/cargo-fuzz-version"
    /home/ubuntu/.cargo/bin/rustc +nightly -Vv >"$output_dir/rustc-version"
    python3 - "$source_dir" "$output_dir" <<'PY'
import hashlib, json, os, pathlib, sys
source, out = map(pathlib.Path, sys.argv[1:])
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
files = {str(path.relative_to(source)): digest(path)
         for component in ('dnsmasq', 'ubus')
         for path in (source / 'components' / component).rglob('*')
         if path.is_file() and 'target' not in path.parts
         and path != source / 'components/dnsmasq/fuzz/Cargo.lock'}
for name, expected in files.items():
    if digest(out / 'input' / name) != expected:
        raise RuntimeError(f'fuzz build changed a source input: {name}')
artifacts = [out / name for name in ('dns_wire', 'dhcp_packet', 'config_line')]
report = {'source': str(source), 'kind': 'fuzz', 'cargo_target_dir': os.environ['CARGO_TARGET_DIR'],
          'source_files': files, 'native_target': 'aarch64-unknown-linux-gnu', 'sanitizer': 'address',
          'cargo_version': (out / 'cargo-version').read_text().strip(),
          'cargo_fuzz_version': (out / 'cargo-fuzz-version').read_text().strip(),
          'rustc_version': (out / 'rustc-version').read_text().strip(),
          'fuzz_lock_sha256': digest(out / 'input/components/dnsmasq/fuzz/Cargo.lock'),
          'scope': 'instrumented native targets from frozen source; not the shipped musl ELF',
          'artifacts': [{'path': path.name, 'bytes': path.stat().st_size, 'sha256': digest(path)} for path in artifacts]}
(out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
PY
    exit 0
fi
toolchain=/home/ubuntu/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl
export STAGING_DIR="$toolchain"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$toolchain/bin/aarch64-openwrt-linux-musl-gcc"
export RUSTFLAGS="--remap-path-prefix=$source_dir=/build -Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Cforce-unwind-tables=no"
if [ "$build_kind" = release ]; then
    # Keep the shipped daemon static and select the matching PIE startup.
    # Test and diagnostic binaries retain their existing static linkage.
    export DNSMASQ_STATIC_PIE_CC="$CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$source_dir/packaging/openwrt/owrt-dnsmasq/static-pie-linker.py"
    export RUSTFLAGS="$RUSTFLAGS -Crelocation-model=pie -Ctarget-feature=+crt-static"
fi
# Optional fault/attribution evidence. Only this fresh output can receive the
# map; it stays outside shipped artifacts and under the same build lock.
case ${ORACLE_BUILD_LINK_MAP:-0} in
    0) ;;
    1) case "$output_dir" in *' '*|*','*) echo 'map output path contains whitespace or comma' >&2; exit 2;; esac
       export RUSTFLAGS="$RUSTFLAGS -Clink-arg=-Wl,-Map=$output_dir/link.map" ;;
    *) echo 'ORACLE_BUILD_LINK_MAP must be 0 or 1' >&2; exit 2;;
esac
unset CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
case ${ORACLE_BUILD_OPT_LEVEL:-3} in
    3|s|z) export CARGO_PROFILE_RELEASE_OPT_LEVEL=${ORACLE_BUILD_OPT_LEVEL:-3} ;;
    *) echo 'ORACLE_BUILD_OPT_LEVEL must be 3, s or z' >&2; exit 2;;
esac
feature_args=""
if [ -n "${ORACLE_BUILD_FEATURES:-}" ]; then
    case "$ORACLE_BUILD_FEATURES" in
        m6b-diagnostics) feature_args="--features $ORACLE_BUILD_FEATURES" ;;
        *) echo 'ORACLE_BUILD_FEATURES contains an unsupported feature' >&2; exit 2 ;;
    esac
fi
if [ "$build_kind" = probe-tests ] || [ "$build_kind" = primitive-probes ]; then
    [ "$CARGO_PROFILE_RELEASE_OPT_LEVEL" = 3 ] && [ -z "$feature_args" ] || {
        echo 'primitive/probe builds require opt3 and feature-off' >&2; exit 2;
    }
    if [ "$build_kind" = primitive-probes ]; then
        for probe_name in m6b-cache-core m6b-cache-policy m6b-cache-edns m6b-cache-lease; do
            [ -f "$source_dir/components/dnsmasq/examples/$probe_name.rs" ] || {
                echo 'all four allowlisted primitive examples must be prepared' >&2; exit 2;
            }
        done
    fi
    python3 - "$source_dir" "$output_dir" "$build_kind" <<'PY'
import hashlib, json, pathlib, sys
source, out = map(pathlib.Path, sys.argv[1:3])
files = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
         for part in ('dnsmasq', 'ubus') for p in sorted((source / 'components' / part).rglob('*'))
         if p.is_file() and 'target' not in p.relative_to(source).parts}
if sys.argv[3] == 'primitive-probes':
    extra = [source / name for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml')]
    extra += sorted((source / '.cargo').rglob('*'))
    for path in extra:
        if path.is_file():
            files[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
(out / 'probe-source-before.json').write_text(json.dumps(files, sort_keys=True) + '\n')
PY
fi
cargo=/home/ubuntu/.cargo/bin/cargo
# Git archives preserve historical mtimes. Reusing a fixed source path can
# otherwise make Cargo accept stale package artifacts after the input changes.
# Keep dependency caches, but invalidate this package inside the copy lock.
if [ "$build_kind" = release ] || [ "$build_kind" = probe-tests ] || [ "$build_kind" = primitive-probes ]; then
    "$cargo" +1.98.1 clean --manifest-path "$manifest_path" \
        --package "$package_name" --target aarch64-unknown-linux-musl --release \
        >"$output_dir/clean.stdout" 2>"$output_dir/clean.log"
else
    "$cargo" +1.98.1 clean --manifest-path "$manifest_path" \
        --package "$package_name" --target aarch64-unknown-linux-musl --profile dev \
        >"$output_dir/clean.stdout" 2>"$output_dir/clean.log"
fi
if [ "$build_kind" = release ]; then
    "$cargo" +1.98.1 build --release --frozen --target aarch64-unknown-linux-musl \
        --manifest-path "$source_dir/components/dnsmasq/Cargo.toml" --bin dnsmasq-rs $feature_args \
        >"$output_dir/build.stdout" 2>"$output_dir/build.log"
    cp "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/dnsmasq-rs" "$output_dir/dnsmasq-rs"
elif [ "$build_kind" = tests ]; then
    "$cargo" +1.98.1 test --frozen --target aarch64-unknown-linux-musl \
        --manifest-path "$source_dir/components/dnsmasq/Cargo.toml" --lib --bin dnsmasq-rs \
        --no-run --message-format=json >"$output_dir/build.stdout" 2>"$output_dir/build.log"
elif [ "$build_kind" = primitive-probes ]; then
    # Four source-bound actual-crate bridges. No main product or harness runs;
    # only the allowlisted example binaries are copied under the shared lock.
    "$cargo" +1.98.1 build --release --frozen --target aarch64-unknown-linux-musl \
        --manifest-path "$manifest_path" \
        --example m6b-cache-core --example m6b-cache-policy \
        --example m6b-cache-edns --example m6b-cache-lease --message-format=json \
        >"$output_dir/build.stdout" 2>"$output_dir/build.log"
elif [ "$build_kind" = probe-tests ]; then
    # Diagnostic-only ignored lib tests use the same release settings, target,
    # copy lock and source invalidation. Nothing executes inside this build.
    "$cargo" +1.98.1 test --release --frozen --target aarch64-unknown-linux-musl \
        --manifest-path "$manifest_path" --lib --no-run --message-format=json \
        >"$output_dir/build.stdout" 2>"$output_dir/build.log"
else
    "$cargo" +1.98.1 test --frozen --target aarch64-unknown-linux-musl \
        --manifest-path "$manifest_path" --lib \
        --no-run --message-format=json >"$output_dir/build.stdout" 2>"$output_dir/build.log"
fi
python3 - "$source_dir" "$output_dir" "$build_kind" <<'PY'
import hashlib, json, os, pathlib, shutil, sys
source, out, kind = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
artifacts = [out / 'dnsmasq-rs'] if kind == 'release' else []
if kind in ('tests', 'ubus-tests', 'probe-tests'):
    for line in (out / 'build.stdout').read_text().splitlines():
        row = json.loads(line)
        if row.get('reason') != 'compiler-artifact' or not row.get('executable'):
            continue
        if not row.get('profile', {}).get('test'):
            continue
        target = row['target']
        path = out / (target['kind'][0] + '-' + target['name'])
        shutil.copy2(row['executable'], path)
        artifacts.append(path)
    expected = 2 if kind == 'tests' else 1
    if len(artifacts) != expected:
        raise RuntimeError(f'expected {expected} test executable(s)')
if kind == 'primitive-probes':
    allowed = {'m6b-cache-core', 'm6b-cache-policy', 'm6b-cache-edns', 'm6b-cache-lease'}
    seen = set()
    for line in (out / 'build.stdout').read_text().splitlines():
        row = json.loads(line)
        if row.get('reason') != 'compiler-artifact' or not row.get('executable'):
            continue
        target = row['target']
        name = target['name']
        if target.get('kind') != ['example'] or name not in allowed or row.get('profile', {}).get('test'):
            raise RuntimeError('unexpected executable in primitive build')
        if name in seen:
            raise RuntimeError('duplicate primitive executable')
        seen.add(name)
        path = out / name
        shutil.copy2(row['executable'], path)
        artifacts.append(path)
    if seen != allowed:
        raise RuntimeError('missing allowlisted primitive executable')
report = {'source': str(source), 'kind': kind, 'cargo_target_dir': os.environ['CARGO_TARGET_DIR'],
          'opt_level': os.environ['CARGO_PROFILE_RELEASE_OPT_LEVEL'],
          'features': os.environ.get('ORACLE_BUILD_FEATURES', ''),
          'rustflags': os.environ['RUSTFLAGS'], 'artifacts': [
              {'path': path.name, 'bytes': path.stat().st_size,
               'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in artifacts]}
if kind in ('probe-tests', 'primitive-probes'):
    before = out / 'probe-source-before.json'
    files = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
             for part in ('dnsmasq', 'ubus') for p in sorted((source / 'components' / part).rglob('*'))
             if p.is_file() and 'target' not in p.relative_to(source).parts}
    if kind == 'primitive-probes':
        extra = [source / name for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml')]
        extra += sorted((source / '.cargo').rglob('*'))
        for path in extra:
            if path.is_file():
                files[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if files != json.loads(before.read_text()):
        raise RuntimeError('diagnostic source changed during locked build')
    report['source_files'] = files
    report['source_before_sha256'] = hashlib.sha256(before.read_bytes()).hexdigest()
    report['diagnostic_only'] = True
if (out / 'link.map').exists():
    report['link_map'] = {'path': 'link.map',
                         'sha256': hashlib.sha256((out / 'link.map').read_bytes()).hexdigest()}
(out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
PY
