#!/bin/sh
# Builds (incrementally) and runs the host-only owrt-tools binary.
# `owrt-tools.sh --path` prints the binary instead, for callers that run it
# under sudo or from an SDK recipe. Target and compiler-flag overrides of the
# calling build never reach this host build.
set -eu
repo=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
bin=$(env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS -u CARGO_BUILD_TARGET \
    -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER -u CARGO_BUILD_RUSTC_WRAPPER \
    cargo build --release --locked --quiet --manifest-path "$repo/tools/owrt-tools/Cargo.toml" \
    --message-format=json-render-diagnostics |
    sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -1)
[ -n "$bin" ] && [ -x "$bin" ] || { echo 'owrt-tools: the build produced no executable' >&2; exit 1; }
if [ "${1:-}" = --path ]; then
    printf '%s\n' "$bin"
    exit 0
fi
exec "$bin" "$@"
