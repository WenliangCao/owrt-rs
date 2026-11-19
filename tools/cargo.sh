#!/bin/sh
# SDK entry point: preserve compiler arguments and use the shared Cargo fork.
set -eu
if [ "$#" = 1 ]; then
    case "$1" in -V|--version) exec cargo "$@" ;; esac
fi
version=$(cargo -V)
case "$version" in
    *huacnlee/cargo*) ;;
    *) echo "expected huacnlee/cargo, got: $version" >&2; exit 1 ;;
esac
# Name the actual compiler, not the rustup proxy: shared Cargo metadata must
# distinguish simultaneous builds using different pinned Rust toolchains.
if [ -z "${RUSTC:-}" ]; then
    RUSTC=$(rustup which rustc)
    export RUSTC
fi
exec cargo "$@"
