#!/bin/sh
# Select static PIE startup objects for the pinned Rust musl target.
#
# rustc links aarch64-unknown-linux-musl with one explicit -static and its own
# self-contained crt1.o/crtbegin.o/crtend.o. Replace exactly those three with
# their PIE variants and -static with -static-pie; every other argument is
# passed through unchanged to the SDK compiler named by DNSMASQ_STATIC_PIE_CC.
set -eu

fail() {
    echo "static-pie-linker: $*" >&2
    exit 1
}

cc=${DNSMASQ_STATIC_PIE_CC:-}
case $cc in
    /*) ;;
    *) fail "DNSMASQ_STATIC_PIE_CC must name the actual SDK compiler" ;;
esac
if [ ! -f "$cc" ] || [ ! -x "$cc" ] || [ "$(readlink -f "$cc")" = "$(readlink -f "$0")" ]; then
    fail "DNSMASQ_STATIC_PIE_CC must name the actual SDK compiler"
fi

statics=0
for arg do
    case $arg in
        -static) statics=$((statics + 1)) ;;
        -pie | -static-pie | -shared | @*) statics=2 ;;
    esac
done
[ "$statics" = 1 ] || fail "expected one explicit -static link without PIE/shared flags or response files"

count=$#
seen=" "
for arg do
    case $arg in
        -static) set -- "$@" -static-pie; continue ;;
        -no-pie) continue ;;
    esac
    name=${arg##*/}
    case $name in
        crt1.o) replacement=rcrt1.o ;;
        crtbegin.o) replacement=crtbeginS.o ;;
        crtend.o) replacement=crtendS.o ;;
        *) set -- "$@" "$arg"; continue ;;
    esac
    directory=${arg%/*}
    case " $seen " in *" $name "*) fail "expected one of each pinned Rust self-contained startup object" ;; esac
    case $directory in
        "$arg") fail "expected one of each pinned Rust self-contained startup object" ;;
        rustlib/aarch64-unknown-linux-musl/lib/self-contained | */rustlib/aarch64-unknown-linux-musl/lib/self-contained) ;;
        *) fail "expected one of each pinned Rust self-contained startup object" ;;
    esac
    [ -f "$arg" ] || fail "expected one of each pinned Rust self-contained startup object"
    [ -f "$directory/$replacement" ] || fail "missing static PIE startup object: $directory/$replacement"
    seen="$seen$name "
    set -- "$@" "$directory/$replacement"
done
shift "$count"
for required in crt1.o crtbegin.o crtend.o; do
    case $seen in *" $required "*) ;; *) fail "missing pinned Rust crt1/crtbegin/crtend inputs" ;; esac
done
exec "$cc" "$@"
