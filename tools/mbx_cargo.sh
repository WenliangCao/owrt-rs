#!/bin/sh
# Cargo-shaped SDK entry: compiler identity queries stay truthful; all other
# commands use the shared cache. No compiler flags or arguments are rewritten.
set -eu
if [ "$#" = 1 ]; then
    case "$1" in -V|--version) exec cargo "$@" ;; esac
fi
exec mbx "$@"
