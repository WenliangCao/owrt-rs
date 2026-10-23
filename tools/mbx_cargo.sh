#!/bin/sh
# Cargo-shaped SDK entry: compiler identity queries stay truthful; all other
# commands use the shared cache. No compiler flags or arguments are rewritten.
set -eu
if [ "$#" = 1 ]; then
    case "$1" in -V|--version) exec cargo "$@" ;; esac
fi
# OpenWrt sets TMPDIR inside its long SDK build path. mbx places a Unix socket
# below it, so use the standard short root for mbx's private temporary session.
export TMPDIR=/tmp
exec mbx "$@"
