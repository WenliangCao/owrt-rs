#!/bin/sh
# Entry point for the explicit netifd differential suite.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$here/netifd_renewal_keep.py" --rootfs "$1" --candidate "$2" --out "$3/results"
