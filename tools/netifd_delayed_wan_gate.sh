#!/bin/bash
# Build-host-only regression gate, including independent C lifecycle checks.
set -eu
root=$1; candidate=$2; out=$3
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
. "$here/netifd_test_ns.sh"
netifd_test_ns_init "$here" "$out"
python3 "$here/netifd_delayed_wan_probe.py" "$root" "$candidate" \
    "$NETIFD_TEST_NS_EXEC" "$out/results" --gate
