#!/bin/sh
# All experimental DNS/DHCP/TFTP listeners live in a new network namespace.
# Usage (Linux): sudo -n sh run_isolated.sh COMMAND ARG...
set -eu
[ "$(uname -s)" = Linux ] || { echo 'Linux network namespace required' >&2; exit 1; }
exec unshare --net --mount --pid --fork --mount-proc sh -c '
    set -eu
    ip link set lo up
    export DNSMASQ_TEST_ISOLATED=1
    exec "$@"
' isolated "$@"
