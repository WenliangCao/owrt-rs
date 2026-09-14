#!/bin/sh
# netifd_suite creates OUTPUT; the probe requires its own fresh directory.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
python3 "$here/r91_netifd_logging.py" "$1" "$2" "$3/probe"
