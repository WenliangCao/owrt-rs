#!/bin/sh
set -eu
python3 private/r101/libubus-client/run-cpu.py > private/r101/libubus-client/run-cpu.log 2>&1
code=$?
printf '%s\n' "$code" > private/r101/libubus-client/run-cpu-exit
exit "$code"
