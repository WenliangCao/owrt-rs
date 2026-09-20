#!/bin/sh
set -eu
python3 private/r102/event-fanout/run.py > private/r102/event-fanout/run.log 2>&1
code=$?
printf '%s\n' "$code" > private/r102/event-fanout/run-exit
exit $code
