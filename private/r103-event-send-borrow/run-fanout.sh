#!/bin/sh
set -eu
python3 private/r103-event-send-borrow/run-fanout.py > private/r103-event-send-borrow/fanout.log 2>&1
code=$?; echo "$code" > private/r103-event-send-borrow/fanout-exit; exit "$code"
