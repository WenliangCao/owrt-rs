#!/usr/bin/env python3
"""Verify session expiry, deferred replies and fd cleanup under continuous RPCs.

Runs both implementations only in r17's disposable exact-image rootfs. Raw
output stays in the supplied private directory; this is not a timing benchmark.
"""
import argparse
import json
from pathlib import Path

import r17_rpcd_core_check as base


BUSY = r'''
set -eu
before=$(ls /proc/$core_pid/fd | wc -l)
touch /tmp/busy-run
loads=
for i in 1 2 3 4 5 6 7 8; do
    (
        count=0
        while [ -e /tmp/busy-run ]; do
            ubus -S -t 5 call session access '{"ubus_rpc_session":"00000000000000000000000000000000","scope":"ubus","object":"uci","function":"get"}' >/dev/null
            count=$((count + 1))
        done
        echo "$count" >/tmp/busy-count-$i
    ) &
    loads="$loads $!"
done
trap 'rm -f /tmp/busy-run; kill $loads 2>/dev/null || true' EXIT
ubus -S -t 10 call file exec '{"command":"/bin/sh","params":["-c","sleep 1; exit 17"]}' >/tmp/busy-exec.json &
worker=$!
sleep 3
rc=0
ubus -S -t 5 call session get '{"ubus_rpc_session":"@SIDT@"}' >/tmp/busy-expired.out 2>/tmp/busy-expired.err || rc=$?
[ "$rc" = 4 ]
wait "$worker"
[ "$(jsonfilter -i /tmp/busy-exec.json -e '@.code')" = 17 ]
ubus -S -t 5 call session list '{}' >/dev/null
rm /tmp/busy-run
for pid in $loads; do wait "$pid"; done
sleep 1
total=0
for i in 1 2 3 4 5 6 7 8; do
    count=$(cat /tmp/busy-count-$i)
    [ "$count" -gt 0 ]
    total=$((total + count))
done
after=$(ls /proc/$core_pid/fd | wc -l)
[ "$before" = "$after" ]
printf '{"expired_session_status":%s,"worker_exit":17,"load_requests":%s,"fds_before":%s,"fds_after":%s}\n' "$rc" "$total" "$before" "$after"
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs")
    parser.add_argument("candidate")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    base.STEPS.clear()
    base.cap("SIDT", "timer", "session", "create", {"timeout": 1})
    base.shx("busy", BUSY)
    summary = []
    for side in ("original", "candidate"):
        results, _, logs = base.run_side(args.rootfs, side, args.candidate)
        directory = args.output / side
        directory.mkdir(mode=0o700)
        for name, data in results.items():
            (directory / name).write_bytes(data)
        (directory / "logs.json").write_text(json.dumps(logs) + "\n")
        assert results["timer.rc"].strip() == b"0", side
        assert results["busy.rc"].strip() == b"0", (side, results["busy.err"])
        row = {"side": side, **json.loads(results["busy.out"])}
        assert row["expired_session_status"] == 4 and row["worker_exit"] == 17
        assert row["fds_before"] == row["fds_after"] and row["load_requests"] > 0
        summary.append(row)
        print(json.dumps(row), flush=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (args.output / "COMPLETE").touch()


if __name__ == "__main__":
    main()
