#!/bin/sh
# Correctness only. Enter through r95_device_smoke.py, never on production /.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = reload-config ] && [ "$3" = rs ] || exit 125
bin=/tmp/bin/reload_config_rs
guard=/tmp/bin/guard
out=/tmp/out
sha256sum "$bin" > "$out/binary-sha256.txt"
# Both the bus and receiver live in this private namespace. The helper only
# implements service.event and cannot trigger production service reloads.
receiver=/tmp/bin/event-benchmark
[ -x "$receiver" ] || exit 125
sha256sum /sbin/ubusd /bin/ubus "$receiver" > "$out/protocol-identities.txt"
mkdir -p /var/run/ubus /tmp/.uci
/sbin/ubusd -s /var/run/ubus/ubus.sock > "$out/ubusd.log" 2>&1 & bus=$!
receiver_pid=
trap 'kill "${receiver_pid:-}" "$bus" 2>/dev/null || true' EXIT INT TERM
for attempt in 1 2 3 4 5; do
    [ -S /var/run/ubus/ubus.sock ] && break
    sleep 1
done
[ -S /var/run/ubus/ubus.sock ]
"$receiver" reload-fault-service /var/run/ubus/ubus.sock "$out/events" > "$out/receiver.log" 2>&1 & receiver_pid=$!
for attempt in 1 2 3 4 5; do
    [ -f "$out/events-ready" ] && break
    sleep 1
done
[ -f "$out/events-ready" ]

assert_baseline() {
    : > "$out/baseline-expected"
    for name in alpha beta; do
        if [ "${1:-}" = timeout ] && [ "$name" = alpha ]; then
            digest=d41d8cd98f00b204e9800998ecf8427e
        else
            digest=$(/sbin/uci show "$name" | md5sum | cut -c1-32)
        fi
        printf '%s  /var/run/config.check/%s\n' "$digest" "$name" >> "$out/baseline-expected"
    done
    cmp /var/run/config.md5 "$out/baseline-expected"
}

assert_no_repeat() {
    cp /var/run/config.md5 "$out/baseline-recovered"
    : > "$out/events.log"
    : > "$out/events-status"
    : > "$out/events-raw.jsonl"
    "$bin" --timeout-ms 1000 --trace-stderr > /dev/null 2> "$out/$1-repeat.trace"
    [ ! -s "$out/events.log" ]
    cmp /var/run/config.md5 "$out/baseline-recovered"
}

reset_case() {
    # These directories are tmpfs in the chroot established by isolated.sh.
    rm -f /etc/config/* /tmp/.uci/* /var/run/config.md5 /tmp/ready /tmp/release
    rm -rf /var/run/uci
    : > "$out/events-status"
    for name in alpha beta; do
        printf "config test 's'\n option value 'before'\n" > "/etc/config/$name"
    done
    "$bin" --trace-stderr > /dev/null 2> "$out/prime.trace"
    cp /var/run/config.md5 "$out/baseline-before"
    : > "$out/events.log"
    : > "$out/events-status"
    : > "$out/events-raw.jsonl"
    for name in alpha beta; do
        printf "config test 's'\n option value 'after'\n" > "/etc/config/$name"
    done
    case "$1" in
        config) lockfile=/etc/config/alpha ;;
        delta)
            printf "alpha.s.value='staged'\n" > /tmp/.uci/alpha
            lockfile=/tmp/.uci/alpha ;;
        override)
            mkdir /var/run/uci
            cp /etc/config/alpha /var/run/uci/alpha
            lockfile=/var/run/uci/alpha ;;
    esac
}

hold_lock() {
    mkfifo /tmp/ready /tmp/release
    (
        exec 9<"$lockfile"
        flock -x 9
        printf 'ready\n' > /tmp/ready
        IFS= read -r release < /tmp/release
    ) & holder=$!
    IFS= read -r ready < /tmp/ready
    [ "$ready" = ready ]
}

release_lock() {
    printf 'release\n' > /tmp/release
    wait "$holder"
    rm /tmp/ready /tmp/release
}

if [ -x /tmp/bin/before-rs ]; then
    reset_case config
    hold_lock
    if "$guard" 1 /tmp/bin/before-rs --timeout-ms 100 --trace-stderr > /dev/null 2> "$out/before.trace"; then
        status=0
    else status=$?; fi
    release_lock
    [ "$status" = 124 ]
    cmp /var/run/config.md5 "$out/baseline-before"
    [ ! -s "$out/events.log" ]
    printf 'before_config_lock: deadline exceeded; guard killed candidate (expected red)\n' >> "$out/results.txt"
fi

for kind in config delta override; do
    reset_case "$kind"
    hold_lock
    "$guard" 3 "$bin" --timeout-ms 100 --trace-stderr > /dev/null 2> "$out/$kind-timeout.trace"
    release_lock
    grep -q '"status":"timeout"' "$out/$kind-timeout.trace"
    [ "$(wc -l < "$out/events.log")" -eq 2 ]
    [ "$(sed -n '1p' "$out/events.log" | cut -f1)" = alpha ]
    [ "$(sed -n '2p' "$out/events.log" | cut -f1)" = beta ]
    assert_baseline timeout
    cp "$out/events.log" "$out/$kind-timeout.events"
    cp "$out/events-raw.jsonl" "$out/$kind-timeout.raw.jsonl"
    # Next invocation must reload the full package after contention ends.
    : > "$out/events.log"
    : > "$out/events-status"
    : > "$out/events-raw.jsonl"
    "$bin" --timeout-ms 1000 --trace-stderr > /dev/null 2> "$out/$kind-retry.trace"
    [ "$(wc -l < "$out/events.log")" -eq 1 ]
    [ "$(cut -f1 "$out/events.log")" = alpha ]
    assert_baseline
    cp "$out/events.log" "$out/$kind-timeout-recovery.events"
    cp "$out/events-raw.jsonl" "$out/$kind-timeout-recovery.raw.jsonl"
    assert_no_repeat "$kind-timeout"
    printf '%s_timeout: continued beta, full baseline matched, recovery and repeat passed\n' "$kind" >> "$out/results.txt"

    reset_case "$kind"
    hold_lock
    "$bin" --timeout-ms 10000 --trace-stderr > /dev/null 2> "$out/$kind-cancel.trace" & child=$!
    # This exact image's BusyBox sleep accepts whole seconds only.
    sleep 1
    kill -TERM "$child"
    if wait "$child"; then status=0; else status=$?; fi
    release_lock
    [ "$status" = 75 ]
    cmp /var/run/config.md5 "$out/baseline-before"
    [ ! -s "$out/events.log" ]
    cp "$out/events.log" "$out/$kind-cancel.events"
    "$bin" --timeout-ms 1000 --trace-stderr > /dev/null 2> "$out/$kind-cancel-recovery.trace"
    [ "$(wc -l < "$out/events.log")" -eq 2 ]
    [ "$(sed -n '1p' "$out/events.log" | cut -f1)" = alpha ]
    [ "$(sed -n '2p' "$out/events.log" | cut -f1)" = beta ]
    assert_baseline
    cp "$out/events.log" "$out/$kind-cancel-recovery.events"
    cp "$out/events-raw.jsonl" "$out/$kind-cancel-recovery.raw.jsonl"
    assert_no_repeat "$kind-cancel"
    printf '%s_cancel: exit 75, baseline and deliveries unchanged, recovery and repeat passed\n' "$kind" >> "$out/results.txt"
done
# Remote status 6 is not the local deadline outcome. Both failures advance
# the baseline and later invocations must not retry either accepted request.
reset_case config
printf '6\n7\n' > "$out/events-status"
if "$guard" 3 "$bin" --timeout-ms 1000 --trace-stderr > /dev/null 2> "$out/event-status.trace"; then status=0; else status=$?; fi
[ "$status" = 2 ]
grep -q '"outcome":"exit_nonzero","status":250' "$out/event-status.trace"
grep -q '"outcome":"exit_nonzero","status":249' "$out/event-status.trace"
[ "$(wc -l < "$out/events.log")" -eq 2 ]
assert_baseline
cp "$out/events-raw.jsonl" "$out/event-status.raw.jsonl"
assert_no_repeat event-status
printf 'event_status: remote 6/7 mapped to 250/249, baseline advanced, no retry\n' >> "$out/results.txt"

# Omit the first reply but continue servicing later requests. This proves
# timeout and continuation against the protocol, without a CLI path shim.
reset_case config
printf 'drop\n0\n' > "$out/events-status"
if "$guard" 3 "$bin" --timeout-ms 100 --trace-stderr > /dev/null 2> "$out/event-timeout.trace"; then status=0; else status=$?; fi
[ "$status" = 2 ]
grep -q '"package":"alpha","outcome":"timeout"' "$out/event-timeout.trace"
grep -q '"package":"beta","outcome":"success"' "$out/event-timeout.trace"
[ "$(wc -l < "$out/events.log")" -eq 2 ]
assert_baseline
cp "$out/events-raw.jsonl" "$out/event-timeout.raw.jsonl"
assert_no_repeat event-timeout
printf 'event_timeout: alpha timed out, beta accepted, baseline advanced, no retry\n' >> "$out/results.txt"

reset_case config
printf 'drop\n0\n' > "$out/events-status"
"$bin" --timeout-ms 10000 --trace-stderr > /dev/null 2> "$out/event-cancel.trace" & child=$!
for attempt in 1 2 3 4 5; do
    [ -s "$out/events.log" ] && break
    sleep 1
done
[ "$(wc -l < "$out/events.log")" -eq 1 ]
kill -TERM "$child"
if wait "$child"; then status=0; else status=$?; fi
[ "$status" = 75 ]
cmp /var/run/config.md5 "$out/baseline-before"
[ "$(wc -l < "$out/events.log")" -eq 1 ]
[ "$(cut -f1 "$out/events.log")" = alpha ]
cp "$out/events-raw.jsonl" "$out/event-cancel.raw.jsonl"
: > "$out/events.log"
: > "$out/events-status"
: > "$out/events-raw.jsonl"
"$bin" --timeout-ms 1000 --trace-stderr > /dev/null 2> "$out/event-cancel-recovery.trace"
[ "$(wc -l < "$out/events.log")" -eq 2 ]
[ "$(sed -n '1p' "$out/events.log" | cut -f1)" = alpha ]
[ "$(sed -n '2p' "$out/events.log" | cut -f1)" = beta ]
assert_baseline
cp "$out/events-raw.jsonl" "$out/event-cancel-recovery.raw.jsonl"
assert_no_repeat event-cancel
printf 'event_cancel: exit 75, beta not sent, old baseline preserved, next round recovered\n' >> "$out/results.txt"

reset_case config
lockfile=/var/run/reload-config-rs.lock
hold_lock
"$bin" --timeout-ms 10000 --trace-stderr > /dev/null 2> "$out/run-lock-cancel.trace" & child=$!
sleep 1
kill -TERM "$child"
if wait "$child"; then status=0; else status=$?; fi
release_lock
[ "$status" = 75 ]
cmp /var/run/config.md5 "$out/baseline-before"
[ ! -s "$out/events.log" ]
"$bin" --timeout-ms 1000 --trace-stderr > /dev/null 2> "$out/run-lock-recovery.trace"
[ "$(wc -l < "$out/events.log")" -eq 2 ]
assert_baseline
cp "$out/events-raw.jsonl" "$out/run-lock-recovery.raw.jsonl"
assert_no_repeat run-lock
printf 'run_lock_cancel: exit 75 while waiting, baseline/events unchanged, recovery passed\n' >> "$out/results.txt"
kill -0 "$receiver_pid"
kill -0 "$bus"
touch "$out/COMPLETE"
