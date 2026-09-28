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
mkdir -p /tmp/probe-bin /var/run /tmp/.uci
cat > /tmp/probe-bin/ubus <<'UBUS'
#!/bin/sh
printf '%s\n' "$4" >> /tmp/out/events
UBUS
chmod 755 /tmp/probe-bin/ubus
export PATH=/tmp/probe-bin:$PATH

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
    : > "$out/events"
    "$bin" --timeout-ms 1000 --trace-stderr > /dev/null 2> "$out/$1-repeat.trace"
    [ ! -s "$out/events" ]
    cmp /var/run/config.md5 "$out/baseline-recovered"
}

reset_case() {
    # These directories are tmpfs in the chroot established by isolated.sh.
    rm -f /etc/config/* /tmp/.uci/* /var/run/config.md5 /tmp/ready /tmp/release
    rm -rf /var/run/uci
    for name in alpha beta; do
        printf "config test 's'\n option value 'before'\n" > "/etc/config/$name"
    done
    "$bin" --trace-stderr > /dev/null 2> "$out/prime.trace"
    cp /var/run/config.md5 "$out/baseline-before"
    : > "$out/events"
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
    [ ! -s "$out/events" ]
    printf 'before_config_lock: deadline exceeded; guard killed candidate (expected red)\n' >> "$out/results.txt"
fi

for kind in config delta override; do
    reset_case "$kind"
    hold_lock
    "$guard" 3 "$bin" --timeout-ms 100 --trace-stderr > /dev/null 2> "$out/$kind-timeout.trace"
    release_lock
    grep -q '"status":"timeout"' "$out/$kind-timeout.trace"
    [ "$(wc -l < "$out/events")" -eq 2 ]
    sed -n '1p' "$out/events" | grep -q '"package": "alpha"'
    sed -n '2p' "$out/events" | grep -q '"package": "beta"'
    assert_baseline timeout
    cp "$out/events" "$out/$kind-timeout.events"
    # Next invocation must reload the full package after contention ends.
    : > "$out/events"
    "$bin" --timeout-ms 1000 --trace-stderr > /dev/null 2> "$out/$kind-retry.trace"
    [ "$(wc -l < "$out/events")" -eq 1 ]
    grep -q '"package": "alpha"' "$out/events"
    assert_baseline
    cp "$out/events" "$out/$kind-timeout-recovery.events"
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
    [ ! -s "$out/events" ]
    cp "$out/events" "$out/$kind-cancel.events"
    "$bin" --timeout-ms 1000 --trace-stderr > /dev/null 2> "$out/$kind-cancel-recovery.trace"
    [ "$(wc -l < "$out/events")" -eq 2 ]
    sed -n '1p' "$out/events" | grep -q '"package": "alpha"'
    sed -n '2p' "$out/events" | grep -q '"package": "beta"'
    assert_baseline
    cp "$out/events" "$out/$kind-cancel-recovery.events"
    assert_no_repeat "$kind-cancel"
    printf '%s_cancel: exit 75, baseline and deliveries unchanged, recovery and repeat passed\n' "$kind" >> "$out/results.txt"
done
touch "$out/COMPLETE"
