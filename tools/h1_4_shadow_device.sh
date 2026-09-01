#!/bin/sh
set -eu

umask 077

RUN_ROOT=/tmp/owrt-r05-shadow-20260901
SHADOW_ROOT=$RUN_ROOT/root
EVIDENCE_DIR=$RUN_ROOT/evidence
FAKE_BIN=$RUN_ROOT/bin
FAKE_UBUS_LOG=$EVIDENCE_DIR/fake-ubus.log
CANDIDATE=/tmp/owrt-h1-4-reload-config-rs
HARNESS=/tmp/owrt-h1-4-shadow.sh
EXPECTED_CANDIDATE_SHA256=b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75
EXPECTED_DISPATCHER_SHA256=f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15
SYNTHETIC_PACKAGE=h1_shadow_probe

cleanup() {
    saved_status=$?
    trap - EXIT HUP INT TERM
    cleanup_status=0

    if [ "$RUN_ROOT" != /tmp/owrt-r05-shadow-20260901 ]; then
        cleanup_status=1
    elif [ -d "$RUN_ROOT" ]; then
        busybox rm -r "$RUN_ROOT" || cleanup_status=1
    fi
    for path in "$CANDIDATE" "$HARNESS"; do
        case "$path" in
            /tmp/owrt-h1-4-reload-config-rs | /tmp/owrt-h1-4-shadow.sh) ;;
            *)
                cleanup_status=1
                continue
                ;;
        esac
        if [ -e "$path" ]; then
            busybox rm "$path" || cleanup_status=1
        fi
    done

    if [ "$cleanup_status" -eq 0 ] && [ ! -e "$RUN_ROOT" ] &&
        [ ! -e "$CANDIDATE" ] && [ ! -e "$HARNESS" ]; then
        printf '%s\n' 'cleanup=PASS'
    else
        printf '%s\n' 'cleanup=FAIL'
        [ "$saved_status" -ne 0 ] || saved_status=90
    fi
    exit "$saved_status"
}
trap cleanup EXIT HUP INT TERM

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

tree_digest() {
    directory=$1
    if [ ! -d "$directory" ]; then
        printf '%s\n' absent
        return
    fi
    (
        cd "$directory"
        find . -type f -exec sha256sum '{}' \; | sort | sha256sum | awk '{print $1}'
    )
}

mount_count() {
    awk '$5 == "/sbin/reload_config" { count++ } END { print count + 0 }' /proc/self/mountinfo
}

line_count() {
    wc -l <"$1" | tr -d ' '
}

run_candidate() {
    label=$1
    H1_4_UBUS_LOG="$FAKE_UBUS_LOG" \
        PATH="$FAKE_BIN:/usr/sbin:/usr/bin:/sbin:/bin" \
        "$CANDIDATE" --root "$SHADOW_ROOT" --timeout-ms 5000 \
        2>"$EVIDENCE_DIR/$label.jsonl"
}

[ "$0" = "$HARNESS" ]
[ ! -e "$RUN_ROOT" ]
[ -f "$CANDIDATE" ]
[ "$(sha256_file "$CANDIDATE")" = "$EXPECTED_CANDIDATE_SHA256" ]
[ "$(sha256_file /sbin/reload_config)" = "$EXPECTED_DISPATCHER_SHA256" ]
[ -f /var/run/config.md5 ]
[ ! -e /usr/sbin/reload_config_rs ]
[ ! -e /usr/sbin/owrt-reload-config-switch ]
[ "$(mount_count)" -eq 0 ]

live_config_before=$(tree_digest /etc/config)
live_uci_before=$(tree_digest /var/run/uci)
live_baseline_before=$(sha256_file /var/run/config.md5)
dispatcher_before=$(sha256_file /sbin/reload_config)
package_db_before=$(sha256_file /lib/apk/db/installed)
mount_before=$(mount_count)

mkdir -p "$SHADOW_ROOT/etc/config" "$SHADOW_ROOT/var/run" \
    "$EVIDENCE_DIR" "$FAKE_BIN"
cp -a /etc/config/. "$SHADOW_ROOT/etc/config/"
if [ -d /var/run/uci ]; then
    mkdir -p "$SHADOW_ROOT/var/run/uci"
    cp -a /var/run/uci/. "$SHADOW_ROOT/var/run/uci/"
fi
cp /var/run/config.md5 "$SHADOW_ROOT/var/run/config.md5"

[ "$(tree_digest "$SHADOW_ROOT/etc/config")" = "$live_config_before" ]
[ "$(tree_digest "$SHADOW_ROOT/var/run/uci")" = "$live_uci_before" ]
shadow_baseline_initial=$(sha256_file "$SHADOW_ROOT/var/run/config.md5")
[ "$shadow_baseline_initial" = "$live_baseline_before" ]

cat >"$FAKE_BIN/ubus" <<'FAKE_UBUS'
#!/bin/sh
set -eu
: "${H1_4_UBUS_LOG:?}"
first=1
for argument in "$@"; do
    if [ "$first" -eq 0 ]; then
        printf '\t' >>"$H1_4_UBUS_LOG"
    fi
    printf '%s' "$argument" >>"$H1_4_UBUS_LOG"
    first=0
done
printf '\n' >>"$H1_4_UBUS_LOG"
FAKE_UBUS
chmod 0500 "$FAKE_BIN/ubus"
: >"$FAKE_UBUS_LOG"
[ "$(PATH="$FAKE_BIN:/usr/sbin:/usr/bin:/sbin:/bin" command -v ubus)" = "$FAKE_BIN/ubus" ]

run_candidate run1_shared_baseline
[ "$(line_count "$FAKE_UBUS_LOG")" -eq 0 ]
grep -Fq '"changed_entries":[]' "$EVIDENCE_DIR/run1_shared_baseline.jsonl"
grep -Fq '"delivery_failures":0' "$EVIDENCE_DIR/run1_shared_baseline.jsonl"
shadow_baseline_after_run1=$(sha256_file "$SHADOW_ROOT/var/run/config.md5")
[ "$shadow_baseline_after_run1" = "$shadow_baseline_initial" ]

[ ! -e "$SHADOW_ROOT/etc/config/$SYNTHETIC_PACKAGE" ]
cat >"$SHADOW_ROOT/etc/config/$SYNTHETIC_PACKAGE" <<'SYNTHETIC_ONE'
config probe 'main'
        option value 'one'
SYNTHETIC_ONE
run_candidate run2_creation_silent
[ "$(line_count "$FAKE_UBUS_LOG")" -eq 0 ]
grep -Fq '"changed_entries":[]' "$EVIDENCE_DIR/run2_creation_silent.jsonl"
grep -Fq '"delivery_failures":0' "$EVIDENCE_DIR/run2_creation_silent.jsonl"

cat >"$SHADOW_ROOT/etc/config/$SYNTHETIC_PACKAGE" <<'SYNTHETIC_TWO'
config probe 'main'
        option value 'two'
SYNTHETIC_TWO
run_candidate run3_modification_event
[ "$(line_count "$FAKE_UBUS_LOG")" -eq 1 ]
grep -Fq '"changed_entries":["h1_shadow_probe"]' \
    "$EVIDENCE_DIR/run3_modification_event.jsonl"
grep -Fq '"package":"h1_shadow_probe","outcome":"success","status":0' \
    "$EVIDENCE_DIR/run3_modification_event.jsonl"
grep -Fq '"delivery_failures":0' "$EVIDENCE_DIR/run3_modification_event.jsonl"
expected_fake_call=$(printf '%s\t%s\t%s\t%s' call service event \
    '{ "type": "config.change", "data": { "package": "h1_shadow_probe" } }')
[ "$(cat "$FAKE_UBUS_LOG")" = "$expected_fake_call" ]

live_config_after=$(tree_digest /etc/config)
live_uci_after=$(tree_digest /var/run/uci)
live_baseline_after=$(sha256_file /var/run/config.md5)
dispatcher_after=$(sha256_file /sbin/reload_config)
package_db_after=$(sha256_file /lib/apk/db/installed)
mount_after=$(mount_count)

[ "$live_config_after" = "$live_config_before" ]
[ "$live_uci_after" = "$live_uci_before" ]
[ "$live_baseline_after" = "$live_baseline_before" ]
[ "$dispatcher_after" = "$dispatcher_before" ]
[ "$package_db_after" = "$package_db_before" ]
[ "$mount_after" -eq "$mount_before" ]
[ ! -e /usr/sbin/reload_config_rs ]
[ ! -e /usr/sbin/owrt-reload-config-switch ]

printf '%s\n' \
    'h1_4_shadow=PASS' \
    "candidate_sha256=$EXPECTED_CANDIDATE_SHA256" \
    "dispatcher_sha256=$dispatcher_after" \
    "live_config_tree_sha256=$live_config_after" \
    "live_uci_tree_sha256=$live_uci_after" \
    "live_baseline_sha256=$live_baseline_after" \
    "package_db_sha256=$package_db_after" \
    "mount_count=$mount_after" \
    'run1_shared_baseline=PASS' \
    'run2_creation_silent=PASS' \
    'run3_modification_event=PASS' \
    'real_ubus_calls=0' \
    'device_writes=tmpfs-only' \
    'persistent_writes=0' \
    'runtime_mount_changes=0' \
    'router_reboot=false' \
    'firmware_flash=false'

for trace in run1_shared_baseline run2_creation_silent run3_modification_event; do
    printf 'trace_%s_begin\n' "$trace"
    cat "$EVIDENCE_DIR/$trace.jsonl"
    printf 'trace_%s_end\n' "$trace"
done
printf '%s\n' 'fake_ubus_begin'
cat "$FAKE_UBUS_LOG"
printf '%s\n' 'fake_ubus_end'
