#!/bin/sh
set -eu

umask 077

RUN_ROOT=/tmp/owrt-h1-5-install-20260902
APK_PATH=/tmp/owrt-h1-5-r1.apk
HARNESS_PATH=/tmp/owrt-h1-5-disabled-install.sh
APK_TOOL=/usr/bin/apk
PACKAGE=owrt-reload-config
CANDIDATE=/usr/sbin/reload_config_rs
SWITCH=/usr/sbin/owrt-reload-config-switch
EXPECTED_APK_SHA256=02d0c977d68192c28d0ef537a704435d9814fb8e04763cd67d73e00e41e5d9b1
EXPECTED_CANDIDATE_SHA256=b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75
EXPECTED_SWITCH_SHA256=ce7ef65892c69d1900ee0f626183bcae5a42b3ccd1f18f706ab496703b990bdf
EXPECTED_DISPATCHER_SHA256=f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15
EXPECTED_BASELINE_SHA256=b77e0e99672ee504d1ee1183f14b8ba8cfe92f6c546aa585f7efc784d2b0c163
EXPECTED_CONFIG_TREE_SHA256=c571059487c486dc8f255228f49ab558092a50ee22c0845c91ed4839a0ded44a
EXPECTED_PACKAGE_DB_SHA256=6149a91ae1efa348b3e56d08ef13f844ecee6288a78448749519682a9e8cb5fc
EXPECTED_WORLD_SHA256=906eb5cf1013afd8e8ff97b486175fa77a97a2a2437d640a1c4fdc4dd9eab69b
EXPECTED_SCRIPTS_SHA256=4a5fd6b59a9eadd3b27dd31fd4d79b622083b0a11d966a8c2dd5916c1b945bfc
EXPECTED_TRIGGERS_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
ROM_SCRIPTS=/rom/lib/apk/db/scripts.tar.gz
SCRIPTS_RESTORE=/lib/apk/db/.scripts.tar.gz.h1-5-restore
current_step=entry
restore_temp_created=0

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

tree_digest() {
    directory=$1
    (
        cd "$directory"
        find . -type f -exec sha256sum '{}' \; | sort | sha256sum | awk '{print $1}'
    )
}

mount_count() {
    awk '$5 == "/sbin/reload_config" { count++ } END { print count + 0 }' \
        /proc/self/mountinfo
}

package_installed() {
    "$APK_TOOL" info -e "$PACKAGE" >/dev/null 2>&1
}

file_metadata() {
    LC_ALL=C ls -ldn "$1" | awk '{ print $1 ":" $3 ":" $4 }'
}

restore_scripts_archive() {
    [ -f "$ROM_SCRIPTS" ] || return 1
    [ "$(sha256_file "$ROM_SCRIPTS")" = "$EXPECTED_SCRIPTS_SHA256" ] || return 1
    [ ! -e "$SCRIPTS_RESTORE" ] || return 1
    restore_temp_created=1
    cp "$ROM_SCRIPTS" "$SCRIPTS_RESTORE" || return 1
    [ "$(sha256_file "$SCRIPTS_RESTORE")" = "$EXPECTED_SCRIPTS_SHA256" ] || return 1
    chmod 0644 "$SCRIPTS_RESTORE" || return 1
    mv -f "$SCRIPTS_RESTORE" /lib/apk/db/scripts.tar.gz || return 1
    restore_temp_created=0
    [ "$(sha256_file /lib/apk/db/scripts.tar.gz)" = "$EXPECTED_SCRIPTS_SHA256" ]
}

cleanup() {
    saved_status=$?
    trap - EXIT HUP INT TERM
    cleanup_status=0
    rollback_status=not-needed

    if [ "$saved_status" -ne 0 ]; then
        if package_installed; then
            rollback_status=attempted
            if [ -x "$SWITCH" ]; then
                "$SWITCH" disable >"$RUN_ROOT/rollback-disable.log" 2>&1 || cleanup_status=1
            fi
            if ! "$APK_TOOL" --no-network del "$PACKAGE" \
                >"$RUN_ROOT/rollback-delete.log" 2>&1; then
                cleanup_status=1
            fi
        fi
        if [ "$(sha256_file /lib/apk/db/scripts.tar.gz)" != "$EXPECTED_SCRIPTS_SHA256" ]; then
            rollback_status=attempted
            restore_scripts_archive || cleanup_status=1
        fi
        if package_installed || [ -e "$CANDIDATE" ] || [ -e "$SWITCH" ]; then
            cleanup_status=1
        elif [ "$(sha256_file /sbin/reload_config)" != "$EXPECTED_DISPATCHER_SHA256" ] ||
            [ "$(sha256_file /var/run/config.md5)" != "$EXPECTED_BASELINE_SHA256" ] ||
            [ "$(tree_digest /etc/config)" != "$EXPECTED_CONFIG_TREE_SHA256" ] ||
            [ "$(sha256_file /lib/apk/db/installed)" != "$EXPECTED_PACKAGE_DB_SHA256" ] ||
            [ "$(sha256_file /etc/apk/world)" != "$EXPECTED_WORLD_SHA256" ] ||
            [ "$(sha256_file /lib/apk/db/scripts.tar.gz)" != "$EXPECTED_SCRIPTS_SHA256" ] ||
            [ "$(sha256_file /lib/apk/db/triggers)" != "$EXPECTED_TRIGGERS_SHA256" ] ||
            [ "$(mount_count)" -ne 0 ]; then
            cleanup_status=1
        elif [ "$rollback_status" = attempted ]; then
            rollback_status=passed
        fi
    fi

    if [ "$restore_temp_created" -eq 1 ] && [ -e "$SCRIPTS_RESTORE" ]; then
        busybox rm "$SCRIPTS_RESTORE" || cleanup_status=1
        restore_temp_created=0
    fi

    if [ "$saved_status" -ne 0 ] && [ -d "$RUN_ROOT" ]; then
        for log in simulate.log install.log rollback-disable.log rollback-delete.log; do
            if [ -f "$RUN_ROOT/$log" ]; then
                printf 'diagnostic_%s_begin\n' "$log"
                cat "$RUN_ROOT/$log"
                printf 'diagnostic_%s_end\n' "$log"
            fi
        done
    fi

    if [ "$RUN_ROOT" != /tmp/owrt-h1-5-install-20260902 ]; then
        cleanup_status=1
    elif [ -d "$RUN_ROOT" ]; then
        busybox rm -r "$RUN_ROOT" || cleanup_status=1
    fi
    for path in "$APK_PATH" "$HARNESS_PATH"; do
        case "$path" in
            /tmp/owrt-h1-5-r1.apk | /tmp/owrt-h1-5-disabled-install.sh) ;;
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
        [ ! -e "$APK_PATH" ] && [ ! -e "$HARNESS_PATH" ]; then
        if [ "$saved_status" -ne 0 ]; then
            printf 'failed_step=%s\n' "$current_step"
            printf 'rollback=%s\n' "$rollback_status"
        fi
        printf '%s\n' 'cleanup=PASS'
    else
        printf 'failed_step=%s\n' "$current_step"
        printf 'rollback=%s\n' "$rollback_status"
        printf '%s\n' 'cleanup=FAIL'
        [ "$saved_status" -ne 0 ] || saved_status=90
    fi
    exit "$saved_status"
}
trap cleanup EXIT HUP INT TERM

current_step=identity-guards
[ "$0" = "$HARNESS_PATH" ]
[ ! -e "$RUN_ROOT" ]
[ -x "$APK_TOOL" ]
[ -f "$APK_PATH" ]
[ "$(sha256_file "$APK_PATH")" = "$EXPECTED_APK_SHA256" ]
[ "$(sha256_file /sbin/reload_config)" = "$EXPECTED_DISPATCHER_SHA256" ]
[ "$(sha256_file /var/run/config.md5)" = "$EXPECTED_BASELINE_SHA256" ]
[ "$(tree_digest /etc/config)" = "$EXPECTED_CONFIG_TREE_SHA256" ]
[ "$(sha256_file /lib/apk/db/installed)" = "$EXPECTED_PACKAGE_DB_SHA256" ]
[ "$(sha256_file /etc/apk/world)" = "$EXPECTED_WORLD_SHA256" ]
[ "$(sha256_file /lib/apk/db/scripts.tar.gz)" = "$EXPECTED_SCRIPTS_SHA256" ]
[ "$(sha256_file /lib/apk/db/triggers)" = "$EXPECTED_TRIGGERS_SHA256" ]
[ "$(sha256_file "$ROM_SCRIPTS")" = "$EXPECTED_SCRIPTS_SHA256" ]
[ ! -e "$SCRIPTS_RESTORE" ]
[ "$(mount_count)" -eq 0 ]
! package_installed
[ ! -e "$CANDIDATE" ]
[ ! -e "$SWITCH" ]
for dependency in libc procd uci ubus; do
    "$APK_TOOL" info -e "$dependency" >/dev/null
done
available_kib=$(df -Pk /overlay | awk 'NR == 2 { print $4 }')
[ "$available_kib" -ge 4096 ]

mkdir -p "$RUN_ROOT"

current_step=offline-simulation
"$APK_TOOL" --no-network add --simulate --allow-untrusted "$APK_PATH" \
    >"$RUN_ROOT/simulate.log" 2>&1
[ "$(sha256_file /lib/apk/db/installed)" = "$EXPECTED_PACKAGE_DB_SHA256" ]
[ "$(sha256_file /etc/apk/world)" = "$EXPECTED_WORLD_SHA256" ]
[ "$(sha256_file /lib/apk/db/scripts.tar.gz)" = "$EXPECTED_SCRIPTS_SHA256" ]
! package_installed
[ ! -e "$CANDIDATE" ]
[ ! -e "$SWITCH" ]

current_step=package-install
"$APK_TOOL" --no-network add --allow-untrusted "$APK_PATH" \
    >"$RUN_ROOT/install.log" 2>&1

current_step=package-identity
package_installed
"$APK_TOOL" --no-network query --from installed \
    --fields name,version,arch,origin,installed-size "$PACKAGE" \
    >"$RUN_ROOT/query.log" 2>/dev/null
grep -Fqx 'Name: owrt-reload-config' "$RUN_ROOT/query.log"
grep -Fqx 'Version: 0.1.0-r1' "$RUN_ROOT/query.log"
grep -Fqx 'Arch: aarch64_cortex-a53' "$RUN_ROOT/query.log"
grep -Fqx 'Origin: feeds/base/owrt-reload-config' "$RUN_ROOT/query.log"
grep -Fqx 'Installed-Size: 348430' "$RUN_ROOT/query.log"
"$APK_TOOL" --no-network info -L "$PACKAGE" >"$RUN_ROOT/files.log" 2>/dev/null
grep -Fqx 'lib/apk/packages/owrt-reload-config.list' "$RUN_ROOT/files.log"
grep -Fqx 'usr/sbin/owrt-reload-config-switch' "$RUN_ROOT/files.log"
grep -Fqx 'usr/sbin/reload_config_rs' "$RUN_ROOT/files.log"
[ "$(grep -Ec '^(lib|usr)/' "$RUN_ROOT/files.log")" -eq 3 ]

current_step=installed-files
[ -x "$CANDIDATE" ]
[ -x "$SWITCH" ]
[ "$(sha256_file "$CANDIDATE")" = "$EXPECTED_CANDIDATE_SHA256" ]
[ "$(sha256_file "$SWITCH")" = "$EXPECTED_SWITCH_SHA256" ]
[ "$(file_metadata "$CANDIDATE")" = '-rwxr-xr-x:0:0' ]
[ "$(file_metadata "$SWITCH")" = '-rwxr-xr-x:0:0' ]

current_step=disabled-state
set +e
"$SWITCH" status >"$RUN_ROOT/status.log" 2>&1
status_rc=$?
set -e
[ "$status_rc" -eq 3 ]
[ "$(cat "$RUN_ROOT/status.log")" = disabled ]
[ "$(mount_count)" -eq 0 ]
[ "$(sha256_file /sbin/reload_config)" = "$EXPECTED_DISPATCHER_SHA256" ]

current_step=live-invariants
[ "$(sha256_file /var/run/config.md5)" = "$EXPECTED_BASELINE_SHA256" ]
[ "$(tree_digest /etc/config)" = "$EXPECTED_CONFIG_TREE_SHA256" ]
[ "$(sha256_file /lib/apk/db/installed)" != "$EXPECTED_PACKAGE_DB_SHA256" ]
[ "$(sha256_file /etc/apk/world)" != "$EXPECTED_WORLD_SHA256" ]
[ "$(sha256_file /lib/apk/db/scripts.tar.gz)" != "$EXPECTED_SCRIPTS_SHA256" ]
[ "$(sha256_file /lib/apk/db/triggers)" = "$EXPECTED_TRIGGERS_SHA256" ]
[ "$(mount_count)" -eq 0 ]

package_db_after=$(sha256_file /lib/apk/db/installed)
world_after=$(sha256_file /etc/apk/world)
scripts_after=$(sha256_file /lib/apk/db/scripts.tar.gz)
available_kib_after=$(df -Pk /overlay | awk 'NR == 2 { print $4 }')

current_step=emit-summary
printf '%s\n' \
    'h1_5_disabled_install=PASS' \
    'package=owrt-reload-config' \
    'version=0.1.0-r1' \
    'arch=aarch64_cortex-a53' \
    "candidate_sha256=$EXPECTED_CANDIDATE_SHA256" \
    "switch_sha256=$EXPECTED_SWITCH_SHA256" \
    "dispatcher_sha256=$EXPECTED_DISPATCHER_SHA256" \
    "baseline_sha256=$EXPECTED_BASELINE_SHA256" \
    "config_tree_sha256=$EXPECTED_CONFIG_TREE_SHA256" \
    "package_db_sha256_before=$EXPECTED_PACKAGE_DB_SHA256" \
    "package_db_sha256_after=$package_db_after" \
    "world_sha256_before=$EXPECTED_WORLD_SHA256" \
    "world_sha256_after=$world_after" \
    "scripts_sha256_before=$EXPECTED_SCRIPTS_SHA256" \
    "scripts_sha256_after=$scripts_after" \
    "overlay_available_kib_before=$available_kib" \
    "overlay_available_kib_after=$available_kib_after" \
    'switch_status=disabled' \
    'switch_status_rc=3' \
    'candidate_activation=false' \
    'real_ubus_calls=0' \
    'persistent_writes=package-only' \
    'runtime_mount_changes=0' \
    'router_reboot=false' \
    'firmware_flash=false'
printf '%s\n' 'simulate_log_begin'
cat "$RUN_ROOT/simulate.log"
printf '%s\n' 'simulate_log_end'
printf '%s\n' 'install_log_begin'
cat "$RUN_ROOT/install.log"
printf '%s\n' 'install_log_end'
