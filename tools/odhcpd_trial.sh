#!/bin/sh
# Finite, single-service trial. Never promotes a bind mount into a release.
# Generated private inputs are authenticated before being sourced.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
BASE=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
TARGET=/usr/sbin/odhcpd
INIT=/etc/init.d/odhcpd
LOCK=/tmp/owrt-odhcpd-trial.lock
ACTION=${1:?action required}
TOKEN_ARG=${2:?trial token required}
BOOT_ARG=${3:?expected boot required}
BUNDLE_ARG=${4:?bundle manifest digest required}

digest() { sha256sum "$1" | awk '{print $1}'; }
now() { cut -d. -f1 /proc/uptime; }
fail() { printf '%s\n' "$*" >&2; return 1; }
record() { printf 'uptime=%s %s\n' "$(now)" "$*" >> "$BASE/guard.log"; }
put() { printf '%s\n' "$2" > "$BASE/$1.new"; mv -f "$BASE/$1.new" "$BASE/$1"; }
bounded() { "$BASE/bounded" bounded "$@"; }

# The external manifest hash binds the executable script, helper and settings.
# Recovery intentionally does not depend on an intact candidate or leasefile.
[ "$(id -u)" = 0 ]
[ "$(digest "$BASE/bundle.sha256")" = "$BUNDLE_ARG" ]
(cd "$BASE"; awk '$2 == "trial.sh" || $2 == "bounded" || $2 == "inputs.env" || $2 == "config.sha256" {print}' bundle.sha256 | sha256sum -c - >/dev/null)
. "$BASE/inputs.env"
[ "$TOKEN_ARG" = "$TOKEN" ] && [ "$BOOT_ARG" = "$BOOT" ]
[ "$BASE" = "/tmp/owrt-odhcpd-trial-$TOKEN" ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$BOOT" ]
[ "$(digest "$BASE/bounded")" = "$HELPER_SHA" ]

tmpfs_gate() {
    awk '$5 == "/tmp" {for(i=6;i<NF;i++) if($i=="-" && $(i+1)=="tmpfs") found=1} END {exit !found}' /proc/self/mountinfo || return 1
    [ ! -L "$BASE" ] || return 1
    # No second filesystem may replace the source directory or one of its
    # inputs below /tmp. That would invalidate our exact bind ownership proof.
    awk -v base="$BASE" '$5==base || index($5,base "/")==1 {bad=1} END {exit bad}' /proc/self/mountinfo || return 1
}

static_gate() {
    [ ! -L "$INIT" ] || return 1
    [ "$(digest "$INIT")" = "$INIT_SHA" ] || return 1
    [ "$(digest /usr/sbin/odhcpd-update)" = "$TRIGGER_SHA" ] || return 1
    [ "$(digest /rom/usr/sbin/odhcpd)" = "$C_SHA" ] || return 1
    [ "$(cat /proc/sys/kernel/random/boot_id)" = "$BOOT" ] || return 1
}

config_gate() { sha256sum -c "$BASE/config.sha256" >/dev/null; }
mount_count() { awk -v target="$TARGET" '$5==target {n++} END {print n+0}' /proc/self/mountinfo; }
owned_mount() {
    [ "$(mount_count)" = 1 ] || return 1
    awk -v target="$TARGET" -v root="/owrt-odhcpd-trial-$TOKEN/candidate.elf" \
        '$5==target && $4==root {found=1} END {exit !found}' /proc/self/mountinfo
}

process_id() {
    # PID plus start ticks prevents a reused PID satisfying a stale receipt.
    awk '{sub(/^.*\) /, ""); print $2, $20}' "/proc/$1/stat" 2>/dev/null
}

runtime() {
    runtime_expected=$1
    runtime_file=$BASE/service.$$.json
    bounded 5 ubus -S -t 3 call service list '{"name":"odhcpd"}' > "$runtime_file" || return 1
    runtime_pid=$(jsonfilter -i "$runtime_file" -e '@.odhcpd.instances.*.pid') || return 1
    case "$runtime_pid" in ''|*[!0-9]*) return 1 ;; esac
    [ "$(jsonfilter -i "$runtime_file" -e '@.odhcpd.instances.*.running')" = true ] || return 1
    [ "$(jsonfilter -i "$runtime_file" -e '@.odhcpd.instances.*.command[0]')" = "$TARGET" ] || return 1
    runtime_before=$(process_id "$runtime_pid") || return 1
    [ "${runtime_before%% *}" = 1 ] || return 1
    [ "$(digest "/proc/$runtime_pid/exe")" = "$runtime_expected" ] || return 1
    [ "$(process_id "$runtime_pid")" = "$runtime_before" ] || return 1
    rm -f "$runtime_file"
    printf '%s %s\n' "$runtime_pid" "${runtime_before#* }"
}

wait_runtime() {
    wait_expected=$1
    wait_deadline=$(( $(now) + 20 ))
    while [ "$(now)" -lt "$wait_deadline" ]; do
        if runtime "$wait_expected" > "$BASE/runtime.$$.id" 2>/dev/null; then
            cat "$BASE/runtime.$$.id"
            return 0
        fi
        sleep 1
    done
    return 1
}

dhcp_gate() {
    bounded 5 ubus -S -t 3 call dhcp ipv6leases > "$BASE/leases.$$.json" || return 1
    jsonfilter -i "$BASE/leases.$$.json" -e '@.device' > /dev/null || return 1
    bounded 5 ubus -S -t 3 call dhcp ipv6ra > "$BASE/ra.$$.json" || return 1
    jsonfilter -i "$BASE/ra.$$.json" -e '@.interfaces' > /dev/null || return 1
    rm -f "$BASE/leases.$$.json" "$BASE/ra.$$.json"
}

preflight() {
    tmpfs_gate || return 1
    static_gate || return 1
    (cd "$BASE"; sha256sum -c bundle.sha256 >/dev/null) || return 1
    for input in candidate.elf stock.elf bounded trial.sh inputs.env config.sha256 config-backup.tar.gz original-init original-trigger; do
        [ -f "$BASE/$input" ] && [ ! -L "$BASE/$input" ] || return 1
    done
    [ "$(digest "$BASE/config-backup.tar.gz")" = "$BACKUP_SHA" ] || return 1
    [ "$(digest "$BASE/stock.elf")" = "$C_SHA" ] || return 1
    [ "$(digest "$BASE/candidate.elf")" = "$CANDIDATE_SHA" ] || return 1
    config_gate || return 1
    [ "$(mount_count)" = 0 ] || return 1
    [ ! -L "$TARGET" ] || return 1
    [ "$(digest "$TARGET")" = "$C_SHA" ] || return 1
    for pending in /root/owrt-native-trial/armed /tmp/owrt-native-guard-lock \
        /tmp/owrt-native-decision-lock /etc/r84-pending /etc/r84-reverting \
        /etc/p6-pending /etc/p6-reverting /root/r84/trial.pending /root/r84/trial.reverting; do
        [ ! -e "$pending" ] || { fail "another trial is active: $pending"; return 1; }
    done
    [ -x /usr/bin/setsid ] || return 1
    "$INIT" enabled || return 1
    runtime "$C_SHA" > "$BASE/original.id" || return 1
    dhcp_gate || return 1
}

guard_alive() {
    [ -f "$LOCK/identity" ] || return 1
    read -r guard_pid guard_start guard_token < "$LOCK/identity" || return 1
    [ "$guard_token" = "$TOKEN" ] || return 1
    case "$guard_pid:$guard_start" in *[!0-9:]*|:*) return 1 ;; esac
    guard_identity=$(process_id "$guard_pid") || return 1
    [ "${guard_identity#* }" = "$guard_start" ] || return 1
}

candidate_alive() {
    read -r active_pid active_start < "$BASE/active.id" || return 1
    active_identity=$(process_id "$active_pid") || return 1
    [ "$active_identity" = "1 $active_start" ] || return 1
    [ "$(digest "/proc/$active_pid/exe")" = "$CANDIDATE_SHA" ] || return 1
}

health_receipt() {
    health_digest=$1
    case "$health_digest" in *[!a-f0-9]*|'') return 1 ;; esac
    [ "${#health_digest}" -eq 64 ] || return 1
    [ "$(digest "$BASE/client-health.json")" = "$health_digest" ] || return 1
    [ "$(jsonfilter -i "$BASE/client-health.json" -e '@.passed')" = true ] || return 1
    [ "$(jsonfilter -i "$BASE/client-health.json" -e '@.trial_token')" = "$TOKEN" ] || return 1
    [ "$(jsonfilter -i "$BASE/client-health.json" -e '@.boot_id')" = "$BOOT" ] || return 1
    [ "$(jsonfilter -i "$BASE/client-health.json" -e '@.candidate_sha256')" = "$CANDIDATE_SHA" ] || return 1
    external_token=$(jsonfilter -i "$BASE/client-health.json" -e '@.external_health_token') || return 1
    case "$external_token" in *[!a-f0-9]*|'') return 1 ;; esac
    [ "${#external_token}" -eq 64 ] || return 1
}
restore_c() {
    restore_reason=$1
    static_gate || return 1
    put state restoring || true
    record "restore-start reason=$restore_reason" || true
    # A running daemon can keep its bind mount busy. Stop only this procd
    # service before unmounting; neither PID1 nor the bus is restarted.
    stop_identity=$(runtime "$CANDIDATE_SHA" 2>/dev/null || true)
    if [ -z "$stop_identity" ] && [ -f "$BASE/active.id" ]; then
        stop_identity=$(cat "$BASE/active.id")
    fi
    bounded 15 "$INIT" stop >> "$BASE/restore.log" 2>&1 || return 1
    if [ -n "$stop_identity" ]; then
        old_pid=${stop_identity%% *}
        old_start=${stop_identity#* }
        stop_deadline=$(( $(now) + 15 ))
        while [ "$(process_id "$old_pid" || true)" = "1 $old_start" ]; do
            [ "$(now)" -lt "$stop_deadline" ] || return 1
            sleep 1
        done
    fi
    if [ "$(mount_count)" -ne 0 ]; then
        owned_mount || return 1
        unmount_deadline=$(( $(now) + 15 ))
        while [ "$(mount_count)" -ne 0 ]; do
            owned_mount || return 1
            if bounded 3 umount "$TARGET" >> "$BASE/restore.log" 2>&1; then break; fi
            [ "$(now)" -lt "$unmount_deadline" ] || return 1
            sleep 1
        done
    fi
    [ "$(mount_count)" = 0 ] || return 1
    [ "$(digest "$TARGET")" = "$C_SHA" ] || return 1
    bounded 15 "$INIT" restart >> "$BASE/restore.log" 2>&1 || return 1
    wait_runtime "$C_SHA" > "$BASE/restored.id" || return 1
    dhcp_gate || return 1
    config_gate || return 1
    put state "restored-$restore_reason" || return 1
    record "restore-complete reason=$restore_reason C=$C_SHA" || return 1
    if [ -f "$LOCK/identity" ] && [ "$(awk '{print $3}' "$LOCK/identity")" = "$TOKEN" ]; then
        rm -f "$LOCK/identity"
        rmdir "$LOCK"
    fi
    return 0
}

case "$ACTION" in
    preflight)
        [ ! -e "$LOCK" ]
        preflight
        printf '%s\n' 'preflight passed; no service or mount changed'
        ;;
    activate)
        [ ! -e "$LOCK" ] && [ ! -e "$BASE/state" ]
        preflight
        # The detached process owns the mutation, not the SSH command. A lost
        # caller cannot strand a mount between activation and arming a timer.
        /usr/bin/setsid /bin/sh "$BASE/trial.sh" guard "$TOKEN" "$BOOT" "$BUNDLE_ARG" \
            </dev/null >> "$BASE/guard.log" 2>&1 &
        launch_deadline=$(( $(now) + 45 ))
        while [ "$(now)" -lt "$launch_deadline" ]; do
            state=$(cat "$BASE/state" 2>/dev/null || true)
            case "$state" in
                active) guard_alive; printf '%s\n' 'finite odhcpd trial active; confirmation restores C'; exit 0 ;;
                restoring|restored-*|restore-failed) fail "activation ended in $state"; exit 1 ;;
            esac
            sleep 1
        done
        fail 'activation did not acknowledge; detached guard retains the deadline'
        ;;
    guard)
        tmpfs_gate
        mkdir "$LOCK"
        own_identity=$(process_id "$$")
        printf '%s %s %s\n' "$$" "${own_identity#* }" "$TOKEN" > "$LOCK/identity"
        changed=0
        trap '' HUP
        trap 'exit 143' TERM INT
        trap 'guard_rc=$?; trap - EXIT; if [ "$changed" -eq 1 ]; then if ! restore_c failure; then put state restore-failed; record restore-failed; fi; else rm -f "$LOCK/identity"; rmdir "$LOCK"; fi; exit "$guard_rc"' EXIT
        preflight
        put state arming
        deadline=$(( $(now) + LIMIT ))
        put deadline "$deadline"
        changed=1
        bounded 10 mount -o bind "$BASE/candidate.elf" "$TARGET"
        owned_mount
        [ "$(digest "$TARGET")" = "$CANDIDATE_SHA" ]
        bounded 15 "$INIT" restart >> "$BASE/activation.log" 2>&1
        wait_runtime "$CANDIDATE_SHA" > "$BASE/active.id"
        dhcp_gate
        put state active
        record "candidate-active deadline=$deadline"
        reason=timeout
        while [ "$(now)" -lt "$deadline" ]; do
            if ! candidate_alive; then reason=failure; break; fi
            request=$(cat "$BASE/request" 2>/dev/null || true)
            case "$request" in
                restore) reason=manual; break ;;
                confirm\ *)
                    receipt=${request#confirm }
                    if health_receipt "$receipt" && candidate_alive && dhcp_gate && config_gate; then
                        put accepted "$receipt $external_token"
                        reason=confirmed
                        break
                    fi
                    reason=failed-confirmation
                    break
                    ;;
            esac
            sleep 1
        done
        if restore_c "$reason"; then changed=0; trap - EXIT; exit 0; fi
        put state restore-failed
        record restore-failed
        # Keep ownership/evidence for a deliberate manual retry. Never reboot.
        changed=0
        trap - EXIT
        exit 1
        ;;
    confirm)
        [ "$(cat "$BASE/state")" = active ]
        guard_alive
        health_receipt "${5:?client health receipt digest required}"
        candidate_alive
        put request "confirm $5"
        printf '%s\n' 'confirmation queued; success requires state restored-confirmed'
        ;;
    restore)
        restore_state=$(cat "$BASE/state" 2>/dev/null || true)
        case "$restore_state" in
            restored-*) static_gate; [ "$(mount_count)" = 0 ]; runtime "$C_SHA" >/dev/null; dhcp_gate; config_gate; exit 0 ;;
            arming|active|restoring|restore-failed) ;;
            *) fail 'no activated trial to restore'; exit 1 ;;
        esac
        if [ -f "$LOCK/identity" ]; then
            [ "$(awk '{print $3}' "$LOCK/identity")" = "$TOKEN" ]
        fi
        if guard_alive; then
            put request restore
            printf '%s\n' 'early restoration queued'
        else
            # A dead guard can be recovered without touching any other service.
            # Exclusive retry ownership also avoids two callers doing stop/start.
            mkdir "$BASE/manual-recovery.lock"
            trap 'rmdir "$BASE/manual-recovery.lock"' EXIT
            restore_c manual
        fi
        ;;
    *) fail 'usage: trial.sh preflight|activate|confirm|restore TOKEN BOOT BUNDLE_SHA [HEALTH_SHA]'; exit 2 ;;
esac
