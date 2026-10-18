#!/bin/sh
# Temporary HFO toggle; restore the original firewall unless explicitly accepted.
# No reboot, module, network or Wi-Fi operations. Stage all inputs before arm.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
BASE=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
ACTION=${1:?check|arm|run|verify-candidate|verify-off|confirm|finish}
TOKEN=${2:?token}
BOOT=${3:?expected boot}
MANIFEST=${4:?bundle manifest SHA256}
HELPER_SHA=21609fa0e03e4a4595e74d266235a9566f2cc37f71571ad9315900d3def5cb49
LOCK=/tmp/owrt-offload-runtime.lock
now() { cut -d. -f1 /proc/uptime; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
put() { printf '%s\n' "$2" > "$BASE/$1.new"; mv -f "$BASE/$1.new" "$BASE/$1"; }
record() { printf 'uptime=%s %s\n' "$(now)" "$*" >> "$BASE/events.log"; }
bounded() { "$BASE/bounded" bounded 15 "$@"; }
identity() {
    [ "$(cat /proc/sys/kernel/random/boot_id)" = "$BOOT" ] &&
    [ "$(sha "$BASE/bundle.sha256")" = "$MANIFEST" ] &&
    (cd "$BASE"; sha256sum -c bundle.sha256 >/dev/null) &&
    [ "$(sha "$BASE/bounded")" = "$HELPER_SHA" ] || return 1
    # Optional settings are trusted only when covered by the supplied manifest.
    for file in original-hfo expected-wed candidate-firewall; do
        if [ -e "$BASE/$file" ] || [ -L "$BASE/$file" ]; then
            [ -f "$BASE/$file" ] && [ ! -L "$BASE/$file" ] &&
            grep -Fxq "$(sha "$BASE/$file")  $file" "$BASE/bundle.sha256" || return 1
        fi
    done
}
settings() {
    ORIGINAL_HFO=1; EXPECTED_WED=Y
    [ ! -f "$BASE/original-hfo" ] || ORIGINAL_HFO=$(cat "$BASE/original-hfo")
    [ ! -f "$BASE/expected-wed" ] || EXPECTED_WED=$(cat "$BASE/expected-wed")
    case "$ORIGINAL_HFO" in 0|1) ;; *) return 1;; esac
    case "$EXPECTED_WED" in Y|N) ;; *) return 1;; esac
    CANDIDATE_HFO=$((1 - ORIGINAL_HFO))
}
original_matches() {
    [ ! -L /etc/config/firewall ] &&
    cmp -s "$BASE/original-firewall" /etc/config/firewall &&
    [ "$(ls -ldn "$BASE/original-firewall" | awk '{print $1 ":" $3 ":" $4}')" = "$(ls -ldn /etc/config/firewall | awk '{print $1 ":" $3 ":" $4}')" ]
}
unchanged() {
    sha256sum -c "$BASE/unchanged.sha256" >/dev/null &&
    [ "$(cat /sys/module/mt7915e/parameters/wed_enable)" = "$EXPECTED_WED" ]
}
runtime() {
    wanted=$1
    [ "$(uci -q get firewall.@defaults[0].flow_offloading_hw)" = "$wanted" ] || return 1
    bounded nft -s list flowtable inet fw4 ft > "$BASE/runtime-$wanted.nft" || return 1
    grep -q 'flowtable ft' "$BASE/runtime-$wanted.nft" || return 1
    if [ "$wanted" = 1 ]; then
        grep -Eq '^[[:space:]]*flags[[:space:]]+offload;?[[:space:]]*$' "$BASE/runtime-$wanted.nft"
    else
        ! grep -Eq '^[[:space:]]*flags[[:space:]]+offload;?[[:space:]]*$' "$BASE/runtime-$wanted.nft"
    fi
}
preflight() {
    [ -f "$BASE/original-firewall" ] && [ ! -L "$BASE/original-firewall" ] &&
    [ -z "$(uci changes)" ] && original_matches && unchanged && runtime "$ORIGINAL_HFO"
}
candidate_matches() {
    [ -f "$BASE/candidate-firewall" ] && [ ! -L /etc/config/firewall ] &&
    cmp -s "$BASE/candidate-firewall" /etc/config/firewall &&
    [ "$(ls -ldn "$BASE/candidate-firewall" | awk '{print $1 ":" $3 ":" $4}')" = "$(ls -ldn /etc/config/firewall | awk '{print $1 ":" $3 ":" $4}')" ]
}
verify_candidate() {
    [ "$(cat "$BASE/state")" = armed ] &&
    [ "$(now)" -lt "$(cat "$BASE/deadline")" ] &&
    [ ! -e "$BASE/finish-requested" ] &&
    identity && [ -z "$(uci changes)" ] && candidate_matches &&
    unchanged && runtime "$CANDIDATE_HFO" &&
    [ "$(now)" -lt "$(cat "$BASE/deadline")" ] && [ ! -e "$BASE/finish-requested" ]
}
restore() {
    restored=1
    trap '' HUP INT TERM
    put state restoring
    identity || { record 'identity changed; refusing unverified restore'; return 1; }
    [ ! -L /etc/config/firewall ] || return 1
    # The rollback must also clear any incomplete experiment UCI transaction.
    uci -q revert firewall || return 1
    cp -p "$BASE/original-firewall" /etc/config/firewall.offload-restore
    cmp -s "$BASE/original-firewall" /etc/config/firewall.offload-restore
    mv -f /etc/config/firewall.offload-restore /etc/config/firewall
    original_matches || return 1
    for attempt in 1 2 3; do
        record "restore fw4 reload attempt=$attempt"
        if bounded fw4 reload > "$BASE/restore-$attempt.log" 2>&1 &&
           original_matches && unchanged && runtime "$ORIGINAL_HFO"; then
            put state restored
            record "original firewall bytes/mode and actual HFO=$ORIGINAL_HFO restored; WED unchanged"
            return 0
        fi
        [ "$attempt" = 3 ] || sleep 2
    done
    record 'bounded restore attempts exhausted; no wider action taken'
    return 1
}

[ "$(id -u)" = 0 ]
case "$TOKEN" in ''|*[!a-f0-9-]*) exit 2;; esac
[ "$BASE" = "/tmp/owrt-offload-runtime-$TOKEN" ]
identity
settings
case "$ACTION" in
    check)
        [ ! -e "$LOCK" ] && [ ! -e "$BASE/state" ]
        preflight
        ;;
    arm)
        seconds=${5:-600}
        case "$seconds" in ''|*[!0-9]*) exit 2;; esac
        [ "$seconds" -ge 60 ] && [ "$seconds" -le 600 ]
        [ ! -e "$LOCK" ] && [ ! -e "$BASE/state" ]
        preflight
        setsid /bin/sh "$BASE/guard.sh" run "$TOKEN" "$BOOT" "$MANIFEST" "$seconds" \
            </dev/null >> "$BASE/guard.log" 2>&1 &
        printf '%s\n' 'launched; wait for state armed before changing firewall'
        ;;
    run)
        seconds=${5:?deadline seconds}
        case "$seconds" in ''|*[!0-9]*) exit 2;; esac
        [ "$seconds" -ge 60 ] && [ "$seconds" -le 600 ]
        mkdir "$LOCK"
        printf '%s %s\n' "$$" "$TOKEN" > "$LOCK/owner"
        armed=0; restored=0; accepted=0; finish_requested=0
        trap '' HUP
        trap 'finish_requested=1' INT TERM
        trap 'rc=$?; trap - EXIT; if [ "$armed" = 1 ] && [ "$restored" = 0 ] && [ "$accepted" = 0 ]; then restore || rc=1; fi; if [ "$armed" = 0 ] || [ "$accepted" = 1 ] || [ "$(cat "$BASE/state" 2>/dev/null || true)" = restored ]; then rm -f "$LOCK/owner"; rmdir "$LOCK"; else put state recovery-failed || true; fi; exit "$rc"' EXIT
        preflight
        put guard.pid "$$"
        deadline=$(( $(now) + seconds ))
        put deadline "$deadline"
        armed=1
        put state armed
        record "armed; restore starts at deadline=$deadline or explicit finish; at most three bounded reload/read attempts"
        while [ "$(now)" -lt "$deadline" ] && [ "$finish_requested" = 0 ] && [ ! -e "$BASE/finish-requested" ]; do
            if [ -f "$BASE/accept-requested" ]; then
                # Only this process decides acceptance versus timeout/rollback.
                if [ "$(cat "$BASE/accept-requested")" = "$TOKEN $BOOT $MANIFEST" ] &&
                   verify_candidate && [ "$finish_requested" = 0 ] && [ ! -e "$BASE/finish-requested" ]; then
                    put state accepted
                    accepted=1
                    record "candidate HFO=$CANDIDATE_HFO accepted; WED=$EXPECTED_WED unchanged"
                    exit 0
                fi
                record 'accept request rejected; rollback remains armed'
                rm -f "$BASE/accept-requested"
            fi
            sleep 2
        done
        restore
        ;;
    verify-candidate)
        verify_candidate
        ;;
    verify-off)
        # Compatibility for original HFO-on/WED-on measurement bundles.
        [ "$(cat "$BASE/state")" = armed ]
        [ "$(now)" -lt "$(cat "$BASE/deadline")" ]
        unchanged && runtime 0
        ;;
    confirm)
        verify_candidate
        put accept-requested "$TOKEN $BOOT $MANIFEST"
        printf '%s\n' 'requested; wait for state accepted and guard exit before removing the bundle'
        ;;
    finish)
        [ "$(cat "$BASE/state")" = armed ]
        put finish-requested "$(now)"
        ;;
    *) exit 2;;
esac
