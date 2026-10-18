#!/bin/sh
# Temporary HFO-off measurement; always restore the original HFO-on firewall.
# No reboot, module, network or Wi-Fi operations. Stage all inputs before arm.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
BASE=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
ACTION=${1:?check|arm|run|verify-off|finish}
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
    [ "$(sha "$BASE/bounded")" = "$HELPER_SHA" ]
}
original_matches() {
    [ ! -L /etc/config/firewall ] &&
    cmp -s "$BASE/original-firewall" /etc/config/firewall &&
    [ "$(ls -ldn "$BASE/original-firewall" | awk '{print $1 ":" $3 ":" $4}')" = "$(ls -ldn /etc/config/firewall | awk '{print $1 ":" $3 ":" $4}')" ]
}
unchanged() {
    sha256sum -c "$BASE/unchanged.sha256" >/dev/null &&
    [ "$(cat /sys/module/mt7915e/parameters/wed_enable)" = Y ]
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
    [ -z "$(uci changes)" ] && original_matches && unchanged && runtime 1
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
           original_matches && unchanged && runtime 1; then
            put state restored
            record 'original firewall bytes/mode and actual hardware flowtable restored; WED unchanged'
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
        armed=0; restored=0; finish_requested=0
        trap '' HUP
        trap 'finish_requested=1' INT TERM
        trap 'rc=$?; trap - EXIT; if [ "$armed" = 1 ] && [ "$restored" = 0 ]; then restore || rc=1; fi; if [ "$armed" = 0 ] || [ "$(cat "$BASE/state" 2>/dev/null || true)" = restored ]; then rm -f "$LOCK/owner"; rmdir "$LOCK"; else put state recovery-failed || true; fi; exit "$rc"' EXIT
        preflight
        put guard.pid "$$"
        deadline=$(( $(now) + seconds ))
        put deadline "$deadline"
        armed=1
        put state armed
        record "armed; restore starts at deadline=$deadline or explicit finish; at most three bounded reload/read attempts"
        while [ "$(now)" -lt "$deadline" ] && [ "$finish_requested" = 0 ] && [ ! -e "$BASE/finish-requested" ]; do sleep 2; done
        restore
        ;;
    verify-off)
        [ "$(cat "$BASE/state")" = armed ]
        [ "$(now)" -lt "$(cat "$BASE/deadline")" ]
        unchanged && runtime 0
        ;;
    finish)
        [ "$(cat "$BASE/state")" = armed ]
        put finish-requested "$(now)"
        ;;
    *) exit 2;;
esac
