#!/bin/sh
# Whole-stack trial lease, independent of the 900-second boot canary.
# Install in /root/r84/tools. arm before the Rust boot; disarm only in stock.
set -eu
BASE=/root/r84
PENDING=$BASE/trial.pending
CLAIMED=$BASE/trial.reverting
INIT=/etc/init.d/owrt-stack-trial
LINK=/etc/rc.d/S98owrt-stack-trial

restore() {
    token=$1
    mv "$PENDING" "$CLAIMED" 2>/dev/null || return 0
    if [ "$(head -n 1 "$CLAIMED")" != "$token" ]; then
        mv "$CLAIMED" "$PENDING"
        return 0
    fi
    if /bin/sh "$BASE/stack-switch.sh" rescue; then
        rm -f "$CLAIMED" "$LINK" "$INIT"
        sync
        reboot
    else
        mv "$CLAIMED" "$PENDING"
        return 1
    fi
}

case "${1:-}" in
    arm)
        seconds=${2:?duration required}
        case "$seconds" in ''|*[!0-9]*) exit 2 ;; esac
        if [ "$seconds" -lt 1 ] || [ "$seconds" -gt 7200 ]; then exit 2; fi
        for path in "$PENDING" "$CLAIMED" "$INIT" "$LINK"; do
            if [ -e "$path" ] || [ -L "$path" ]; then
                echo "existing trial state: $path" >&2
                exit 1
            fi
        done
        token=$(cat /proc/sys/kernel/random/uuid)
        (umask 077; printf '%s\n%s\n' "$token" "$seconds" > "$PENDING")
        cat > "$INIT" <<'EOF'
#!/bin/sh /etc/rc.common
START=98
start() {
    [ -f /root/r84/trial.pending ] || return 0
    /bin/sh /root/r84/tools/stack_trial_guard.sh run </dev/null >>/root/r84/trial-guard.log 2>&1 &
}
EOF
        chmod 755 "$INIT"
        ln -s ../init.d/owrt-stack-trial "$LINK"
        sync
        printf '%s\n' "$token"
        ;;
    run)
        [ -f "$PENDING" ] || exit 0
        token=$(head -n 1 "$PENDING")
        seconds=$(tail -n 1 "$PENDING")
        case "$seconds" in ''|*[!0-9]*) exit 2 ;; esac
        if [ "$seconds" -lt 1 ] || [ "$seconds" -gt 7200 ]; then exit 2; fi
        sleep "$seconds"
        restore "$token"
        ;;
    restore)
        restore "${2:?token required}"
        ;;
    disarm)
        /bin/sh "$BASE/stack-switch.sh" verify stock >/dev/null
        [ ! -e "$CLAIMED" ]
        rm -f "$PENDING" "$LINK" "$INIT"
        sync
        ;;
    *) echo 'usage: stack_trial_guard.sh arm SECONDS | run | restore TOKEN | disarm' >&2; exit 2 ;;
esac
