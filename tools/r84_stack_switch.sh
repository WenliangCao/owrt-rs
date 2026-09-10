#!/bin/sh
# Cold switch for all nine replacements. Never restarts a live system bus.
# Install as /root/r84/stack-switch.sh, alongside:
#   bins/{procd-rs,ubusd-rs,netifd-rs,...}, bundle.sha256 (relative to bins/),
#   original.sha256 (/rom paths), installed.sha256 (/usr/sbin Rust paths).
# Physical execution requires explicit deployment authorization and the
# AGENTS.md recovery gate. The canary cannot rescue a failed early PID 1:
# mesh-button failsafe over lan4 remains a mandatory independent fallback.
set -eu
BASE=$(cd "$(dirname "$0")" && pwd)
PENDING=/etc/r84-pending
CONFIRMED=/etc/r84-confirmed
REVERTING=/etc/r84-reverting
CANARY=/etc/init.d/r84-canary
CANARY_LINK=/etc/rc.d/S99r84-canary
COMPONENTS='uci reload-config logd httpd fw4 rpcd'

digest() { sha256sum "$1" | awk '{print $1}'; }
rom_gate() { sha256sum -c "$BASE/original.sha256" >/dev/null; }
bundle_gate() { (cd "$BASE/bins" && sha256sum -c "$BASE/bundle.sha256" >/dev/null); }
installed_gate() { sha256sum -c "$BASE/installed.sha256" >/dev/null; }

atomic_install() {
    src=$1; dst=$2
    cp "$src" "$dst.r84-new" || return 1
    chmod 755 "$dst.r84-new" || return 1
    cmp -s "$src" "$dst.r84-new" || return 1
    sync || return 1
    mv -f "$dst.r84-new" "$dst" || return 1
}

boot_mode() {
    mode=$1
    for c in $COMPONENTS; do
        if [ "$mode" = rust ]; then
            : > "/etc/owrt-$c.boot-enable" || return 1
            "/etc/init.d/owrt-$c" enable || return 1
        else
            rm -f "/etc/owrt-$c.boot-enable" || return 1
            "/etc/init.d/owrt-$c" disable || return 1
        fi
    done
    for s in rpcd log uhttpd; do
        if [ "$mode" = rust ]; then "/etc/init.d/$s" disable || return 1
        else "/etc/init.d/$s" enable || return 1; fi
    done
}

restore_stock() {
    rom_gate || return 1
    boot_mode stock || return 1
    for component in procd ubusd netifd; do
        atomic_install "/rom/sbin/$component" "/sbin/$component" || return 1
    done
    rm -f "$CANARY_LINK" || return 1
    printf 'stock\n' > "$BASE/next-boot-mode" || return 1
    sync || return 1
}

verify_live() {
    mode=$1
    rom_gate
    for component in procd ubusd netifd rpcd logd httpd; do
        case "$component" in
            procd) pid=1 ;;
            ubusd|netifd) pid=$(pidof "$component") ;;
            rpcd|logd|httpd)
                if [ "$mode" = rust ]; then name=$component-rs
                elif [ "$component" = httpd ]; then name=uhttpd
                else name=$component; fi
                pid=$(pidof "$name") ;;
        esac
        case "$pid" in ''|*[!0-9]*) echo "expected one $component process" >&2; return 1 ;; esac
        if [ "$mode" = rust ]; then expected=$(digest "$BASE/bins/$component-rs")
        elif [ "$component" = httpd ]; then expected=$(digest /rom/usr/sbin/uhttpd)
        else expected=$(digest "/rom/sbin/$component"); fi
        [ "$(digest "/proc/$pid/exe")" = "$expected" ] || {
            echo "running $component hash mismatch" >&2; return 1;
        }
        printf '%s %s %s\n' "$component" "$pid" "$expected"
    done
    for component in uci fw4 reload-config; do
        case "$component" in
            reload-config) target=reload_config; binary=reload_config_rs ;;
            *) target=$component; binary=$component-rs ;;
        esac
        if [ "$mode" = rust ]; then expected=$(digest "$BASE/bins/$binary")
        else expected=$(digest "/rom/sbin/$target"); fi
        [ "$(digest "/sbin/$target")" = "$expected" ] || {
            echo "active $component hash mismatch" >&2; return 1;
        }
        printf '%s - %s\n' "$component" "$expected"
    done
}

case "${1:-}:${2:-}" in
    stage:stock)
        [ ! -e "$PENDING" ] && [ ! -e "$REVERTING" ] || {
            echo 'a switch is already pending; resolve it first' >&2; exit 1;
        }
        restore_stock
        echo 'all-original OpenWrt staged for the next boot'
        ;;
    stage:rust)
        rom_gate; bundle_gate; installed_gate
        for pending in "$PENDING" "$REVERTING" /etc/p6-pending /etc/p6-reverting; do
            [ ! -e "$pending" ] || { echo "existing transition: $pending" >&2; exit 1; }
        done
        for component in procd ubusd netifd; do
            if [ -e "/sbin/$component.c-orig" ]; then
                cmp -s "/sbin/$component.c-orig" "/rom/sbin/$component"
            else cp -p "/rom/sbin/$component" "/sbin/$component.c-orig"; fi
        done
        # A failed staging operation must leave a coherent stock next boot.
        trap 'rc=$?; if [ "$rc" -ne 0 ]; then restore_stock; rm -f "$PENDING"; fi; exit "$rc"' EXIT
        cat > "$CANARY" <<'EOF'
#!/bin/sh /etc/rc.common
START=99
start() {
    [ -e /etc/r84-pending ] || return 0
    token=$(cat /etc/r84-pending)
    (
        sleep 900
        /bin/sh /root/r84/stack-switch.sh rollback "$token"
    ) </dev/null >>/root/r84/canary.log 2>&1 &
}
EOF
        chmod 755 "$CANARY"
        ln -sf ../init.d/r84-canary "$CANARY_LINK"
        (umask 077; cat /proc/sys/kernel/random/boot_id > "$PENDING")
        boot_mode rust
        for component in procd ubusd netifd; do
            atomic_install "$BASE/bins/$component-rs" "/sbin/$component"
        done
        printf 'rust\n' > "$BASE/next-boot-mode"
        sync
        echo 'latest Rust stack staged; unconfirmed boot restores all nine originals after 900 seconds'
        ;;
    verify:stock|verify:rust) verify_live "$2" ;;
    confirm:*)
        if [ ! -f "$PENDING" ]; then
            # Retrying a lost SSH response must be safe after a completed
            # confirmation, but cannot confirm a different staging window.
            [ -n "${2:-}" ] && [ -f "$CONFIRMED" ] && [ "$(cat "$CONFIRMED")" = "$2" ] || {
                echo 'no matching pending or confirmed switch' >&2; exit 1;
            }
            bundle_gate; installed_gate; verify_live rust
            echo 'this Rust window is already confirmed'
            exit 0
        fi
        [ -z "${2:-}" ] || [ "$(cat "$PENDING")" = "$2" ] || {
            echo 'confirmation token does not match staging window' >&2; exit 1;
        }
        [ "$(cat "$PENDING")" != "$(cat /proc/sys/kernel/random/boot_id)" ] || {
            echo 'not rebooted since staging' >&2; exit 1;
        }
        bundle_gate; installed_gate; verify_live rust
        # Atomic election with rollback: only one rename of PENDING succeeds.
        mv "$PENDING" "$CONFIRMED" || { echo 'rollback already began' >&2; exit 1; }
        rm -f "$CANARY_LINK" "$CANARY"
        sync
        echo 'Rust stack confirmed after client-side health observation'
        ;;
    rollback:*)
        mv "$PENDING" "$REVERTING" 2>/dev/null || exit 0
        # A sleeping timer from a confirmed window must not act on a later
        # staging operation in the same boot. Check after the atomic election.
        if [ -n "${2:-}" ] && [ "$(cat "$REVERTING")" != "$2" ]; then
            mv "$REVERTING" "$PENDING"
            exit 0
        fi
        echo "automatic stock rollback $(date -Iseconds)"
        if restore_stock; then
            rm -f "$REVERTING"
            sync
            reboot
        else
            mv "$REVERTING" "$PENDING"
            sync
            echo 'restore failed; recovery still pending' >&2
            exit 1
        fi
        ;;
    rescue:)
        # For failsafe after mount_root; no ubus or running Rust is required.
        restore_stock
        rm -f "$PENDING" "$REVERTING"
        echo 'stock restored; sync and reboot when ready'
        ;;
    *) echo 'usage: stack-switch.sh stage stock|rust | verify stock|rust | confirm | rollback | rescue' >&2; exit 2 ;;
esac
