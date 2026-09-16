#!/bin/sh
# Restore all nine Rust control-plane replacements to the exact C programs in
# this router's immutable OpenWrt 25.12.5 /rom, then cold boot into that stack.
#
# This is not a factory reset. It preserves /etc/config, installed packages,
# keys and user data. The Rust packages and retained bundles stay on disk but
# are inactive after the reboot.
#
# Run from the repository checkout:
#   ssh openwrt 'sh -s preflight' < tools/restore_all_stock.sh
#   ssh openwrt 'sh -s apply-and-reboot' < tools/restore_all_stock.sh
#   ssh openwrt 'sh -s postcheck' < tools/restore_all_stock.sh
set -eu

EXPECTED_RELEASE="25.12.5"
EXPECTED_REVISION="r33051-f5dae5ece4"
EXPECTED_BOARD="xiaomi,mi-router-ax3000t"
COMPONENTS="uci reload-config logd httpd fw4 rpcd"

die() {
    echo "restore-all-stock: $*" >&2
    exit 1
}

digest() {
    sha256sum "$1" | awk '{print $1}'
}

require_sha256() {
    expected=$1
    path=$2
    [ -f "$path" ] || die "missing required file: $path"
    actual=$(digest "$path")
    [ "$actual" = "$expected" ] || \
        die "identity mismatch for $path: expected $expected, got $actual"
}

require_no_transition() {
    for marker in \
        /etc/r84-pending /etc/r84-reverting \
        /etc/p6-pending /etc/p6-reverting
    do
        [ ! -e "$marker" ] || \
            die "existing deployment transition $marker; do not overlap recovery operations"
    done
}

require_originals() {
    require_sha256 c240b413a4cf80617ac1a71f601d2e0edae46b0493e3c00fbe883b2446e4a1a6 /rom/sbin/fw4
    require_sha256 1f8dc03d563489626215a1e7b33ebac693737e39e3f8d862a5d836c178b491b3 /rom/usr/sbin/uhttpd
    require_sha256 894c81b683662b57756e0462f66d12c1a3a5c0255863e645d9210e122e9b7a89 /rom/sbin/logd
    require_sha256 8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90 /rom/sbin/netifd
    require_sha256 36269ae10ae267b9753233bfecdea48bd6fed4b2f7980f722f96413bd2ca681a /rom/sbin/procd
    require_sha256 f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15 /rom/sbin/reload_config
    require_sha256 94bed60981a6e71638b5bb4552c1f3539c550d4625af7d5ada7d71bbafdb8947 /rom/sbin/rpcd
    require_sha256 cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88 /rom/sbin/ubusd
    require_sha256 050e9ab320b794f636174536ca4dbca2f615a1c6c37bc19e9ca06bfd6d6e7278 /rom/sbin/uci
}

preflight() {
    [ "$(id -u)" -eq 0 ] || die "must run as root on the router"
    [ -f /etc/openwrt_release ] || die "not an OpenWrt system"
    grep -Fqx "DISTRIB_RELEASE='$EXPECTED_RELEASE'" /etc/openwrt_release || \
        die "unexpected OpenWrt release"
    grep -Fqx "DISTRIB_REVISION='$EXPECTED_REVISION'" /etc/openwrt_release || \
        die "unexpected OpenWrt revision"
    [ -r /tmp/sysinfo/board_name ] || die "missing board identity"
    [ "$(cat /tmp/sysinfo/board_name)" = "$EXPECTED_BOARD" ] || \
        die "unexpected board: $(cat /tmp/sysinfo/board_name)"

    command -v sha256sum >/dev/null 2>&1 || die "sha256sum is unavailable"
    command -v sysupgrade >/dev/null 2>&1 || die "sysupgrade backup tool is unavailable"
    require_originals
    require_no_transition
    for component in $COMPONENTS; do
        [ -x "/etc/init.d/owrt-$component" ] || \
            die "missing Rust boot service control: /etc/init.d/owrt-$component"
    done
    for service in rpcd log uhttpd; do
        [ -x "/etc/init.d/$service" ] || \
            die "missing stock boot service control: /etc/init.d/$service"
    done

    echo "preflight: exact AX3000T OpenWrt image confirmed"
    echo "preflight: all nine immutable C originals confirmed"
    echo "preflight: stock and Rust boot service controls confirmed"
    echo "preflight: no deployment transition is pending"
}

make_backup() {
    stamp=$(date +%Y%m%d-%H%M%S)-$$
    backup="/root/pre-stock-rollback-$stamp.tar.gz"
    partial="$backup.part"
    state="/root/pre-stock-rollback-$stamp.state.txt"

    rm -f "$partial"
    sysupgrade -b "$partial"
    gzip -t "$partial"
    tar -tzf "$partial" >/dev/null
    chmod 600 "$partial"
    mv "$partial" "$backup"

    {
        echo "created=$(date -Iseconds)"
        echo "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
        echo "config_backup=$backup"
        echo "config_backup_sha256=$(digest "$backup")"
        echo "requested_next_boot=stock"
        if command -v owrt-switch >/dev/null 2>&1; then
            echo "owrt_switch_status_begin"
            owrt-switch status 2>&1 || true
            echo "owrt_switch_status_end"
        fi
    } > "$state"
    chmod 600 "$state"
    sync

    echo "backup: $backup"
    echo "backup-sha256: $(digest "$backup")"
    echo "state: $state"
}

atomic_install() {
    src=$1
    dst=$2
    tmp="$dst.restore-all-stock-new"

    rm -f "$tmp"
    cp "$src" "$tmp"
    chmod 755 "$tmp"
    cmp -s "$src" "$tmp" || die "copy verification failed for $dst"
    sync
    mv -f "$tmp" "$dst"
}

stage_stock() {
    # This is the stock half of the reviewed R92 cold-switch procedure,
    # embedded here so recovery does not depend on a retained /root bundle.
    # Do not hot-restart the live bus or daemons; only change the next boot.
    for component in $COMPONENTS; do
        rm -f "/etc/owrt-$component.boot-enable"
        "/etc/init.d/owrt-$component" disable
    done
    for service in rpcd log uhttpd; do
        "/etc/init.d/$service" enable
    done
    for component in procd ubusd netifd; do
        atomic_install "/rom/sbin/$component" "/sbin/$component"
    done
    rm -f /etc/rc.d/S99r84-canary
    sync

    echo "all-original OpenWrt staged for the next boot"
}

verify_staged() {
    for component in procd ubusd netifd; do
        cmp -s "/sbin/$component" "/rom/sbin/$component" || \
            die "$component was not restored from /rom"
    done
    for component in $COMPONENTS; do
        [ ! -e "/etc/owrt-$component.boot-enable" ] || \
            die "Rust boot flag remains for $component"
        if "/etc/init.d/owrt-$component" enabled >/dev/null 2>&1; then
            die "Rust boot service remains enabled for $component"
        fi
    done
    for service in rpcd log uhttpd; do
        "/etc/init.d/$service" enabled >/dev/null 2>&1 || \
            die "stock boot service is not enabled: $service"
    done
    [ ! -e /etc/rc.d/S99r84-canary ] || die "Rust rollback canary remains enabled"
    require_no_transition
    sync

    echo "staged: next boot will use all nine C components"
}

verify_live_process() {
    label=$1
    pid=$2
    original=$3
    case "$pid" in
        ''|*[!0-9]*) die "expected exactly one running $label process, got: ${pid:-none}" ;;
    esac
    expected=$(digest "$original")
    actual=$(digest "/proc/$pid/exe")
    [ "$actual" = "$expected" ] || \
        die "running $label is not the C original: expected $expected, got $actual"
    echo "live: $label pid=$pid sha256=$actual"
}

verify_live_stock() {
    verify_live_process procd 1 /rom/sbin/procd

    pid=$(pidof ubusd 2>/dev/null || true)
    verify_live_process ubusd "$pid" /rom/sbin/ubusd
    pid=$(pidof netifd 2>/dev/null || true)
    verify_live_process netifd "$pid" /rom/sbin/netifd
    pid=$(pidof rpcd 2>/dev/null || true)
    verify_live_process rpcd "$pid" /rom/sbin/rpcd
    pid=$(pidof logd 2>/dev/null || true)
    verify_live_process logd "$pid" /rom/sbin/logd
    pid=$(pidof uhttpd 2>/dev/null || true)
    verify_live_process uhttpd "$pid" /rom/usr/sbin/uhttpd

    require_sha256 050e9ab320b794f636174536ca4dbca2f615a1c6c37bc19e9ca06bfd6d6e7278 /sbin/uci
    require_sha256 c240b413a4cf80617ac1a71f601d2e0edae46b0493e3c00fbe883b2446e4a1a6 /sbin/fw4
    require_sha256 f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15 /sbin/reload_config
    echo "live: uci, fw4 and reload_config are C originals"
}

apply_and_reboot() {
    preflight
    make_backup
    stage_stock
    verify_staged
    echo "reboot: starting in 3 seconds; this SSH session will disconnect"
    sync
    sleep 3
    reboot
}

postcheck() {
    preflight
    verify_live_stock
    verify_staged

    echo "postcheck: all nine running/active component identities are C originals"
    if ip -4 route show default | grep -q '^default '; then
        echo "postcheck: IPv4 default route present"
        ip -4 route show default
    else
        echo "postcheck: IPv4 default route is still missing" >&2
        exit 1
    fi
    if ping -c 3 -W 2 1.1.1.1 >/dev/null 2>&1; then
        echo "postcheck: WAN IPv4 reachability passed (1.1.1.1)"
    else
        echo "postcheck: C stack is active, but WAN IPv4 reachability still fails" >&2
        exit 1
    fi
}

case "${1:-}" in
    preflight) preflight ;;
    apply-and-reboot) apply_and_reboot ;;
    postcheck) postcheck ;;
    *)
        echo "usage: sh restore_all_stock.sh preflight|apply-and-reboot|postcheck" >&2
        exit 2
        ;;
esac
