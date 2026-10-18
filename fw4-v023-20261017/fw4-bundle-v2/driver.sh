#!/bin/sh
# A single persistent private namespace. No implicit samples or timing policy.
# Usage: driver.sh IMAGE_ROOT BUNDLE OUTPUT
# Control FIFO commands: SCENE A|B SAMPLE_ID ; or "stop".
# IMAGE_ROOT may be / on the router: bind read-only, then private tmp/etc/dev.
set -eu
if [ "${1:-}" = --namespace ]; then
    shift
    [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
    image=$1 bundle=$2 out=$3 root=$4
    mount --bind "$image" "$root"
    mount -o remount,bind,ro "$root"
    for dir in tmp etc dev; do mount -t tmpfs -o mode=0755 tmpfs "$root/$dir"; done
    mkdir -p "$root/tmp/bin" "$root/tmp/out" "$root/tmp/run/ubus" "$root/etc/config" "$root/etc/nftables.d" "$root/tmp/empty-includes"
    for file in protocols services passwd group; do
        [ ! -f "$image/etc/$file" ] || cp "$image/etc/$file" "$root/etc/$file"
    done
    mount --bind "$bundle" "$root/tmp/bin"
    mount -o remount,bind,ro "$root/tmp/bin"
    mount --bind "$out" "$root/tmp/out"
    mount --bind /proc "$root/proc"
    mount -t sysfs -o ro,nosuid,nodev,noexec sysfs "$root/sys"
    mount --bind "$root/tmp/empty-includes" "$root/usr/share/nftables.d"
    mknod -m 666 "$root/dev/null" c 1 3
    mknod -m 666 "$root/dev/zero" c 1 5
    mknod -m 666 "$root/dev/urandom" c 1 9
    ln -s /proc/self/fd "$root/dev/fd"
    ln -s /proc/self/fd/0 "$root/dev/stdin"
    mount --bind "$root/dev/null" "$root/proc/kmsg"
    exec chroot "$root" /bin/sh /tmp/bin/driver.sh --workload
fi

if [ "${1:-}" = --workload ]; then
    [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
    [ "$(cat /proc/1/comm)" = ns-exec ] || exit 125
    [ "$(ls /sys/class/net)" = lo ] || exit 125
    unset FW4_MOCK_DIRS FW4_TRACE QUIET TTY
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    ip link set lo up
    # bridge support is already used by the production LAN; no module install
    # or physical interface is needed. These bridges have no attached ports.
    ip link add wan type bridge
    ip link add br-lan type bridge
    ip link set wan up
    ip link set br-lan up
    cp /tmp/bin/comments.nft /etc/nftables.d/10-custom-filter-chains.nft
    sha256sum /sbin/ubusd /usr/bin/ucode /usr/sbin/nft /usr/share/firewall4/helpers > /tmp/out/dependencies.sha256
    readlink /proc/self/ns/net > /tmp/out/netns.txt
    ip link show > /tmp/out/links.txt
    /sbin/ubusd > /tmp/out/ubusd.log 2>&1 &
    bus=$!
    n=0
    while [ ! -S /var/run/ubus/ubus.sock ]; do
        kill -0 "$bus"; [ "$n" -lt 100 ]; n=$((n+1)); sleep 0.02
    done
    /usr/bin/ucode /tmp/bin/fixture.uc > /tmp/out/fixture.log 2>&1 &
    provider=$!
    n=0
    while [ ! -f /tmp/out/fixture.ready ]; do
        kill -0 "$provider"; [ "$n" -lt 100 ]; n=$((n+1)); sleep 0.02
    done
    ubus list > /tmp/out/objects.txt
    printf 'fixture\nnetwork.interface\nservice\n' > /tmp/objects.expected
    cmp /tmp/out/objects.txt /tmp/objects.expected
    cat /proc/$bus/status > /tmp/out/ubusd.status
    cat /proc/$provider/status > /tmp/out/fixture.status
    exec 7<> /tmp/out/control
    printf 'ready\n' > /tmp/out/READY
    while read -r scene side id extra <&7; do
        [ "$scene" != stop ] || exit 0
        case "$scene" in unchanged|changed|start|check|print) ;; *) exit 2;; esac
        case "$side" in A) elf=/tmp/bin/fw4-v022;; B) elf=/tmp/bin/fw4-v023;; *) exit 2;; esac
        case "$id" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
        [ -z "$extra" ]
        sample=/tmp/out/$id
        mkdir "$sample"
        printf '%s %s\n' "$scene" "$side" > "$sample/request"
        sha256sum "$elf" > "$sample/elf.sha256"
        # All initial state changes are outside the timed command.
        nft flush ruleset
        rm -f /var/run/fw4.state /var/run/fw4.reload-state /var/run/fw4.reload-state.tmp
        cp /tmp/bin/firewall-a /etc/config/firewall
        ubus call fixture select '{"variant":0}' > "$sample/select-a.json"
        if [ "$scene" != start ]; then
            "$elf" start > "$sample/setup-start.stdout" 2> "$sample/setup-start.stderr"
            "$elf" reload > "$sample/setup-reload.stdout" 2> "$sample/setup-reload.stderr"
            nft -s list flowtable inet fw4 ft > "$sample/flowtable-before.nft"
            if [ "$side" = B ]; then [ -s /var/run/fw4.reload-state ]; fi
        fi
        action=$scene
        case "$scene" in
            unchanged)
                action=reload
                ubus call fixture select '{"variant":1}' > "$sample/select-b.json"
                ;;
            changed)
                action=reload
                cp /tmp/bin/firewall-b /etc/config/firewall
                ;;
        esac
        nft -a -s list ruleset > "$sample/before.nft"
        stdout=$sample/stdout
        [ "$scene" != print ] || stdout=/dev/null
        /tmp/bin/exec-sample "$sample/measurement.json" "$stdout" "$sample/stderr" "$elf" "$action"
        nft -a -s list ruleset > "$sample/after.nft"
        [ ! -s "$sample/stderr" ]
        case "$scene:$side" in
            unchanged:B|check:*|print:*) cmp "$sample/before.nft" "$sample/after.nft";;
            *) if cmp -s "$sample/before.nft" "$sample/after.nft"; then exit 3; fi;;
        esac
        nft -s list flowtable inet fw4 ft > "$sample/flowtable-after.nft"
        if [ "$scene" = changed ]; then grep -q 'dport 41001' "$sample/after.nft"; fi
        if [ "$scene" = start ]; then [ ! -s "$sample/before.nft" ]; fi
        printf 'complete\n' > "$sample/COMPLETE"
    done
    exit 0
fi

[ "$#" = 3 ] || exit 2
image=$1 bundle=$2 out=$3
[ -d "$image" ] && [ -d "$bundle" ] && [ ! -e "$out" ]
mkdir -m 700 "$out"
mkdir "$out/root"
mkfifo -m 600 "$out/control"
sha256sum "$bundle"/* > "$out/bundle.sha256"
readlink /proc/self/ns/net > "$out/parent-netns.txt"
exec "$bundle/ns-exec" /bin/sh "$bundle/driver.sh" --namespace "$image" "$bundle" "$out" "$out/root"
