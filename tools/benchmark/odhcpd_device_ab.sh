#!/bin/sh
# One frozen C/Rust batch, with a fresh private namespace for every sample.
# Usage: odhcpd_device_ab.sh IMAGE_ROOT BUNDLE NEW_OUTPUT [smoke]
# BUNDLE: ns-exec, odhcpd-probe, odhcpd-c, odhcpd-rs, this driver,
# odhcpd_device_provider.uc, odhcpd_device_update.sh, and bundle.sha256.
# "smoke" is Oracle-only functional validation (one A and one B), never data
# for the device performance gate. The default router schedule is immutable.
set -eu
C_SHA=53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82
R_SHA=c7c5f1f9e79ea80febe696d6c758db8d3463d1e4b94c7a002f1aa597b9c3ea30
start_ticks() { sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'; }

if [ "${1:-}" = --namespace ]; then
    shift
    [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
    image=$1 bundle=$2 out=$3 root=$4 side=$5 phase=$6 ordinal=$7
    mount --bind "$image" "$root"
    mount -o remount,bind,ro "$root"
    for directory in tmp etc dev; do mount -t tmpfs -o mode=0755 tmpfs "$root/$directory"; done
    chmod 1777 "$root/tmp"
    # OpenWrt /var is a symlink to /tmp. Refuse an unexpected layout rather
    # than accidentally expose persistent or production runtime sockets.
    case "$(readlink "$root/var")" in /tmp|tmp) ;; *) exit 125;; esac
    mkdir -p "$root/etc/config" "$root/tmp/bin" "$root/tmp/out" "$root/tmp/run/ubus" "$root/tmp/empty-acl"
    for name in passwd group protocols services; do
        [ ! -f "$image/etc/$name" ] || cp "$image/etc/$name" "$root/etc/$name"
    done
    mount --bind "$bundle" "$root/tmp/bin"
    mount -o remount,bind,ro "$root/tmp/bin"
    mount --bind "$out" "$root/tmp/out"
    mount --bind /proc "$root/proc"
    mount -t sysfs -o ro,nosuid,nodev,noexec sysfs "$root/sys"
    mount --bind "$root/tmp/empty-acl" "$root/usr/share/acl.d"
    for node in null:3 zero:5 random:8 urandom:9; do
        mknod -m 666 "$root/dev/${node%:*}" c 1 "${node#*:}"
    done
    ln -s /proc/self/fd "$root/dev/fd"
    ln -s /proc/self/fd/0 "$root/dev/stdin"
    ln -s /proc/self/fd/1 "$root/dev/stdout"
    ln -s /proc/self/fd/2 "$root/dev/stderr"
    mount --bind "$root/dev/null" "$root/proc/kmsg"
    exec chroot "$root" /bin/sh /tmp/bin/odhcpd_device_ab.sh --sample "$side" "$phase" "$ordinal"
fi

if [ "${1:-}" = --sample ]; then
    side=$2 phase=$3 ordinal=$4
    [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
    [ "$(cat /proc/1/comm)" = ns-exec ] || exit 125
    [ "$(ls /sys/class/net)" = lo ] || exit 125
    PATH=/usr/sbin:/usr/bin:/sbin:/bin
    export PATH
    ip link set lo up
    ip link add br-lan type bridge
    # Setting an empty bridge's MAC makes this kernel clear carrier. Keep its
    # generated MAC on both sides and archive it; all IPv6/client IDs are fixed.
    ip link set dev br-lan mtu 1500
    # BusyBox ip lacks the nodad keyword. This is the newly-created device's
    # netns-local setting, not the host default or a production interface.
    printf '0\n' > /proc/sys/net/ipv6/conf/br-lan/accept_dad
    # Private netns only. Empty bridges report UNKNOWN/LOWER_UP on this target;
    # check that before running subjects. No modules or physical ports needed.
    ip link set dev br-lan up
    ip -6 addr flush dev br-lan scope link
    ip -6 addr add fe80::2/64 dev br-lan
    # Linux enumerates newly added IPv6 addresses first. Keep the server's
    # fe80::1 first for both daemons' default source selection.
    ip -6 addr add fe80::1/64 dev br-lan
    ip -6 addr add 2001:db8:1::1/64 dev br-lan
    ip -6 addr add fd12:3456:789a::1/60 dev br-lan
    ip -6 route add default dev br-lan
    [ -z "$(ls /sys/class/net/br-lan/brif)" ]
    ip link show dev br-lan | grep -q LOWER_UP
    cat > /etc/config/dhcp <<'DHCP'
config odhcpd 'odhcpd'
 option maindhcp '0'
 option leasefile '/tmp/odhcpd.leases'
 option hostsdir '/tmp/hosts'
 option piodir '/tmp/odhcpd-piodir'
 option leasetrigger '/tmp/bin/lease-trigger'
 option loglevel '4'
config dhcp 'lan'
 option interface 'lan'
 option dhcpv4 'server'
 option start '100'
 option limit '150'
 option leasetime '12h'
 option dhcpv6 'server'
 option ra 'server'
 option ra_slaac '1'
 list ra_flags 'managed-config'
 list ra_flags 'other-config'
DHCP
    cat > /etc/config/network <<'NETWORK'
config globals 'globals'
config interface 'lan'
 option device 'br-lan'
 option proto 'static'
NETWORK
    cat > /etc/config/system <<'SYSTEM'
config system
 option timezone 'CET-1CEST,M3.5.0,M10.5.0/3'
 option zonename 'Europe/Berlin'
SYSTEM
    readlink /proc/self/ns/net > /tmp/out/netns.txt
    readlink /proc/self/ns/pid > /tmp/out/pidns.txt
    cat /proc/self/mountinfo > /tmp/out/mountinfo.txt
    ip link show > /tmp/out/links.txt
    cat /sys/class/net/br-lan/address > /tmp/out/bridge-mac.txt
    ip -6 addr show > /tmp/out/addresses-before.txt
    ip -6 route show table all > /tmp/out/routes-before.txt
    sha256sum /sbin/ubusd /usr/bin/ucode /bin/ubus /bin/busybox > /tmp/out/dependencies.sha256
    cd /tmp/out
    if [ "$side" = floor ]; then
        /tmp/bin/odhcpd-probe floor > measurements.jsonl 2> probe.stderr
        echo complete > COMPLETE
        exit 0
    fi
    case "$side" in A) elf=/tmp/bin/odhcpd-c; expected=$C_SHA;; B) elf=/tmp/bin/odhcpd-rs; expected=$R_SHA;; *) exit 2;; esac
    [ "$(sha256sum "$elf" | cut -d' ' -f1)" = "$expected" ]
    printf '{"schema_version":1,"phase":"%s","ordinal":%s,"side":"%s","elf_sha256":"%s"}\n' "$phase" "$ordinal" "$side" "$expected" > identity.json
    /sbin/ubusd > ubusd.log 2>&1 & bus=$!
    tries=0
    while [ ! -S /var/run/ubus/ubus.sock ]; do kill -0 "$bus"; tries=$((tries+1)); [ "$tries" -lt 10 ]; sleep 1; done
    /usr/bin/ucode /tmp/bin/odhcpd_device_provider.uc > provider.log 2>&1 & provider=$!
    tries=0
    while [ ! -f /tmp/provider.ready ]; do kill -0 "$provider"; tries=$((tries+1)); [ "$tries" -lt 10 ]; sleep 1; done
    "$elf" -f > daemon.log 2>&1 & subject=$!
    printf '%s %s\n' "$subject" "$(start_ticks "$subject")" > subject.id
    tries=0
    while [ "$(ubus -S -t 1 list dhcp 2>/dev/null || true)" != dhcp ]; do
        kill -0 "$subject"; tries=$((tries+1)); [ "$tries" -lt 10 ]; sleep 1
    done
    /tmp/bin/odhcpd-probe run "$subject" /tmp/bin/odhcpd_device_update.sh > measurements.jsonl 2> probe.stderr
    kill -0 "$subject"; kill -0 "$provider"; kill -0 "$bus"
    [ "$(sha256sum /proc/$subject/exe | cut -d' ' -f1)" = "$expected" ]
    [ "$(cat subject.id)" = "$subject $(start_ticks "$subject")" ]
    ubus -S -t 2 call fixture stats > provider-final.json
    [ "$(jsonfilter -i provider-final.json -e '@.sequence')" = 8 ]
    [ "$(jsonfilter -i provider-final.json -e '@.notifications')" = 8 ]
    [ "$(jsonfilter -i provider-final.json -e '@.subscribed')" = true ]
    ubus -S -t 2 call dhcp ipv6leases > leases-final.json
    ubus -S -t 2 call dhcp ipv6ra > ra-final.json
    /usr/bin/ucode -e 'import {readfile} from "fs"; let data=json(readfile("leases-final.json")); let na=0,pd=0,bound=0; for(let lease in data.device["br-lan"].leases) { if(lease["ipv6-addr"]) na++; if(lease["ipv6-prefix"]) pd++; for(let flag in lease.flags) if(flag=="bound") bound++; } if(na!=3 || pd!=0 || bound!=3) die("unexpected final lease population"); print({na,pd,bound});' > lease-counts.json
    [ -f /tmp/odhcpd.leases ] && cp /tmp/odhcpd.leases leases-final.txt
    mkdir hosts-final
    for file in /tmp/hosts/*; do [ ! -f "$file" ] || cp "$file" hosts-final/; done
    ip -6 addr show > addresses-after.txt
    ip -6 route show table all > routes-after.txt
    echo complete > COMPLETE
    exit 0
fi

[ "$#" -ge 3 ] && [ "$#" -le 4 ] || exit 2
image=$(cd "$1" && pwd -P)
bundle=$(cd "$2" && pwd -P)
out=$3 mode=${4:-device}
case "$out" in /*) ;; *) echo 'output must be absolute' >&2; exit 2;; esac
[ ! -e "$out" ]
case "$mode" in
    device) [ "$image" = / ]; schedule='A B B A A B A B B A B A A B';;
    smoke) [ ! -f /etc/openwrt_release ]; schedule='A B';;
    *) exit 2;;
esac
(cd "$bundle"; sha256sum -c bundle.sha256)
for file in ns-exec odhcpd-probe odhcpd-c odhcpd-rs odhcpd_device_update.sh lease-trigger; do [ -x "$bundle/$file" ]; done
[ "$(sha256sum "$bundle/odhcpd-c" | cut -d' ' -f1)" = "$C_SHA" ]
[ "$(sha256sum "$bundle/odhcpd-rs" | cut -d' ' -f1)" = "$R_SHA" ]
mkdir -m 700 "$out"
cat /proc/sys/kernel/random/boot_id > "$out/boot-before.txt"
cat /proc/meminfo > "$out/meminfo-before.txt"
readlink /proc/self/ns/net > "$out/parent-netns.txt"
cp "$bundle/bundle.sha256" "$out/bundle.sha256"
printf '%s\n' "$mode" > "$out/mode.txt"
child= watchdog=
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    [ "$result" -eq 0 ] || printf 'batch failed rc=%s\n' "$result" > "$out/FAILED"
    for pid in "$child" "$watchdog"; do [ -z "$pid" ] || kill -TERM "$pid" 2>/dev/null || true; done
    for pid in "$child" "$watchdog"; do [ -z "$pid" ] || wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'exit 124' HUP INT TERM
parent=$$; parent_start=$(start_ticks "$$")
(
    sleeper=
    trap '[ -z "$sleeper" ] || kill "$sleeper" 2>/dev/null || true; exit 0' HUP INT TERM
    began=$(cut -d. -f1 /proc/uptime)
    while [ "$(start_ticks "$parent")" = "$parent_start" ]; do
        [ $(( $(cut -d. -f1 /proc/uptime) - began )) -lt 600 ] || break
        sleep 1 & sleeper=$!
        wait "$sleeper"; sleeper=
    done
    if [ "$(start_ticks "$parent")" = "$parent_start" ]; then
        printf '600 second batch deadline\n' > "$out/TIMEOUT"
    else
        printf 'controller disappeared\n' > "$out/OWNER_DIED"
    fi
    if [ -f "$out/active-namespace.id" ]; then
        read -r pid born < "$out/active-namespace.id"
        [ "$(start_ticks "$pid")" != "$born" ] || kill -TERM "$pid" 2>/dev/null || true
    fi
    [ "$(start_ticks "$parent")" != "$parent_start" ] || kill -TERM "$parent" 2>/dev/null || true
) & watchdog=$!
sample() {
    side=$1 phase=$2 ordinal=$3 id=$4
    directory=$out/$id
    mkdir "$directory" "$directory/root"
    "$bundle/ns-exec" /bin/sh "$bundle/odhcpd_device_ab.sh" --namespace "$image" "$bundle" "$directory" "$directory/root" "$side" "$phase" "$ordinal" > "$directory/driver.log" 2>&1 &
    child=$!
    printf '%s %s\n' "$child" "$(start_ticks "$child")" > "$out/active-namespace.id"
    wait "$child"; child=
    rm "$out/active-namespace.id"
    [ -f "$directory/COMPLETE" ]
    [ "$(cat "$directory/netns.txt")" != "$(cat "$out/parent-netns.txt")" ]
    rmdir "$directory/root"
}
sample floor floor 0 floor
index=0
for side in $schedule; do
    if [ "$mode" = smoke ]; then phase=smoke; ordinal=$index
    elif [ "$index" -lt 6 ]; then phase=calibration; ordinal=$index
    else phase=formal; ordinal=$((index-6)); fi
    sample "$side" "$phase" "$ordinal" "$phase-$ordinal-$side"
    index=$((index+1))
done
cat /proc/sys/kernel/random/boot_id > "$out/boot-after.txt"
cmp "$out/boot-before.txt" "$out/boot-after.txt"
cat /proc/meminfo > "$out/meminfo-after.txt"
echo complete > "$out/COMPLETE"
