#!/bin/sh
# One persistent side of the externally frozen eight-event A/B batch.
# ROOTFS BUNDLE SUBJECT_NAME NEW_OUT A|B
# Wait for READY, then write the common T0_MONOTONIC_NS to start.fifo once.
# BUNDLE: ns-exec, netifd-renewal-cpu, and the frozen subject ELF(s).
set -eu

if [ "${1:-}" = --workload ]; then
    shift
    [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
    subject=$1; side=$2
    probe=/tmp/bench/netifd-renewal-cpu
    socket=/var/run/ubus/ubus.sock
    [ "$(cat /proc/1/comm)" = ns-exec ] || exit 125
    interfaces=0
    for device in /sys/class/net/*; do
        [ "${device##*/}" = lo ] || exit 125
        interfaces=$((interfaces + 1))
    done
    [ "$interfaces" -eq 1 ] || exit 125
    mkdir -p /var/run/ubus /var/lock /var/state /tmp/resolv.conf.d
    cat > /etc/config/network <<'NETWORK'
config interface 'loopback'
 option device 'lo'
 option proto 'static'
 option ipaddr '127.0.0.1/8'
config device 'bench_wan'
 option name 'wan'
 option type 'bridge'
 option bridge_empty '1'
config interface 'wan'
 option device 'wan'
 option proto 'renewaltest'
 option force_link '1'
NETWORK
    : > /etc/config/wireless
    cat > /lib/netifd/proto/renewaltest.sh <<'PROTO'
#!/bin/sh
. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"
proto_renewaltest_init_config() { :; }
proto_renewaltest_setup() {
 proto_init_update "$2" 1
 proto_send_update "$1"
}
proto_renewaltest_teardown() { :; }
add_protocol renewaltest
PROTO
    chmod 755 /lib/netifd/proto/renewaltest.sh
    echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
    ip link set lo up
    sha256sum "/tmp/bench/$subject" "$probe" /sbin/ubusd > /tmp/out/identities.sha256
    /sbin/ubusd -s "$socket" > /tmp/out/ubusd.log 2>&1 &
    bus=$!
    tries=0
    while [ ! -S "$socket" ]; do
        kill -0 "$bus"
        tries=$((tries + 1)); [ "$tries" -lt 50 ] || exit 1
        sleep 1
    done
    "/tmp/bench/$subject" -S -s "$socket" > /tmp/out/netifd.log 2>&1 &
    subject_pid=$!
    printf '%s\n' "$subject_pid" > /tmp/out/subject.pid
    tries=0
    while ! ubus -s "$socket" call network.interface.wan status 2>/dev/null | grep -Eq '"up"[[:space:]]*:[[:space:]]*true'; do
        kill -0 "$subject_pid"
        tries=$((tries + 1)); [ "$tries" -lt 100 ] || exit 1
        sleep 1
    done
    "$probe" prepare "$socket" "$subject_pid" network.interface.wan > /tmp/out/prepared.json
    ip -4 addr show dev wan > /tmp/out/addresses.before
    ip -4 route show > /tmp/out/routes.before
    grep -q 'inet 192.0.2.2/24' /tmp/out/addresses.before
    grep -q '^default via 192.0.2.1 dev wan' /tmp/out/routes.before
    readlink /proc/self/ns/net > /tmp/out/netns
    readlink /proc/self/ns/pid > /tmp/out/pidns
    mkfifo /tmp/out/start.fifo
    printf '%s\n' "$side" > /tmp/out/READY
    read -r t0 < /tmp/out/start.fifo
    case "$t0" in ''|*[!0-9]*) exit 2 ;; esac
    printf '%s\n' "$t0" > /tmp/out/t0.ns
    "$probe" run "$socket" "$subject_pid" network.interface.wan "$side" "$t0" > /tmp/out/samples.jsonl
    ip -4 addr show dev wan > /tmp/out/addresses.after
    ip -4 route show > /tmp/out/routes.after
    cmp /tmp/out/addresses.before /tmp/out/addresses.after
    cmp /tmp/out/routes.before /tmp/out/routes.after
    kill -0 "$bus"
    kill -0 "$subject_pid"
    echo complete > /tmp/out/COMPLETE
    exit 0
fi

if [ "${1:-}" = --namespace ]; then
    shift
    [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
    image=$1; bundle=$2; subject=$3; out=$4; side=$5; work=$6; script=$7
    root=$work/root
    mkdir "$root"
    mount --bind "$image" "$root"
    mount -o remount,bind,ro "$root"
    for dir in tmp etc dev; do mount -t tmpfs -o mode=0755 tmpfs "$root/$dir"; done
    mkdir -p "$root/etc/config" "$root/tmp/bench" "$root/tmp/out" "$root/tmp/acl"
    for name in passwd group; do
        [ ! -f "$image/etc/$name" ] || cp "$image/etc/$name" "$root/etc/$name"
    done
    cp -a "$image/usr/share/acl.d/." "$root/tmp/acl/"
    chown -R 0:0 "$root/tmp/acl"
    mount --bind "$root/tmp/acl" "$root/usr/share/acl.d"
    mount --bind "$bundle" "$root/tmp/bench"
    mount -o remount,bind,ro "$root/tmp/bench"
    mount --bind "$out" "$root/tmp/out"
    mount --bind /proc "$root/proc"
    mount -t sysfs sysfs "$root/sys"
    for node in null:3 zero:5 random:8 urandom:9; do
        mknod -m 666 "$root/dev/${node%:*}" c 1 "${node#*:}"
    done
    mount -t tmpfs tmpfs "$root/lib/netifd/proto"
    mount -t tmpfs tmpfs "$root/lib/netifd/wireless"
    printf '#!/bin/sh\nexit 0\n' > "$root/tmp/hotplug-noop"
    chmod 755 "$root/tmp/hotplug-noop"
    mount --bind "$root/tmp/hotplug-noop" "$root/sbin/hotplug-call"
    cp "$script" "$root/tmp/window.sh"
    exec chroot "$root" /bin/sh /tmp/window.sh --workload "$subject" "$side"
fi

[ "$#" -eq 5 ] || exit 2
image=$(cd "$1" && pwd)
bundle=$(cd "$2" && pwd)
subject=$3; out=$4; side=$5
case "$subject" in ''|*[!a-zA-Z0-9_.-]*) exit 2 ;; esac
case "$out" in /*) ;; *) echo 'output must be absolute' >&2; exit 2 ;; esac
case "$side" in A|B) ;; *) exit 2 ;; esac
[ -x "$bundle/ns-exec" ] && [ -x "$bundle/netifd-renewal-cpu" ] && [ -x "$bundle/$subject" ]
[ ! -e "$out" ] || { echo 'output already exists; no automatic rerun' >&2; exit 2; }
mkdir -p "$out"
script=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
work=$(mktemp -d /tmp/netifd-renewal.XXXXXX)
namespace_pid=
cleanup() {
    if [ -n "$namespace_pid" ]; then
        kill "$namespace_pid" 2>/dev/null || true
        wait "$namespace_pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
sha256sum "$script" "$bundle/ns-exec" > "$out/harness.sha256"
"$bundle/ns-exec" /bin/sh "$script" --namespace "$image" "$bundle" "$subject" "$out" "$side" "$work" "$script" &
namespace_pid=$!
printf '%s\n' "$namespace_pid" > "$out/namespace.pid"
wait "$namespace_pid"
namespace_pid=
