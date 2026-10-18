#!/bin/sh
# Exactly one externally scheduled events or idle window; no A/B/retry loop.
# ROOTFS BUNDLE SUBJECT_NAME NEW_OUT N GAP_MS WARMUP events|idle [SUBJECT_CPU CLIENT_CPU]
# BUNDLE: ns-exec, netifd-renewal-cpu, and the frozen subject ELF(s).
set -eu

if [ "${1:-}" = --workload ]; then
    shift
    [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
    subject=$1; n=$2; gap=$3; warmup=$4; mode=$5; subject_cpu=$6; client_cpu=$7
    probe=/tmp/bench/netifd-renewal-cpu
    socket=/var/run/ubus/ubus.sock
    mkdir -p /var/run/ubus /var/lock /var/state /tmp/resolv.conf.d
    cat > /etc/config/network <<'NETWORK'
config interface 'loopback'
 option device 'lo'
 option proto 'static'
 option ipaddr '127.0.0.1/8'
config interface 'wan'
 option device 'wan'
 option proto 'renewaltest'
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
    ip link add wan type veth peer name peer
    ip link set wan up
    ip link set peer up
    sha256sum "/tmp/bench/$subject" "$probe" /sbin/ubusd > /tmp/out/identities.sha256
    "$probe" exec-cpu "$client_cpu" /sbin/ubusd -s "$socket" > /tmp/out/ubusd.log 2>&1 &
    bus=$!
    tries=0
    while [ ! -S "$socket" ]; do
        kill -0 "$bus"
        tries=$((tries + 1)); [ "$tries" -lt 50 ] || exit 1
        sleep 0.1
    done
    "$probe" exec-cpu "$subject_cpu" "/tmp/bench/$subject" -S -s "$socket" > /tmp/out/netifd.log 2>&1 &
    subject_pid=$!
    printf '%s\n' "$subject_pid" > /tmp/out/subject.pid
    tries=0
    while ! ubus -s "$socket" call network.interface.wan status 2>/dev/null | grep -Eq '"up"[[:space:]]*:[[:space:]]*true'; do
        kill -0 "$subject_pid"
        tries=$((tries + 1)); [ "$tries" -lt 100 ] || exit 1
        sleep 0.1
    done
    "$probe" exec-cpu "$client_cpu" "$probe" prepare "$socket" "$subject_pid" network.interface.wan > /tmp/out/prepared.json
    ip -4 addr show dev wan > /tmp/out/addresses.before
    ip -4 route show > /tmp/out/routes.before
    grep -q 'inet 192.0.2.2/24' /tmp/out/addresses.before
    grep -q '^default via 192.0.2.1 dev wan' /tmp/out/routes.before
    "$probe" exec-cpu "$client_cpu" "$probe" "$mode" "$socket" "$subject_pid" network.interface.wan "$n" "$gap" "$warmup" > /tmp/out/measurement.json
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
    image=$1; bundle=$2; subject=$3; out=$4; n=$5; gap=$6; warmup=$7; mode=$8; subject_cpu=$9
    shift 9
    client_cpu=$1; work=$2; script=$3
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
    exec chroot "$root" /bin/sh /tmp/window.sh --workload "$subject" "$n" "$gap" "$warmup" "$mode" "$subject_cpu" "$client_cpu"
fi

[ "$#" -ge 8 ] && [ "$#" -le 10 ] || exit 2
image=$(cd "$1" && pwd)
bundle=$(cd "$2" && pwd)
subject=$3; out=$4; n=$5; gap=$6; warmup=$7; mode=$8
subject_cpu=${9:-1}; client_cpu=${10:-0}
case "$subject" in ''|*[!a-zA-Z0-9_.-]*) exit 2 ;; esac
case "$out" in /*) ;; *) echo 'output must be absolute' >&2; exit 2 ;; esac
case "$mode" in events|idle) ;; *) exit 2 ;; esac
for value in "$n" "$gap" "$warmup" "$subject_cpu" "$client_cpu"; do
    case "$value" in ''|*[!0-9]*) exit 2 ;; esac
done
[ -x "$bundle/ns-exec" ] && [ -x "$bundle/netifd-renewal-cpu" ] && [ -x "$bundle/$subject" ]
[ ! -e "$out" ] || { echo 'output already exists; no automatic rerun' >&2; exit 2; }
mkdir -p "$out"
script=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
work=$(mktemp -d /tmp/netifd-renewal.XXXXXX)
trap 'rm -rf "$work"' EXIT
sha256sum "$script" "$bundle/ns-exec" > "$out/harness.sha256"
"$bundle/ns-exec" /bin/sh "$script" --namespace "$image" "$bundle" "$subject" "$out" "$n" "$gap" "$warmup" "$mode" "$subject_cpu" "$client_cpu" "$work" "$script"
