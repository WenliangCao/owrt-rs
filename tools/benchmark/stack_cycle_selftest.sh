#!/bin/sh
# Linux-only C/Rust UCI/reload/procd/ubusd/logd integration fixture.
# procd is a supervisor here, not PID 1; physical boot is a separate gate.
set -eu
[ ! -f /etc/openwrt_release ] && [ "$(id -u)" -eq 0 ]
image=$1; bundle=$2; out=$3
[ ! -e "$out" ]; mkdir -p "$out"
work=$(mktemp -d /tmp/stack-cycle-test.XXXXXX)
trap 'rm -rf "$work"' EXIT
for side in stock rust; do
    root=$work/$side
    cp -a "$image" "$root"
    mkdir -p "$root/root/r84" "$root/tmp/out"
    cp -a "$bundle/bins" "$bundle/tools" "$root/root/r84/"
    if [ "$side" = rust ]; then
        for c in procd ubusd logd uci; do cp "$bundle/bins/$c-rs" "$root/sbin/$c"; done
        cp "$bundle/bins/reload_config_rs" "$root/sbin/reload_config"
    fi
    cat > "$root/root/r84/stack-switch.sh" <<'EOF'
#!/bin/sh
set -eu
[ "$1" = verify ]
for c in procd ubusd logd; do
    pid=$(cat /tmp/out/$c.pid)
    kill -0 "$pid"
    printf '%s %s ' "$c" "$pid"
    sha256sum /proc/$pid/exe | awk '{print $1}'
done
EOF
    cat > "$root/tmp/drive.sh" <<'EOF'
#!/bin/sh
set -eu
mkdir -p /var/run/ubus /var/lock /var/state /tmp/initd
chmod -R 755 /root/r84/bins
/sbin/ubusd > /tmp/out/ubusd.log 2>&1 & echo $! > /tmp/out/ubusd.pid
i=0
until ubus list >/dev/null 2>&1; do i=$((i+1)); [ "$i" -lt 20 ]; sleep 1; done
/sbin/procd > /tmp/out/procd.log 2>&1 & echo $! > /tmp/out/procd.pid
/sbin/logd > /tmp/out/logd.log 2>&1 & echo $! > /tmp/out/logd.pid
i=0
until ubus list service | grep -qx service; do i=$((i+1)); [ "$i" -lt 20 ]; sleep 1; done
sh /root/r84/tools/benchmark/stack_cycle.sh "$1" /tmp/owrt-stack-test 1 2
cp -a /tmp/owrt-stack-test /tmp/out/cycle
test "$(cat /tmp/out/cycle/deliveries.txt)" = "$(printf '1\n2\n3')"
test "$(cat /tmp/out/cycle/service-after.json | tr -d '\n\t ')" = '{}'
for c in logd procd ubusd; do kill "$(cat /tmp/out/$c.pid)"; done
wait || true
EOF
    "$bundle/bins/ns-exec" /bin/sh -c '
        set -eu
        root=$1; side=$2
        mount --bind /proc "$root/proc"
        mount -t tmpfs tmpfs "$root/dev"
        mknod -m 666 "$root/dev/null" c 1 3
        mknod -m 666 "$root/dev/zero" c 1 5
        mknod -m 666 "$root/dev/urandom" c 1 9
        mount --bind "$root/dev/null" "$root/proc/kmsg"
        ip link set lo up
        chroot "$root" /bin/sh /tmp/drive.sh "$side"
    ' sh "$root" "$side" > "$out/$side.log" 2>&1
    cp -a "$root/tmp/out" "$out/$side"
    echo "PASS: $side real config change reaches service reload, exact delivery count and cleanup"
done
touch "$out/COMPLETE"
