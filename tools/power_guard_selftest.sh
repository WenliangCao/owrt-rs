#!/bin/sh
# Build-host chroot checks. No physical device or real reboot is involved.
set -eu
[ ! -f /etc/openwrt_release ] && [ "$(id -u)" -eq 0 ]
root=$1; source=$2; out=$3
[ ! -e "$out" ]; mkdir -p "$out"
testroot=$(mktemp -d /tmp/owrt-power-guard.XXXXXX)
trap 'rm -rf "$testroot"' EXIT
cp -a "$root/." "$testroot/"
mkdir -p "$testroot/root/owrt-power-test" "$testroot/rom/sbin" "$testroot/rom/usr/sbin" "$testroot/proc/1" "$testroot/proc/sys/kernel/random" "$testroot/dev"
for name in procd ubusd netifd logd rpcd uci fw4 reload_config; do
    cp "$root/sbin/$name" "$testroot/rom/sbin/$name"
done
cp "$root/usr/sbin/uhttpd" "$testroot/rom/usr/sbin/uhttpd"
cp "$source/power_guard.sh" "$source/power_snapshot.sh" "$testroot/root/owrt-power-test/"
cp "$source/power-recorder" "$testroot/root/owrt-power-test/power-recorder-real"
[ -e "$testroot/dev/null" ] || mknod -m 666 "$testroot/dev/null" c 1 3
cat > "$testroot/tmp/test.sh" <<'EOF'
#!/bin/sh
set -eu
BASE=/root/owrt-power-test
guard=$BASE/power_guard.sh
mkdir -p /tmp/test-bin "$BASE/boots/sentinel"
export PATH=/tmp/test-bin:/usr/sbin:/usr/bin:/sbin:/bin
printf 'must survive rollback\n' > "$BASE/boots/sentinel/evidence.txt"
sha256sum "$BASE/boots/sentinel/evidence.txt" > /tmp/evidence.sha256
sha256sum /etc/config/* > /tmp/config.sha256
sha256sum /rom/sbin/procd /rom/sbin/ubusd /rom/sbin/netifd /rom/sbin/logd /rom/sbin/rpcd /rom/sbin/uci /rom/sbin/fw4 /rom/sbin/reload_config /rom/usr/sbin/uhttpd > "$BASE/original.sha256"
cat > /tmp/test-bin/reboot <<'X'
#!/bin/sh
echo reboot >> /tmp/reboots
X
cat > /tmp/test-bin/sleep <<'X'
#!/bin/sh
if [ -e /tmp/stop-healthy ]; then
    n=$(cat /tmp/sleep-count)
    n=$((n + 1)); echo "$n" > /tmp/sleep-count
    [ "$n" -lt 3 ] || kill -TERM "$PPID"
fi
n=$(cut -d. -f1 /proc/uptime)
step=$(cat /tmp/clock-step)
printf '%s.00 0.00\n' "$((n + step))" > /proc/uptime
X
cat > "$BASE/power-recorder" <<'X'
#!/bin/sh
if [ "$1" = bounded ] && [ "${5:-}" = health ]; then
    [ ! -e /tmp/fail-health ]
    exit $?
fi
exec /root/owrt-power-test/power-recorder-real "$@"
X
chmod 755 /tmp/test-bin/* "$BASE/power-recorder"
reset_boot() {
    rm -rf /tmp/owrt-power-guard-lock /tmp/owrt-power-restore-lock
    echo '11111111-1111-1111-1111-111111111111' > /proc/sys/kernel/random/boot_id
    echo '0.00 0.00' > /proc/uptime
    echo candidate-pid1 > /proc/1/exe
    echo token > "$BASE/armed"
    echo 0 > /tmp/sleep-count
}
assert_stock() {
    for name in procd ubusd netifd; do cmp -s "/sbin/$name" "/rom/sbin/$name"; done
    for name in uci reload-config logd httpd fw4 rpcd; do
        [ ! -e "/etc/owrt-$name.boot-enable" ]
        [ ! -e "/etc/rc.d/S18owrt-$name" ]
    done
    [ "$(readlink /etc/rc.d/S12log)" = ../init.d/log ]
    [ "$(readlink /etc/rc.d/S12rpcd)" = ../init.d/rpcd ]
    [ "$(readlink /etc/rc.d/S50uhttpd)" = ../init.d/uhttpd ]
    [ ! -e /etc/r84-pending ] && [ ! -e /etc/rc.d/S99r84-canary ]
    sha256sum -c /tmp/evidence.sha256 /tmp/config.sha256 >/dev/null
    [ -f "$BASE/armed" ]
}
reset_boot
echo 300 > /tmp/clock-step
touch /tmp/fail-health
for name in procd ubusd netifd; do echo candidate > "/sbin/$name"; done
for name in uci reload-config logd httpd fw4 rpcd; do
    touch "/etc/owrt-$name.boot-enable"
    ln -sf "../init.d/owrt-$name" "/etc/rc.d/S18owrt-$name"
done
touch /etc/r84-pending
ln -sf ../init.d/r84-canary /etc/rc.d/S99r84-canary
sh "$guard" run
assert_stock
[ "$(wc -l < /tmp/reboots)" -eq 1 ]
grep -q 'WAN health deadline expired' "$BASE/guard.log"
echo 'PASS: WAN failure restores all nine next-boot paths and preserves evidence/configuration'

reset_boot
cp /rom/sbin/procd /proc/1/exe
sh "$guard" run
[ "$(wc -l < /tmp/reboots)" -eq 1 ]
echo 'PASS: recovered C boot does not enter a reboot loop'

reset_boot
echo 2 > "$BASE/unhealthy-boots"
sh "$guard" run
assert_stock
[ "$(wc -l < /tmp/reboots)" -eq 2 ]
grep -q 'third-unconfirmed-boot' "$BASE/guard.log"
echo 'PASS: persistent counter restores on third unconfirmed startup'

reset_boot
echo 1 > "$BASE/unhealthy-boots"
echo 10 > /tmp/clock-step
rm /tmp/fail-health
touch /tmp/stop-healthy
set +e
sh "$guard" run
status=$?
set -e
[ "$status" -eq 143 ]
[ "$(cat "$BASE/unhealthy-boots")" = 0 ]
[ -f "$BASE/healthy-boot" ] && [ -f "$BASE/armed" ]
[ "$(wc -l < /tmp/reboots)" -eq 2 ]
echo 'PASS: three healthy observations reset counter while leaving future-boot protection armed'

reset_boot
rm -f /tmp/stop-healthy
cp "$BASE/original.sha256" /tmp/original.sha256
echo broken > /rom/sbin/netifd
if sh "$guard" restore; then exit 1; fi
[ "$(wc -l < /tmp/reboots)" -eq 2 ]
sha256sum -c /tmp/evidence.sha256 /tmp/config.sha256 >/dev/null
echo 'PASS: mismatched C original blocks restoration without deleting evidence'
EOF
chroot "$testroot" /bin/sh /tmp/test.sh > "$out/test.log" 2>&1
cat "$out/test.log"
touch "$out/COMPLETE"
