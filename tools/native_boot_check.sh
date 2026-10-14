#!/bin/sh
# Native-path PID1/service smoke test on an aarch64 Linux host. Synthetic
# interfaces and configuration only; physical radios/flash are not exposed.
# Usage (root): native_boot_check.sh EXTRACTED_IMAGE NEW_OUTPUT_DIRECTORY
set -eu
[ ! -f /etc/openwrt_release ] && [ "$(id -u)" -eq 0 ] && [ "$(uname -m)" = aarch64 ] || exit 2
image=$(cd "${1:?image rootfs}" && pwd)
test ! -e "${2:?new output directory}"
mkdir -p "$2"
out=$(cd "$2" && pwd)
tools=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cp -a "$image" "$out/root"
root=$out/root

# Keep the exact image's rcS and five real init services. Hardware services,
# time-setting and persistent entropy updates are excluded from the fixture.
rm -f "$root"/etc/rc.d/*
for entry in S12log S12rpcd S19dnsmasq S20network S50uhttpd; do
    service=$(printf '%s' "$entry" | cut -c4-)
    ln -s "../init.d/$service" "$root/etc/rc.d/$entry"
done
if [ -x "$root/etc/init.d/owrt-native-trial" ]; then
    ln -s ../init.d/owrt-native-trial "$root/etc/rc.d/S01owrt-native-trial"
fi
mkdir -p "$root/tmp/out" "$root/var/run"
cat > "$root/etc/config/system" <<'SYSTEM'
config system
 option hostname 'native-fixture'
 option log_size '64'
SYSTEM
cat > "$root/etc/config/network" <<'NETWORK'
config interface 'loopback'
 option device 'lo'
 option proto 'static'
 option ipaddr '127.0.0.1'
 option netmask '255.0.0.0'
config device
 option name 'br-lan'
 option type 'bridge'
 list ports 'lan1'
config interface 'lan'
 option device 'br-lan'
 option proto 'static'
 option ipaddr '192.168.1.1'
 option netmask '255.255.255.0'
config interface 'wan'
 option device 'wan'
 option proto 'static'
 option ipaddr '198.51.100.2'
 option netmask '255.255.255.0'
 option gateway '198.51.100.1'
NETWORK
cat > "$root/etc/config/dhcp" <<'DHCP'
config dnsmasq 'native'
 option domainneeded '1'
 option boguspriv '1'
 option localise_queries '1'
 option local '/lan/'
 option domain 'lan'
 option expandhosts '1'
 option authoritative '1'
 option leasefile '/tmp/dhcp.leases'
 option noresolv '1'
 option localuse '0'
 option nonwildcard '1'
 option localservice '1'
 option noping '1'
 option rebind_protection '0'
config dhcp 'lan'
 option interface 'lan'
 option start '100'
 option limit '20'
 option leasetime '2m'
 option dhcpv4 'server'
 option dhcpv6 'disabled'
 option ra 'disabled'
 option force '1'
config host
 option name 'native-client'
 option mac '02:00:00:00:00:27'
 option ip '192.168.1.100'
DHCP
printf '127.0.0.1 localhost\n192.0.2.51 lifecycle.lan\n' > "$root/etc/hosts"
cat > "$root/etc/config/uhttpd" <<'HTTP'
config uhttpd 'main'
 list listen_http '127.0.0.1:8080'
 list listen_https '127.0.0.1:8443'
 option home '/www'
 option cgi_prefix '/cgi-bin'
 option ubus_prefix '/ubus'
 option cert '/etc/uhttpd.crt'
 option key '/etc/uhttpd.key'
 option max_requests '3'
 option max_connections '100'
config cert 'defaults'
 option days '1'
 option key_type 'ec'
 option ec_curve 'P-256'
 option commonname 'native-fixture'
HTTP

cat > "$root/tmp/native-drive.sh" <<'DRIVE'
#!/bin/sh
set -eu
trap 'touch /tmp/out/FAILED; echo FAILED >> /tmp/out/verdict' EXIT
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
for wait in $(seq 1 45); do
    if ubus -S -t 1 call network.interface.lan status > /tmp/out/lan.json 2>/dev/null &&
       grep -q '"up":true' /tmp/out/lan.json &&
       ubus -S -t 1 call session list '{}' > /tmp/out/session.json 2>/dev/null &&
       uclient-fetch -q -T 2 -O /tmp/out/http.css http://127.0.0.1:8080/luci-static/bootstrap/cascade.css; then
        break
    fi
    sleep 1
done
grep -q '"up":true' /tmp/out/lan.json
cmp /www/luci-static/bootstrap/cascade.css /tmp/out/http.css
test -s /etc/uhttpd.crt && test -s /etc/uhttpd.key
uclient-fetch --no-check-certificate -q -T 5 -O /tmp/out/https.css https://127.0.0.1:8443/luci-static/bootstrap/cascade.css
cmp /www/luci-static/bootstrap/cascade.css /tmp/out/https.css
ubus -S -t 3 call network.interface.wan status > /tmp/out/wan.json
grep -q '"up":true' /tmp/out/wan.json
ubus -S -t 3 call service list > /tmp/out/services.json
ubus -S -t 3 call luci getMountPoints > /tmp/out/mounts.json
uci show network > /tmp/out/uci.txt
logger -t native-fixture 'native-log-roundtrip'
sleep 1
logread > /tmp/out/logread.txt
grep -q native-log-roundtrip /tmp/out/logread.txt
/sbin/reload_config
/sbin/fw4 print > /tmp/out/fw4-rust.nft
/usr/libexec/owrt-stock/sbin/fw4 print > /tmp/out/fw4-stock.nft
cmp /tmp/out/fw4-rust.nft /tmp/out/fw4-stock.nft
/sbin/fw4 check > /tmp/out/fw4-check.txt 2>&1
for attempt in $(seq 1 20); do
    if nslookup lifecycle.lan 127.0.0.1 > /tmp/out/local-dns.txt 2>&1 &&
       grep -q 192.0.2.51 /tmp/out/local-dns.txt; then break; fi
    sleep 1
done
grep -q 192.0.2.51 /tmp/out/local-dns.txt
touch /tmp/out/server-ready
for attempt in $(seq 1 30); do
    test ! -e /tmp/out/client-fail
    test ! -e /tmp/out/client-pass || break
    sleep 1
done
test -e /tmp/out/client-pass
ubus -S -t 3 call service list > /tmp/out/services.json
ubus -S -t 3 call dnsmasq metrics > /tmp/out/dnsmasq-metrics.json
cp /var/etc/dnsmasq.conf.native /tmp/out/dnsmasq-generated.conf
sha256sum /proc/1/exe > /tmp/out/pid1.sha256
for name in ubusd netifd rpcd logd uhttpd; do
    pid=$(pidof "$name")
    case "$pid" in ''|*[!0-9]*) exit 1;; esac
    printf '%s %s\n' "$name" "$(sha256sum /proc/$pid/exe | awk '{print $1}')" >> /tmp/out/daemons.sha256
done
for process in /proc/[0-9]*; do
    exe=$(readlink "$process/exe" 2>/dev/null) || continue
    case "$exe" in
        /usr/sbin/dnsmasq)
            printf 'dnsmasq %s\n' "$(sha256sum "$process/exe" | awk '{print $1}')" >> /tmp/out/daemons.sha256
            tr '\0' ' ' < "$process/cmdline" > /tmp/out/dnsmasq-cmdline.txt
            ;;
    esac
done
if awk '$5 == "/sbin/uci" || $5 == "/sbin/reload_config" || $5 == "/sbin/fw4" { found=1 } END {exit !found}' /proc/self/mountinfo; then exit 1; fi
if [ -f /root/owrt-native-trial/armed ]; then
    kill -0 "$(cat /tmp/owrt-native-guard-lock/pid)"
    grep -q 'Rust-boot pending_count=' /root/owrt-native-trial/guard.log
    cp /root/owrt-native-trial/guard.log /tmp/out/trial-guard.log
fi
test ! -e /tmp/out/FAILED
echo PASS > /tmp/out/verdict
trap - EXIT
ubus -S -t 3 call system reboot
sleep 10
echo REBOOT_FAILED >> /tmp/out/verdict
DRIVE
chmod 755 "$root/tmp/native-drive.sh"
cat > "$root/etc/inittab" <<'INITTAB'
::sysinit:/etc/init.d/rcS S boot
::shutdown:/etc/init.d/rcS K shutdown
::respawn:/bin/sh /tmp/native-drive.sh
INITTAB

# netns isolates every network operation. A fresh read-only sysfs and private
# minimal /dev prevent access to the builder's radios, flash and watchdog.
set +e
container=1 timeout -s KILL 120 unshare --mount --net --pid --uts --ipc --fork --kill-child /bin/sh -c '
    set -eu
    root=$1
    tools=$2
    mount --make-rprivate /
    # Exact ujail marks its current / MS_PRIVATE before pivot_root. A plain
    # chroot directory is not a mountpoint and fails EINVAL before dnsmasq
    # executes; reproduce the real router root mount boundary privately.
    mount --bind "$root" "$root"
    awk -v root="$root" "\$5 == root { print }" /proc/self/mountinfo > "$root/tmp/out/fixture-root-mount.txt"
    test -s "$root/tmp/out/fixture-root-mount.txt"
    mount -t proc proc /proc
    mount --bind /proc "$root/proc"
    mount -t sysfs -o ro sysfs "$root/sys"
    mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
    mknod -m 666 "$root/dev/null" c 1 3
    mknod -m 666 "$root/dev/zero" c 1 5
    mknod -m 666 "$root/dev/urandom" c 1 9
    ip link set lo up
    ip link add lan1 type veth peer name client0
    ip link add wan type dummy
    chroot "$root" /bin/mkdir -p /var/lock /var/run /var/log /var/state /tmp/resolv.conf.d
    NATIVE_BOOT_ISOLATED=1 python3 "$tools/native_boot_client.py" "$root" > "$root/tmp/out/client-helper.log" 2>&1 &
    exec chroot "$root" /sbin/procd
' sh "$root" "$tools" > "$out/pid1.log" 2>&1
status=$?
set -e
cp -a "$root/tmp/out/." "$out/"
test "$(cat "$out/verdict")" = PASS
test "$status" -ne 124 && test "$status" -ne 137
python3 - "$image" "$out" <<'PY'
import hashlib,json,sys
from pathlib import Path
root,out=map(Path,sys.argv[1:])
manifest=json.loads((root/'usr/share/owrt-control-plane/release.json').read_text())
assert manifest['layout']=='native-ten' and len(manifest['components'])==10
rows=[line.split() for line in (out/'daemons.sha256').read_text().splitlines()]
assert len(rows)==6 and len({row[0] for row in rows})==6
actual=dict(rows)
actual['procd']=(out/'pid1.sha256').read_text().split()[0]
for name,c in manifest['components'].items():
    expected=c['rust_sha256']
    assert hashlib.sha256((root/c['path'].lstrip('/')).read_bytes()).hexdigest()==expected,name
    assert hashlib.sha256((out/'root'/c['path'].lstrip('/')).read_bytes()).hexdigest()==expected,name
    if name in ('uci','fw4','reload-config'):continue
    process='uhttpd' if name=='httpd' else name
    assert actual[process]==expected, name
services=json.loads((out/'services.json').read_text())
for name,path in [('log','/sbin/logd'),('rpcd','/sbin/rpcd'),('uhttpd','/usr/sbin/uhttpd'),('network','/sbin/netifd'),('dnsmasq','/usr/sbin/dnsmasq')]:
    instances=services[name]['instances']
    assert any(i['running'] and i['command'][0]==path for i in instances.values()),name
mounts=json.loads((out/'mounts.json').read_text())['result']
assert not any(m['mount'] in {item['path'] for item in manifest['components'].values()} for m in mounts)
client=json.loads((out/'client-result.json').read_text())
assert client['passed'] and client['lease_file_matches_client']
metrics=json.loads((out/'dnsmasq-metrics.json').read_text())
assert isinstance(metrics,dict) and metrics
for item in manifest['integration_files'].values():
    path=out/'root'/item['path'].lstrip('/')
    assert hashlib.sha256(path.read_bytes()).hexdigest()==item['replacement_sha256']
result={'pid1_and_six_daemon_identities':True,'standard_service_paths':True,
        'synthetic_LAN_and_WAN_up':True,'HTTP_and_HTTPS_content':True,
        'first_boot_certificate_generation':True,'log_roundtrip':True,
        'uci_and_reload_config':True,'fw4_matches_stock_and_checks':True,
        'no_executable_bind_mounts':True,'PID1_reboot_exits_namespace':True,
        'exact_dnsmasq_init_and_ACL':True,'veth_client_DHCP_OFFER_ACK_and_options':True,
        'veth_client_DNS_UDP_and_TCP':True,'actual_DHCP_lease_matches_client':True,
        'dnsmasq_ubus_metrics':True,'client':client,
        'IPv6_and_odhcpd_scope':'not exercised by this fixture; required in physical acceptance',
        'physical_hardware_tested':False}
if (root/'root/owrt-native-trial/armed').exists():
    assert 'Rust-boot pending_count=' in (out/'trial-guard.log').read_text()
    result['temporary_trial_guard_started_and_alive']=True
(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
PY
