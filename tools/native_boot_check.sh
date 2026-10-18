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

# Keep the exact image's rcS and real init services. Hardware services,
# time-setting and persistent entropy updates are excluded from the fixture.
rm -f "$root"/etc/rc.d/*
for entry in S12log S12rpcd S19dnsmasq S20network S50uhttpd; do
    service=$(printf '%s' "$entry" | cut -c4-)
    ln -s "../init.d/$service" "$root/etc/rc.d/$entry"
done
layout=$(python3 - "$image" <<'PY'
import json,sys
from pathlib import Path
manifest=json.loads((Path(sys.argv[1])/'usr/share/owrt-control-plane/release.json').read_text())
layout=manifest['layout']
assert layout in ('native-ten','native-eleven')
assert len(manifest['components']) == (11 if layout == 'native-eleven' else 10)
print(layout)
PY
)
if [ "$layout" = native-eleven ]; then
    test -x "$root/etc/init.d/odhcpd"
    ln -s ../init.d/odhcpd "$root/etc/rc.d/S35odhcpd"
fi
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
if [ "$layout" = native-eleven ]; then
    python3 - "$root" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
network=root/'etc/config/network'
text=network.read_text()
text=text.replace(" option ipaddr '192.168.1.1'\n", " option ipaddr '192.168.1.1'\n list ip6addr '2001:db8:1::1/64'\n list ip6addr 'fd12:3456:789a::1/60'\n")
text=text.replace(" option ipaddr '198.51.100.2'\n", " option ipaddr '198.51.100.2'\n list ip6addr '2001:db8:ffff::2/64'\n option ip6gw '2001:db8:ffff::1'\n")
network.write_text(text)
dhcp=root/'etc/config/dhcp'
text=dhcp.read_text().replace(" option dhcpv6 'disabled'", " option dhcpv6 'server'").replace(" option ra 'disabled'", " option ra 'server'\n option ra_slaac '1'\n list ra_flags 'managed-config'\n list ra_flags 'other-config'")
text += """config odhcpd 'odhcpd'
 option maindhcp '0'
 option leasefile '/tmp/odhcpd.leases'
 option hostsdir '/tmp/hosts'
 option piodir '/tmp/odhcpd-piodir'
 option leasetrigger '/usr/sbin/odhcpd-update'
 option loglevel '4'
"""
dhcp.write_text(text)
(root/'tmp/out/ipv6-enabled').touch()
PY
fi
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
if [ -f /tmp/out/ipv6-enabled ]; then
    ubus -S -t 3 call dhcp ipv6leases > /tmp/out/odhcpd-before.json
    test -x /usr/sbin/odhcpd-update
fi
touch /tmp/out/server-ready
for attempt in $(seq 1 75); do
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
if [ -f /tmp/out/ipv6-enabled ]; then
    expected=$(awk '$2 == "/usr/sbin/odhcpd" {print $1}' /usr/share/owrt-control-plane/rust.sha256)
    test "${#expected}" -eq 64
    matches=0
    for process in /proc/[0-9]*; do
        actual=$(sha256sum "$process/exe" 2>/dev/null) || continue
        actual=${actual%% *}
        [ "$actual" = "$expected" ] || continue
        matches=$((matches + 1))
        printf '%s\n' "${process#/proc/}" > /tmp/out/odhcpd-runtime.pid
        cat "$process/cmdline" > /tmp/out/odhcpd-runtime-cmdline.bin
        cat "$process/stat" > /tmp/out/odhcpd-runtime-stat.txt
        printf 'odhcpd %s\n' "$actual" >> /tmp/out/daemons.sha256
    done
    test "$matches" -eq 1
    ubus -S -t 3 call dhcp ipv6ra > /tmp/out/odhcpd-ipv6ra.json
    ip -6 route show > /tmp/out/ipv6-routes.txt
    sha256sum /etc/init.d/odhcpd /usr/sbin/odhcpd-update > /tmp/out/odhcpd-stock-integration.sha256
fi
expected_dnsmasq=$(awk '$2 == "/usr/sbin/dnsmasq" { print $1 }' /usr/share/owrt-control-plane/rust.sha256)
test "${#expected_dnsmasq}" -eq 64
matches=0
for process in /proc/[0-9]*; do
    # A jailed executable may have a different d_path in the observer's
    # mount namespace. Match actual open executable bytes, never its name.
    actual=$(sha256sum "$process/exe" 2>> /tmp/out/runtime-scan-errors.txt) || continue
    actual=${actual%% *}
    exe=$(readlink "$process/exe" 2>> /tmp/out/runtime-scan-errors.txt) || continue
    printf '%s\t%s\t%s\n' "${process#/proc/}" "$actual" "$exe" >> /tmp/out/runtime-inventory.tsv
    [ "$actual" = "$expected_dnsmasq" ] || continue
    matches=$((matches + 1))
    test "$matches" -eq 1
    printf '%s\n' "${process#/proc/}" > /tmp/out/dnsmasq-runtime.pid
    printf '%s\n' "$exe" > /tmp/out/dnsmasq-runtime.exe
    cat "$process/stat" > /tmp/out/dnsmasq-runtime-stat-before.txt
    cat "$process/status" > /tmp/out/dnsmasq-runtime-status.txt
    cat "$process/cmdline" > /tmp/out/dnsmasq-runtime-cmdline.bin
    actual=$(sha256sum "$process/exe")
    actual=${actual%% *}
    test "$actual" = "$expected_dnsmasq"
    cat "$process/stat" > /tmp/out/dnsmasq-runtime-stat-after.txt
    printf 'dnsmasq %s\n' "$actual" >> /tmp/out/daemons.sha256
    parent=$(awk '$1 == "PPid:" { print $2 }' /tmp/out/dnsmasq-runtime-status.txt)
    sha256sum "/proc/$parent/exe" > /tmp/out/dnsmasq-parent.sha256
    readlink "/proc/$parent/exe" > /tmp/out/dnsmasq-parent.exe
    cat "/proc/$parent/cmdline" > /tmp/out/dnsmasq-parent-cmdline.bin
done
test "$matches" -eq 1
if awk '$5 == "/sbin/uci" || $5 == "/sbin/reload_config" || $5 == "/sbin/fw4" { found=1 } END {exit !found}' /proc/self/mountinfo; then exit 1; fi
if [ -f /root/owrt-native-trial/armed ]; then
    kill -0 "$(cat /tmp/owrt-native-guard-lock/pid)"
    grep -q 'Rust-boot pending_count=' /root/owrt-native-trial/guard.log
    cp /root/owrt-native-trial/guard.log /tmp/out/trial-guard.log
fi
test ! -e /tmp/out/FAILED
touch /tmp/out/client-release
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
ipv6=manifest['layout']=='native-eleven'
assert manifest['layout'] in ('native-ten','native-eleven') and len(manifest['components'])==(11 if ipv6 else 10)
rows=[line.split() for line in (out/'daemons.sha256').read_text().splitlines()]
assert len(rows)==(7 if ipv6 else 6) and len({row[0] for row in rows})==len(rows)
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
instance=services['dnsmasq']['instances']['native']
status=dict(line.split(':',1) for line in (out/'dnsmasq-runtime-status.txt').read_text().splitlines() if ':' in line)
assert int(status['PPid'])==instance['pid'],'actual dnsmasq is not the supervised ujail child'
assert (out/'dnsmasq-parent.sha256').read_text().split()[0]==hashlib.sha256((root/'sbin/ujail').read_bytes()).hexdigest()
cmdline=(out/'dnsmasq-runtime-cmdline.bin').read_bytes().rstrip(b'\0').split(b'\0')
assert [value.decode() for value in cmdline]==instance['command'],'actual dnsmasq argv differs from init submission'
before=(out/'dnsmasq-runtime-stat-before.txt').read_text().rsplit(')',1)[1].split()
after=(out/'dnsmasq-runtime-stat-after.txt').read_text().rsplit(')',1)[1].split()
assert before[19]==after[19],'dnsmasq PID was replaced during identity capture'
runtime={'pid':int((out/'dnsmasq-runtime.pid').read_text()),
         'exe':(out/'dnsmasq-runtime.exe').read_text().strip(),'cmdline':[v.decode() for v in cmdline],
         'sha256':actual['dnsmasq'],'start_ticks':int(before[19]),'parent_pid':instance['pid'],
         'parent_exe':(out/'dnsmasq-parent.exe').read_text().strip(),
         'parent_sha256':(out/'dnsmasq-parent.sha256').read_text().split()[0]}
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
        'dnsmasq_ubus_metrics':True,'client':client,'dnsmasq_runtime':runtime,
        'IPv6_and_odhcpd_scope':'not exercised by this fixture; required in physical acceptance',
        'physical_hardware_tested':False}
if ipv6:
    assert client['ipv6']['passed'] and client['ipv6']['ubus_and_lease_files_match_client']
    assert client['ipv6']['leasetrigger_dns_aaaa']
    assert client['ipv6']['uci_reload_renewal']['passed']
    assert client['ipv6']['luci_consumers']['passed']
    instances=services['odhcpd']['instances']
    running=[i for i in instances.values() if i['running'] and i['command'][0]=='/usr/sbin/odhcpd']
    assert len(running)==1
    assert running[0]['pid']==int((out/'odhcpd-runtime.pid').read_text())
    argv=(out/'odhcpd-runtime-cmdline.bin').read_bytes().rstrip(b'\0').split(b'\0')
    assert [x.decode() for x in argv]==running[0]['command']
    for line in (out/'odhcpd-stock-integration.sha256').read_text().splitlines():
        digest,path=line.split()
        assert digest==hashlib.sha256((root/path.lstrip('/')).read_bytes()).hexdigest(),path
    ra=json.loads((out/'odhcpd-ipv6ra.json').read_text())['interfaces']['br-lan']
    assert {(entry['prefix'],entry['length'],entry['stale']) for entry in ra}=={('2001:db8:1::1',64,False),('fd12:3456:789a::1',60,False)}
    routes=(out/'ipv6-routes.txt').read_text()
    assert all(item['address']+'/'+str(item['length']) in routes for item in client['ipv6']['ia_pd'])
    result.pop('pid1_and_six_daemon_identities')
    result['pid1_and_seven_daemon_identities']=True
    result['exact_S35_odhcpd_init_and_update']=True
    result['IPv6_and_odhcpd_scope']='veth RA/SLAAC, IA_NA/IA_PD, ubus dhcp, leases/hosts and exact leasetrigger to dnsmasq; functionality only'
    result['veth_client_RA_IA_NA_IA_PD']=True
    result['odhcpd_ubus_files_and_leasetrigger']=True
    result['odhcpd_real_UCI_reload_renewal_same_PID']=True
    result['actual_LuCI_DHCPv6_consumers']=True
if (root/'root/owrt-native-trial/armed').exists():
    assert 'Rust-boot pending_count=' in (out/'trial-guard.log').read_text()
    result['temporary_trial_guard_started_and_alive']=True
(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
PY
