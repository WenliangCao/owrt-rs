#!/bin/sh
# The owrt-ubusd package must be inert: installing it and running its verify
# script must not disturb a bus that is already running. This starts the real C
# ubusd as the system bus with a real provider on it, then installs the package
# contents and runs owrt-ubusd-verify, checking the system bus before, during
# and after.
#
# Usage: r38_ubusd_package_check.sh <rootfs-files> <extracted-package-dir> [outdir]
set -eu
rootfs=$1; pkg=$2; out=${3:-/tmp/r38-out}
mkdir -p "$out"
tmp=$(mktemp -d /tmp/owrt-r38-XXXXXX); root=$tmp/root
sudo -n cp -a "$rootfs" "$root"
sudo -n chown -R root:root "$root/usr/share/acl.d"
# what `apk add owrt-ubusd` would put on the filesystem, and nothing else
sudo -n cp "$pkg/usr/sbin/ubusd-rs" "$root/usr/sbin/ubusd-rs"
sudo -n cp "$pkg/usr/sbin/owrt-ubusd-verify" "$root/usr/sbin/owrt-ubusd-verify"
sudo -n chmod 755 "$root/usr/sbin/ubusd-rs" "$root/usr/sbin/owrt-ubusd-verify"

cat > "$tmp/inner.sh" <<'INNER'
set -u
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out; chmod 1777 /var/run/ubus
ip link set lo up 2>/dev/null || true
say() { printf '%s\n' "$*"; }

# the system bus, with a real provider on it
/sbin/ubusd >/tmp/out/system-bus.log 2>&1 & sysbus=$!
sleep 1
/sbin/rpcd >/tmp/out/rpcd.log 2>&1 & rp=$!
i=0; while [ $i -lt 15 ]; do ubus list | grep -q '^uci$' && break; i=$((i+1)); sleep 1; done

sys_objs_before=$(ubus list | sort | tr '\n' ' ')
sys_inode_before=$(ls -i /var/run/ubus/ubus.sock 2>/dev/null | awk '{print $1}')
say "system_objects_before: [$sys_objs_before]"
say "system_bus_alive_before: $(kill -0 $sysbus 2>/dev/null && echo yes || echo no)"

say "--- run the package's verify"
/usr/sbin/owrt-ubusd-verify > /tmp/out/verify.txt 2>&1
say "verify_rc: $?"
say "verify_says_ok: $(grep -c 'owrt-ubusd-verify: OK' /tmp/out/verify.txt || true)"
say "verify_failures: $(grep -c '^FAIL' /tmp/out/verify.txt || true)"

say "--- the system bus must be untouched"
say "system_bus_alive_after: $(kill -0 $sysbus 2>/dev/null && echo yes || echo no)"
say "system_bus_pid_unchanged: $(kill -0 $sysbus 2>/dev/null && echo yes || echo no)"
sys_inode_after=$(ls -i /var/run/ubus/ubus.sock 2>/dev/null | awk '{print $1}')
say "system_socket_replaced: $([ "$sys_inode_before" = "$sys_inode_after" ] && echo no || echo YES)"
say "system_objects_after: [$(ubus list | sort | tr '\n' ' ')]"
say "system_objects_unchanged: $([ "$sys_objs_before" = "$(ubus list | sort | tr '\n' ' ')" ] && echo yes || echo no)"
say "system_call_rc: $(ubus -S call session list '{}' >/dev/null 2>&1; echo $?)"
say "provider_alive: $(kill -0 $rp 2>/dev/null && echo yes || echo no)"

say "--- the candidate must have left nothing behind"
say "alt_socket_gone: $([ -S /var/run/ubus-rs/ubus.sock ] && echo no || echo yes)"
say "candidate_running: $(/usr/sbin/owrt-ubusd-verify status >/dev/null 2>&1 && echo yes || echo no)"

say "--- start/stop mode also leaves the system bus alone"
/usr/sbin/owrt-ubusd-verify start >/dev/null 2>&1; say "start_rc: $?"
say "alt_socket_present: $([ -S /var/run/ubus-rs/ubus.sock ] && echo yes || echo no)"
say "system_objects_during_alt: [$(ubus list | sort | tr '\n' ' ')]"
say "alt_bus_is_separate: $(ubus -s /var/run/ubus-rs/ubus.sock list | wc -l)"
/usr/sbin/owrt-ubusd-verify stop >/dev/null 2>&1; say "stop_rc: $?"
say "system_bus_still_alive: $(kill -0 $sysbus 2>/dev/null && echo yes || echo no)"
say "system_final_objects: [$(ubus list | sort | tr '\n' ' ')]"

kill $rp $sysbus 2>/dev/null; sleep 1
INNER

sudo -n cp "$tmp/inner.sh" "$root/tmp/inner.sh"
sudo -n setsid -w unshare --mount --net --fork /bin/sh -c '
	root=$1; mount --make-rprivate /
	mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
	mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
	mknod -m 666 "$root/dev/null" c 1 3
	mknod -m 666 "$root/dev/urandom" c 1 9
	mknod -m 666 "$root/dev/zero" c 1 5
	trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
	chroot "$root" /bin/sh /tmp/inner.sh' sh "$root" > "$out/report.txt" 2>&1 || true
sudo -n rm -rf "$tmp"
cat "$out/report.txt"
