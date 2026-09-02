#!/bin/sh
# Stage 9 prerequisite (plan 11.6): logd-rs must survive an ubusd restart,
# reconnect, re-register `log` and keep its ring buffer. Runs inside a copy of
# the exact rootfs on the build host (sudo).
# Usage: r21_logd_reconnect_check.sh <rootfs-files> <logd-rs-musl-binary> [extra logd-rs flags]
set -eu
rootfs=$1; bin=$2; extra=${3:-}
tmp=$(mktemp -d /tmp/owrt-r21-XXXXXX)
root=$tmp/root
sudo -n cp -a "$rootfs" "$root"
# ubusd skips ACL files not owned by root:root ("wrong owner"); the extracted
# rootfs belongs to the build user
sudo -n chown -R root:root "$root/usr/share/acl.d"
sudo -n cp "$bin" "$root/tmp/logd-rs"; sudo -n chmod 755 "$root/tmp/logd-rs"
cat > "$tmp/steps.sh" <<'STEPS'
set -u
mkdir -p /var/run/ubus /tmp/out /dev/log
rm -rf /dev/log
/sbin/ubusd >/tmp/out/ubusd1.log 2>&1 & u1=$!
sleep 1
/tmp/logd-rs -S 64 --kmsg none $EXTRA >/tmp/out/logd.log 2>&1 & l=$!
for i in 1 2 3 4 5; do ubus list log >/dev/null 2>&1 && break; sleep 1; done
logger -t r21 "before-outage-1"
sleep 1
echo "devlog: $(ls -la /dev/log 2>&1)"
echo "read1: $(ubus -S call log read '{"lines":5,"stream":false}' 2>&1 | grep -o 'before-outage-1' | wc -l)"
kill $u1; sleep 1
echo "ubusd_down: $(ubus list log >/dev/null 2>&1; echo rc=$?)"
logger -t r21 "during-outage"
sleep 2
/sbin/ubusd >/tmp/out/ubusd2.log 2>&1 & u2=$!
for i in 1 2 3 4 5 6 7 8; do ubus list log >/dev/null 2>&1 && break; sleep 1; done
echo "reregistered_after_s: $i"
echo "objects: $(ubus list 2>&1 | tr '\n' ' ')"
echo "procs: $(ps | grep -E 'ubusd|logd-rs' | grep -v grep | tr '\n' ';')"
logger -t r21 "after-outage"
sleep 1
out=$(ubus -S call log read '{"lines":10,"stream":false}' 2>&1)
echo "read2_before: $(printf '%s' "$out" | grep -o 'before-outage-1' | wc -l) read2_during: $(printf '%s' "$out" | grep -o 'during-outage' | wc -l) read2_after: $(printf '%s' "$out" | grep -o 'after-outage' | wc -l)"
echo "logd_alive: $(kill -0 $l 2>/dev/null && echo yes || echo no)"
cat /tmp/out/logd.log
kill $l $u2 2>/dev/null
STEPS
sudo -n cp "$tmp/steps.sh" "$root/tmp/steps.sh"
sudo -n env EXTRA="$extra" setsid -w unshare --mount --fork /bin/sh -c '
root=$1; mount --make-rprivate /; mount -t proc proc "$root/proc"; mount -t tmpfs tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3; mknod -m 666 "$root/dev/urandom" c 1 9; mknod -m 666 "$root/dev/kmsg" c 1 11
trap "umount $root/dev 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
EXTRA="$2" chroot "$root" /bin/sh /tmp/steps.sh' sh "$root" "$extra"
sudo -n rm -rf "$tmp"
