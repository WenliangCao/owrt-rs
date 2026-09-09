#!/bin/sh
# P4 probe: the `system sysupgrade` exec handover, C against procd-rs, each
# as PID 1 of its own namespace on the shipping rootfs (r71's skeleton).
#
# A FAKE /usr/libexec/validate_firmware_image cats /tmp/validate.json, so the
# drive controls the three validation booleans per call. A FAKE
# /sbin/upgraded records its argv, pid and UPGRADE_*/WDTFD environment, then
# exits -- as PID 1 that ends the namespace, which is the expected end of a
# successful run. Order inside one boot:
#   1. broken image        -> error reply, procd stays
#   2. invalid, no force   -> error reply, procd stays
#   3. valid + backup denied + backup asked -> error reply, procd stays
#   4. valid, with backup/command/options   -> exec: upgraded.txt written
#
# Usage: r75_sysupgrade_probe.sh <rootfs> <candidate> <outdir>
set -eu
root=$1; cand=$2; out=$3
mkdir -p "$out"
work=$(mktemp -d /tmp/rv-r75-XXXXXX)
trap 'rm -rf "$work"' EXIT
{ echo "candidate: $cand"; md5sum "$cand"; echo "rootfs: $root"; date +%Y-%m-%dT%H:%M:%S; } > "$out/inputs.txt"

for tag in ${SIDES:-c rs}; do
	r="$work/$tag-root"
	cp -a "$root" "$r"
	cp "$cand" "$r/sbin/procd-rs"; chmod 0755 "$r/sbin/procd-rs"
	chown -R 0:0 "$r/usr/share/acl.d" 2>/dev/null || true
	mkdir -p "$r/tmp/out" "$r/tmp/rcd" "$r/tmp/run"
	chmod 1777 "$r/tmp/out"
	rm -rf "$r/etc/rc.d"; ln -s /tmp/rcd "$r/etc/rc.d"

	cat > "$r/usr/libexec/validate_firmware_image" <<'X'
#!/bin/sh
cat /tmp/validate.json
X
	chmod 0755 "$r/usr/libexec/validate_firmware_image"
	cat > "$r/sbin/upgraded" <<'X'
#!/bin/sh
{
	echo "argv: $0 $*"
	echo "pid: $$"
	env | grep -E '^(UPGRADE_|WDTFD)' | sort
} > /tmp/out/upgraded.txt
exit 0
X
	chmod 0755 "$r/sbin/upgraded"

	cat > "$r/tmp/drive.sh" <<'X'
#!/bin/sh
[ -e /tmp/out/drive.stamp ] && exec sleep 100000
touch /tmp/out/drive.stamp
log() { echo "$*" >> /tmp/out/drive.txt; }
i=0
while [ $i -lt 30 ]; do
	ubus list system 2>/dev/null | grep -q system && break
	sleep 1; i=$((i+1))
done
echo not-a-real-image > /tmp/fake.img

log "--- 1: broken image"
echo '{"valid": false, "forceable": false, "allow_backup": true}' > /tmp/validate.json
ubus call system sysupgrade '{"path":"/tmp/fake.img","prefix":"/"}' >> /tmp/out/drive.txt 2>&1 || log "rc=$?"

log "--- 2: invalid image without force"
echo '{"valid": false, "forceable": true, "allow_backup": true}' > /tmp/validate.json
ubus call system sysupgrade '{"path":"/tmp/fake.img","prefix":"/"}' >> /tmp/out/drive.txt 2>&1 || log "rc=$?"

log "--- 3: valid image that denies the requested backup"
echo '{"valid": true, "forceable": true, "allow_backup": false}' > /tmp/validate.json
ubus call system sysupgrade '{"path":"/tmp/fake.img","prefix":"/","backup":"/tmp/backup.tar"}' >> /tmp/out/drive.txt 2>&1 || log "rc=$?"

log "--- 4: missing prefix is INVALID_ARGUMENT with no error table"
ubus call system sysupgrade '{"path":"/tmp/fake.img"}' >> /tmp/out/drive.txt 2>&1 || log "rc=$?"

log "--- 5: valid image -- this exec ends the namespace"
echo '{"valid": true, "forceable": true, "allow_backup": true}' > /tmp/validate.json
ubus call system sysupgrade '{"path":"/tmp/fake.img","prefix":"/","backup":"/tmp/backup.tar","command":"stage2-cmd","options":{"save_partitions":1,"bad-name":2,"str":"x"}}' >> /tmp/out/drive.txt 2>&1 || log "rc=$?"
sleep 10
log "STILL ALIVE 10s AFTER SYSUPGRADE"
X
	chmod 0755 "$r/tmp/drive.sh"
	cat > "$r/etc/inittab" <<'X'
::sysinit:/etc/init.d/rcS S boot
null::respawn:/bin/sh /tmp/drive.sh
X

	container=1 timeout -s KILL 120 unshare --mount --net --pid --fork --kill-child /bin/sh -c '
		root=$1
		mount --make-rprivate /
		mount -t proc proc "$root/proc"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		ip link set lo up
		if [ "$2" = c ]; then
			exec chroot "$root" /sbin/procd -S
		else
			exec chroot "$root" /sbin/procd-rs
		fi
	' sh "$r" "$tag" > "$out/$tag-pid1.log" 2>&1 || echo "ns exit $?" >> "$out/$tag-pid1.log"
	umount "$r/proc" "$r/dev" 2>/dev/null || true
	for f in drive.txt upgraded.txt; do
		cp "$r/tmp/out/$f" "$out/$tag-$f" 2>/dev/null || true
	done
done

# ---- verdict: per-side assertions, then scrubbed cross-side diffs.
rc=0
fail() { echo "r75: FAIL($tag): $*" >&2; rc=1; }
for tag in ${SIDES:-c rs}; do
	grep -q "Firmware image is broken and cannot be installed" "$out/$tag-drive.txt" 2>/dev/null \
		|| fail "no broken-image error reply"
	grep -q "Firmware image is invalid" "$out/$tag-drive.txt" 2>/dev/null \
		|| fail "no invalid-image error reply"
	grep -q "Firmware image doesn.t allow preserving a backup" "$out/$tag-drive.txt" 2>/dev/null \
		|| fail "no backup-denied error reply"
	grep -q "STILL ALIVE" "$out/$tag-drive.txt" 2>/dev/null \
		&& fail "the valid sysupgrade did not exec"
	grep -q "argv: /sbin/upgraded /tmp/fake.img stage2-cmd" "$out/$tag-upgraded.txt" 2>/dev/null \
		|| fail "upgraded argv wrong or missing"
	grep -q "pid: 1" "$out/$tag-upgraded.txt" 2>/dev/null \
		|| fail "upgraded is not PID 1 (exec did not replace procd)"
	grep -q "UPGRADE_BACKUP=/tmp/backup.tar" "$out/$tag-upgraded.txt" 2>/dev/null \
		|| fail "UPGRADE_BACKUP not exported"
	grep -q "UPGRADE_OPT_SAVE_PARTITIONS=1" "$out/$tag-upgraded.txt" 2>/dev/null \
		|| fail "UPGRADE_OPT_SAVE_PARTITIONS not exported"
	grep -q "UPGRADE_OPT_BAD" "$out/$tag-upgraded.txt" 2>/dev/null \
		&& fail "an invalid option name leaked into the environment"
	grep -q "UPGRADE_OPT_STR" "$out/$tag-upgraded.txt" 2>/dev/null \
		&& fail "a string option leaked into the environment"
	grep -q "WDTFD=" "$out/$tag-upgraded.txt" 2>/dev/null \
		&& fail "WDTFD exported with no watchdog open"
done
if ! diff -u "$out/c-upgraded.txt" "$out/rs-upgraded.txt" > "$out/upgraded.diff" 2>&1; then
	echo "r75: FAIL: upgraded.txt differs across sides (see $out/upgraded.diff)" >&2
	rc=1
fi
# drive.txt: identical apart from rc lines' ubus error TEXT? Both sides print
# ubus's own error strings, which come from the same ubus binary -- compare
# byte-for-byte.
if ! diff -u "$out/c-drive.txt" "$out/rs-drive.txt" > "$out/drive.diff" 2>&1; then
	echo "r75: FAIL: drive logs differ (see $out/drive.diff)" >&2
	rc=1
fi
[ "$rc" -eq 0 ] && echo "r75: ok" || echo "r75: FAILED" >&2
echo "r75: done -> $out"
exit $rc
