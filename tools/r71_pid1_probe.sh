#!/bin/sh
# P3.2 probe: each procd as the ACTUAL PID 1 of its own pid+mount+net
# namespace on the shipping rootfs, driven from inside by an inittab entry.
# Observed, per side, via files the driver leaves in /tmp/out:
#   - rc.d S* scripts run strictly serially in glob order with the param
#   - a respawn entry with a real /dev id comes back after a kill
#   - a respawn entry with an empty id runs once and never respawns
#   - the early ubus service is on the bus and listed
#   - `system reboot` runs the K scripts and ends the namespace (container=1)
# Usage: pid1_probe.sh <rootfs> <candidate> <outdir>
set -eu
root=$1; cand=$2; out=$3
mkdir -p "$out"
work=$(mktemp -d /tmp/rv-pid1-XXXXXX)
trap 'rm -rf "$work"' EXIT
{ echo "candidate: $cand"; md5sum "$cand"; echo "rootfs: $root"; date +%Y-%m-%dT%H:%M:%S; } > "$out/inputs.txt"

for tag in ${SIDES:-c rs}; do
	r="$work/$tag-root"
	cp -a "$root" "$r"
	cp "$cand" "$r/sbin/procd-rs"; chmod 0755 "$r/sbin/procd-rs"
	chown -R 0:0 "$r/usr/share/acl.d" 2>/dev/null || true
	mkdir -p "$r/tmp/out" "$r/tmp/rcd"
	chmod 1777 "$r/tmp/out"

	for n in S10first S20second S30third; do
		cat > "$r/tmp/rcd/$n" <<X
#!/bin/sh
echo "start $n \$1" >> /tmp/out/rc.txt
sleep 1
echo "end $n" >> /tmp/out/rc.txt
X
		chmod 0755 "$r/tmp/rcd/$n"
	done
	cat > "$r/tmp/rcd/K90bye" <<'X'
#!/bin/sh
echo "K90bye $1" >> /tmp/out/rc.txt
X
	chmod 0755 "$r/tmp/rcd/K90bye"
	rm -rf "$r/etc/rc.d"; ln -s /tmp/rcd "$r/etc/rc.d"

	cat > "$r/tmp/drive.sh" <<'X'
#!/bin/sh
# Started by the inittab `null::respawn` entry. Runs the checks once; later
# respawns just sleep so the respawn machinery stays observable elsewhere.
[ -e /tmp/out/drive.stamp ] && exec sleep 100000
touch /tmp/out/drive.stamp
log() { echo "$*" >> /tmp/out/drive.txt; }
i=0
while [ $i -lt 60 ]; do
	grep -q "end S30third" /tmp/out/rc.txt 2>/dev/null && break
	sleep 1; i=$((i+1))
done
log "rc-done after ${i}s"
sleep 2
log "--- rc.txt:"; cat /tmp/out/rc.txt >> /tmp/out/drive.txt
log "diag ls: $(ls -la /tmp/resp1.sh /tmp/once1.sh 2>&1 | tr '\n' ' ')"
log "diag ps: $(ps w 2>/dev/null | grep -E 'resp1|once1|sleep 98' | grep -v grep | tr '\n' ';')"
log "--- kill the respawned child; it must come back"
before=$(grep -c respawned /tmp/out/resp.txt 2>/dev/null || echo 0)
p987=$(ps w | grep "sleep 987" | grep -v grep | awk "{print \$1}" | head -1)
log "killing sleep-987 pid [$p987] (pkill may not exist on this busybox)"
[ -n "$p987" ] && kill -9 "$p987"
sleep 3
after=$(grep -c respawned /tmp/out/resp.txt 2>/dev/null || echo 0)
log "resp before=$before after=$after (must grow)"
log "once lines: $(wc -l < /tmp/out/once.txt 2>/dev/null || echo 0) (must stay 1: empty id never respawns)"
p986=$(ps w | grep "sleep 986" | grep -v grep | awk "{print \$1}" | head -1)
[ -n "$p986" ] && kill -9 "$p986"
sleep 3
log "once lines after killing it: $(wc -l < /tmp/out/once.txt 2>/dev/null || echo 0) (still 1)"
log "--- objects: $(ubus list 2>/dev/null | tr '\n' ' ')"
log "--- service list: $(ubus call service list 2>/dev/null | tr -d '\n\t ')"
log "--- pid1 exe: $(readlink /proc/1/exe)"
log "--- system reboot"
ubus call system reboot >> /tmp/out/drive.txt 2>&1 || log "reboot call failed rc=$?"
sleep 15
log "STILL ALIVE 15s AFTER REBOOT"
X
	chmod 0755 "$r/tmp/drive.sh"

	# inittab splits the process field on spaces (strtok / MAX_ARGS), so a
	# `sh -c word word` line degenerates to running `word`. Wrapper scripts
	# keep each entry a plain argv.
	cat > "$r/tmp/resp1.sh" <<'X'
#!/bin/sh
echo respawned >> /tmp/out/resp.txt
exec sleep 987
X
	cat > "$r/tmp/once1.sh" <<'X'
#!/bin/sh
echo once >> /tmp/out/once.txt
exec sleep 986
X
	chmod 0755 "$r/tmp/resp1.sh" "$r/tmp/once1.sh"
	cat > "$r/etc/inittab" <<'X'
::sysinit:/etc/init.d/rcS S boot
::shutdown:/etc/init.d/rcS K shutdown
null::respawn:/tmp/resp1.sh
::respawn:/tmp/once1.sh
null::respawn:/bin/sh /tmp/drive.sh
X

	container=1 timeout -s KILL 150 unshare --mount --net --pid --fork --kill-child /bin/sh -c '
		root=$1
		mount --make-rprivate /
		mount -t proc proc "$root/proc"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		ip link set lo up
		if [ "$2" = c ]; then
			exec chroot "$root" /sbin/procd
		else
			exec chroot "$root" /sbin/procd-rs
		fi
	' sh "$r" "$tag" > "$out/$tag-pid1.log" 2>&1 || echo "ns exit $?" >> "$out/$tag-pid1.log"
	umount "$r/proc" "$r/dev" 2>/dev/null || true
	for f in drive.txt rc.txt boot.log resp.txt once.txt; do
		cp "$r/tmp/out/$f" "$out/$tag-$f" 2>/dev/null || true
	done
done
echo "pid1_probe: done -> $out"
