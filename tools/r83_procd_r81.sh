#!/bin/sh
# r83: the procd findings of the R81 cold audit (F01, F21, F22), the
# shipping rootfs's /sbin/procd against procd-rs in identical namespaces.
#
# Three parts. Each side writes one effect line per check; the two effect
# logs are diffed after scrubbing pids, AND every check carries its own
# expectation, so a run where both sides fail the same way is red rather
# than "identical" (R73 hygiene; H03/H04 of the audit).
#
#  A. supervisor (the r65 shape, plus sysfs and the cgroup2 root inside the
#     chroot): `service delete '{}'` is NOT_FOUND; a `stdout 1` instance
#     re-`set` with the SAME config keeps its pid and keeps logging (F21);
#     its child has LD_PRELOAD=/lib/libsetlbf.so and SIGPIPE ignored
#     (F21/F22); it sits in /sys/fs/cgroup/services/<svc>/<inst> (F22).
#  B. hotplug daemon (`-h`, the r72a shape, host netns so a mem/null uevent
#     reaches it): the exec child's environment carries exactly the kernel's
#     DEVNAME and no synthesized DEVICENAME; makedev's parent directories
#     are 0755, not 0777 (F22).
#  C. PID 1 with stderr on a FULL non-blocking pipe, `-S` on both sides so
#     the state lines go to that stderr (F01): both must boot to the driver
#     and answer the bus after respawn churn and ten failing `set`s. The
#     injection is the pre-R83 binary: `eprintln!` on EAGAIN aborts init at
#     "- early -".
#
# Usage: r83_procd_r81.sh <rootfs> <candidate> <outdir>     (run with sudo)
# Part C needs python3 on the host for the non-blocking pipe fixture.
set -eu
root=$1
cand=$2
out=$3
mkdir -p "$out"
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d /tmp/rv-r83-XXXXXX)
trap 'rm -rf "$work"' EXIT
{ echo "candidate: $cand"; md5sum "$cand"; echo "rootfs: $root"; date +%Y-%m-%dT%H:%M:%S; } > "$out/inputs.txt"
rc=0
fail() { echo "r83: FAIL: $*" >&2; rc=1; }

fresh_root() {
	r="$work/$1-root"
	rm -rf "$r"
	cp -a "$root" "$r"
	cp "$cand" "$r/sbin/procd-rs"; chmod 0755 "$r/sbin/procd-rs"
	chown -R 0:0 "$r/usr/share/acl.d" 2>/dev/null || true
	mkdir -p "$r/tmp/out" "$r/tmp/run" "$r/tmp/initd" "$r/tmp/rcd"
	chmod 1777 "$r/tmp/out"
	echo "$r"
}

# ---------------------------------------------------------------- part A
# The same bus bring-up r65 uses: ubusd, then logd so the instance's stdout
# can be read back with logread.
cat > "$work/bus.sh" <<'X'
#!/bin/sh
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out
rm -f /var/run/ubus/ubus.sock /dev/log
/sbin/ubusd -s /var/run/ubus/ubus.sock &
echo $! > /tmp/out/ubusd.pid
i=0; while ! ubus list >/dev/null 2>&1 && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done
/sbin/logd -S 32 &
echo $! > /tmp/out/logd.pid
i=0; while [ ! -S /dev/log ] && [ $i -lt 10 ]; do sleep 1; i=$((i+1)); done
X
cat > "$work/startA.sh" <<'X'
#!/bin/sh
if [ "$1" = c ]; then
	DBGLVL=0 /sbin/procd -S -I /tmp/initd -R /tmp/rcd > /tmp/out/procd.log 2>&1 &
else
	/sbin/procd-rs -S -I /tmp/initd > /tmp/out/procd.log 2>&1 &
fi
echo $! > /tmp/out/procd.pid
i=0
while [ $i -lt 20 ]; do
	ubus list 2>/dev/null | grep -qx service && exit 0
	sleep 1; i=$((i+1))
done
echo "supervisor never registered service" >> /tmp/out/ready.err
X
cat > "$work/driveA.sh" <<'X'
#!/bin/sh
# One effect line per check. `diag:` lines carry the raw numbers and are
# dropped before the cross-side diff.
say() { echo "$@"; }
svc='{"name":"lg","instances":{"i":{"command":["/bin/sh","-c","while :; do echo tick; sleep 1; done"],"stdout":true}}}'
pid_of() { ubus call service list '{"name":"lg"}' 2>/dev/null | sed -n 's/.*"pid": \([0-9]*\).*/\1/p' | head -1; }
ticks() { logread 2>/dev/null | grep -c 'tick'; }

say "--- delete with an empty message"
ubus call service delete '{}' 2>&1; say "rc=$?"

say "--- start lg (stdout 1)"
ubus call service set "$svc" 2>&1; say "rc=$?"
sleep 3
pid1=$(pid_of)
n1=$(ticks)
say "diag: pid1=$pid1 ticks=$n1"
say "running=$(ubus call service list '{"name":"lg"}' 2>/dev/null | grep -c '"running": true')"
if [ -n "$pid1" ]; then
	say "ld_preload=$(tr '\0' '\n' < /proc/$pid1/environ | grep -c '^LD_PRELOAD=/lib/libsetlbf.so$')"
	m=$(awk '/^SigIgn:/{print $2}' /proc/$pid1/status)
	say "sigpipe_ignored=$([ $(( 0x$m & 0x1000 )) -ne 0 ] && echo yes || echo no)"
	say "cgroup_member=$(grep -qx "$pid1" /sys/fs/cgroup/services/lg/i/cgroup.procs 2>/dev/null && echo yes || echo no)"
	# busybox stat here has no -c; the ls mode string is the portable read.
	say "cgroup_mode=$(ls -ld /sys/fs/cgroup/services/lg/i 2>/dev/null | cut -c1-10)"
else
	say "ld_preload=nopid"; say "sigpipe_ignored=nopid"; say "cgroup_member=nopid"; say "cgroup_mode=nopid"
fi

say "--- identical set (a reload whose config did not change)"
ubus call service set "$svc" 2>&1; say "rc=$?"
sleep 3
pid2=$(pid_of)
n2=$(ticks)
say "diag: pid2=$pid2 ticks=$n2"
say "pid_same=$([ -n "$pid1" ] && [ "$pid1" = "$pid2" ] && echo yes || echo no)"
say "log_grew=$([ "${n2:-0}" -gt "${n1:-0}" ] && echo yes || echo no)"
say "running=$(ubus call service list '{"name":"lg"}' 2>/dev/null | grep -c '"running": true')"

say "--- delete lg"
ubus call service delete '{"name":"lg"}' 2>&1; say "rc=$?"
sleep 2
say "listed_after_delete=$(ubus call service list '{"name":"lg"}' 2>/dev/null | grep -c '"lg"')"
echo done > /tmp/out/A.done
X
chmod 0755 "$work/bus.sh" "$work/startA.sh" "$work/driveA.sh"

run_a() {
	tag=$1
	r=$(fresh_root "A-$tag")
	cp "$work/bus.sh" "$work/startA.sh" "$work/driveA.sh" "$r/tmp/"
	timeout -s KILL 120 unshare --mount --net --pid --fork --kill-child /bin/sh -c '
		root=$1; tag=$2; out=$3
		mount --make-rprivate /
		mount -t proc proc "$root/proc"
		mount -t sysfs sysfs "$root/sys"
		# The cgroup2 hierarchy is single; a second mount shows the same
		# tree, which is what procd sees on the device (init mounts it).
		mount -t cgroup2 none "$root/sys/fs/cgroup"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		ip link set lo up
		chroot "$root" /bin/sh /tmp/bus.sh
		chroot "$root" /bin/sh /tmp/startA.sh "$tag"
		chroot "$root" /bin/sh /tmp/driveA.sh > "$out/$tag-A.txt" 2>&1 || true
		cp "$root/tmp/out/procd.log" "$out/$tag-A-daemon.log" 2>/dev/null || true
		cp "$root/tmp/out/ready.err" "$out/$tag-A-ready.err" 2>/dev/null || true
		cp "$root/tmp/out/A.done" "$out/$tag-A.done" 2>/dev/null || true
		for f in procd ubusd logd; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
		umount "$root/sys/fs/cgroup" "$root/sys" "$root/dev" "$root/proc" 2>/dev/null || true
	' sh "$r" "$tag" "$out" > "$out/$tag-A-ns.log" 2>&1 || echo "ns exit $?" >> "$out/$tag-A-ns.log"
	# Both sides leave the (now empty) instance cgroup behind, like the C.
	rmdir /sys/fs/cgroup/services/lg/i /sys/fs/cgroup/services/lg /sys/fs/cgroup/services 2>/dev/null || true
}

# ---------------------------------------------------------------- part B
cat > "$work/hp-rules.json" <<'X'
[
	[ "if", [ "eq", "SUBSYSTEM", "mem" ],
		[ [ "if", [ "eq", "DEVNAME", "null" ],
			[
				[ "exec", "/bin/sh", "-c", "env | grep -c -e '^DEVNAME=' -e '^DEVICENAME=' >> /tmp/out/leak.txt; echo name=%DEVNAME%/%DEVICENAME% >> /tmp/out/hp.txt" ],
				[ "makedev", "/dev/r83/sub/%DEVICENAME%", "0644" ]
			]
		] ]
	]
]
X
cat > "$work/goB.sh" <<'X'
#!/bin/sh
tag=$1
if [ "$tag" = c ]; then bin=/sbin/procd; else bin=/sbin/procd-rs; fi
"$bin" -h /tmp/hp-rules.json > /tmp/out/hpd.log 2>&1 &
hpd=$!
sleep 2
echo add > /sys/class/mem/null/uevent
sleep 3
echo "--- hp.txt:"; cat /tmp/out/hp.txt 2>/dev/null || echo "(none)"
echo "--- exec env lines matching DEVNAME=/DEVICENAME= (kernel sends DEVNAME=null only):"
cat /tmp/out/leak.txt 2>/dev/null || echo "(none)"
echo "--- makedev parent dir modes: $(ls -ld /dev/r83 /dev/r83/sub 2>/dev/null | cut -c1-10 | tr '\n' ' ')"
node=$(ls -l /dev/r83/sub/null 2>/dev/null | cut -c1-10)
echo "--- node: ${node:-missing}"
echo "--- daemon alive: $(kill -0 $hpd 2>/dev/null && echo yes || echo no)"
kill -9 $hpd 2>/dev/null || true
X
chmod 0755 "$work/goB.sh"

run_b() {
	tag=$1
	r=$(fresh_root "B-$tag")
	cp "$work/hp-rules.json" "$work/goB.sh" "$r/tmp/"
	# No --net: a mem/null uevent is a host-wide broadcast, and the daemon
	# must sit in the netns the kernel sends it to.
	timeout -s KILL 60 unshare --mount --pid --fork --kill-child /bin/sh -c '
		root=$1; tag=$2
		mount --make-rprivate /
		mount -t proc proc "$root/proc"
		mount -t sysfs sysfs "$root/sys"
		mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		chroot "$root" /bin/sh /tmp/goB.sh "$tag"
		umount "$root/sys" "$root/dev" "$root/proc" 2>/dev/null || true
	' sh "$r" "$tag" > "$out/$tag-B.txt" 2>&1 || echo "outer exit $?" >> "$out/$tag-B.txt"
}

# ---------------------------------------------------------------- part C
cat > "$work/fullstderr.py" <<'X'
import fcntl, os, sys
# fd 2 becomes the write end of a pipe that is already full and O_NONBLOCK:
# every write(2) to it fails with EAGAIN, which is the console state the
# audit describes (XOFF, or a >4 KiB burst at 115200).
r, w = os.pipe()
fcntl.fcntl(w, fcntl.F_SETFL, fcntl.fcntl(w, fcntl.F_GETFL) | os.O_NONBLOCK)
try:
    while True:
        os.write(w, b"x" * 4096)
except BlockingIOError:
    pass
os.dup2(w, 2)
os.execvp(sys.argv[1], sys.argv[1:])
X
cat > "$work/resp1.sh" <<'X'
#!/bin/sh
echo respawned >> /tmp/out/resp.txt
exec sleep 987
X
cat > "$work/driveC.sh" <<'X'
#!/bin/sh
[ -e /tmp/out/drive.stamp ] && exec sleep 100000
touch /tmp/out/drive.stamp
log() { echo "$*" >> /tmp/out/drive.txt; }
i=0
while [ $i -lt 60 ]; do
	grep -q "end S20second" /tmp/out/rc.txt 2>/dev/null && break
	sleep 1; i=$((i+1))
done
log "rc-done"
log "--- churn: ten failing sets (each is a LOG line on both sides), ten respawns"
n=0
while [ $n -lt 10 ]; do
	ubus call service set '{"name":"nocmd","instances":{"x":{"env":{"A":"b"}}}}' >/dev/null 2>&1
	p=$(ps w | grep "sleep 987" | grep -v grep | awk "{print \$1}" | head -1)
	[ -n "$p" ] && kill -9 "$p"
	sleep 1
	n=$((n+1))
done
sleep 3
resp=$(grep -c respawned /tmp/out/resp.txt 2>/dev/null || echo 0)
log "respawns-grew=$([ "$resp" -gt 5 ] && echo yes || echo no)"
log "pid1-answers=$(ubus call service list >/dev/null 2>&1 && echo yes || echo no)"
log "pid1-exe=$(readlink /proc/1/exe)"
log "--- system reboot"
ubus call system reboot >/dev/null 2>&1 || log "reboot call failed rc=$?"
sleep 15
log "STILL ALIVE 15s AFTER REBOOT"
X
chmod 0755 "$work/resp1.sh" "$work/driveC.sh"

run_c() {
	tag=$1
	r=$(fresh_root "C-$tag")
	cp "$work/resp1.sh" "$work/driveC.sh" "$r/tmp/"
	for n in S10first S20second; do
		cat > "$r/tmp/rcd/$n" <<X
#!/bin/sh
echo "start $n \$1" >> /tmp/out/rc.txt
echo "end $n" >> /tmp/out/rc.txt
X
		chmod 0755 "$r/tmp/rcd/$n"
	done
	rm -rf "$r/etc/rc.d"; ln -s /tmp/rcd "$r/etc/rc.d"
	cat > "$r/etc/inittab" <<'X'
::sysinit:/etc/init.d/rcS S boot
::shutdown:/etc/init.d/rcS K shutdown
null::respawn:/tmp/resp1.sh
null::respawn:/bin/sh /tmp/driveC.sh
X
	# No /dev/console in the namespace: set_stdio("console") fails on both
	# sides (the C's freopen keeps the old stderr), so stderr STAYS the
	# full pipe for the whole boot.
	container=1 timeout -s KILL 150 python3 "$work/fullstderr.py" \
		unshare --mount --net --pid --fork --kill-child /bin/sh -c '
		root=$1; tag=$2
		mount --make-rprivate /
		mount -t proc proc "$root/proc"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		ip link set lo up
		if [ "$tag" = c ]; then
			exec chroot "$root" /sbin/procd -S
		else
			exec chroot "$root" /sbin/procd-rs -S
		fi
	' sh "$r" "$tag" > "$out/$tag-C-ns.log" 2>/dev/null || echo "ns exit $?" >> "$out/$tag-C-ns.log"
	umount "$r/proc" "$r/dev" 2>/dev/null || true
	for f in drive.txt rc.txt resp.txt; do
		cp "$r/tmp/out/$f" "$out/$tag-C-$f" 2>/dev/null || true
	done
}

for tag in c rs; do
	run_a "$tag"
	run_b "$tag"
	run_c "$tag"
done

# ---------------------------------------------------------------- verdict
# A: per-side expectations, then the scrubbed diff.
for tag in c rs; do
	f="$out/$tag-A.txt"
	[ -e "$out/$tag-A.done" ] || fail "A($tag): drive did not run to the end"
	[ -s "$out/$tag-A-ready.err" ] && fail "A($tag): $(cat "$out/$tag-A-ready.err")"
	sed -n '/^--- delete with an empty/,/^rc=/p' "$f" | grep -q "Not found" || fail "A($tag): service delete '{}' is not NOT_FOUND"
	grep -q "^ld_preload=1$" "$f" || fail "A($tag): child has no LD_PRELOAD=/lib/libsetlbf.so"
	grep -q "^sigpipe_ignored=yes$" "$f" || fail "A($tag): child does not have SIGPIPE ignored"
	grep -q "^cgroup_member=yes$" "$f" || fail "A($tag): child not in /sys/fs/cgroup/services/lg/i"
	grep -q "^cgroup_mode=drwx------$" "$f" || fail "A($tag): instance cgroup is not 0700"
	grep -q "^pid_same=yes$" "$f" || fail "A($tag): identical set changed the pid (F21)"
	grep -q "^log_grew=yes$" "$f" || fail "A($tag): stdout log stopped after the identical set (F21)"
	grep -q "^listed_after_delete=0$" "$f" || fail "A($tag): service survived delete"
	grep -v '^diag:' "$f" | sed -e 's/"pid": [0-9]*/"pid": N/g' > "$out/$tag-A.scrubbed"
done
diff -u "$out/c-A.scrubbed" "$out/rs-A.scrubbed" > "$out/A.diff" || fail "A: effect logs differ (see $out/A.diff)"

# B
for tag in c rs; do
	f="$out/$tag-B.txt"
	grep -q "^name=null/null$" "$f" || fail "B($tag): exec did not see the uevent (rule engine fallback)"
	sed -n '/^--- exec env lines/,/^--- makedev/p' "$f" | grep -qx "1" || fail "B($tag): exec env carries a synthesized DEVICENAME (or lost DEVNAME)"
	grep -q "^--- makedev parent dir modes: drwxr-xr-x drwxr-xr-x $" "$f" || fail "B($tag): makedev parent dirs are not 0755"
	grep -q "^--- node: crw-r--r--$" "$f" || fail "B($tag): makedev node missing or wrong mode"
	grep -q -- "--- daemon alive: yes" "$f" || fail "B($tag): hotplug daemon died"
	sed -n '/^--- hp.txt:/,/^--- daemon alive:/p' "$f" > "$out/$tag-B.scrubbed"
done
diff -u "$out/c-B.scrubbed" "$out/rs-B.scrubbed" > "$out/B.diff" || fail "B: effect logs differ (see $out/B.diff)"

# C
for tag in c rs; do
	f="$out/$tag-C-drive.txt"
	[ -s "$f" ] || fail "C($tag): PID 1 never reached the driver with stderr full (F01)"
	grep -q "^rc-done$" "$f" || fail "C($tag): rcS did not run"
	grep -q "^respawns-grew=yes$" "$f" || fail "C($tag): respawn churn did not happen"
	grep -q "^pid1-answers=yes$" "$f" || fail "C($tag): PID 1 does not answer the bus after churn"
	grep -q "STILL ALIVE" "$f" && fail "C($tag): reboot(2) did not end the namespace"
	grep -q "^ns exit" "$out/$tag-C-ns.log" && ! grep -q "^--- system reboot" "$f" && fail "C($tag): namespace ended early: $(cat "$out/$tag-C-ns.log")"
	grep -v '^pid1-exe=' "$f" > "$out/$tag-C.scrubbed"
done
diff -u "$out/c-C.scrubbed" "$out/rs-C.scrubbed" > "$out/C.diff" || fail "C: effect logs differ (see $out/C.diff)"

[ "$rc" -eq 0 ] && echo "r83: ok" || echo "r83: FAILED" >&2
echo "r83: done -> $out"
exit $rc
