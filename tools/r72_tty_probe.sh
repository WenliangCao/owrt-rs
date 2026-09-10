#!/bin/sh
# r72b: askfirst on a REAL tty. A devpts instance is mounted inside the
# namespace; `ptyhold` (started before the init exec, so PID 1 inherits it)
# opens and unlocks the master, making /dev/pts/0 exist for the inittab
# entry `pts/0::askfirst:...`. After boot it presses Enter on the master and
# records the console output: the askfirst banner must appear, and the
# command must run with the pty as its tty.
# Usage: r72_tty_probe.sh <rootfs> <candidate> <ptyhold> <outdir>
set -eu
root=$1; cand=$2; ptyhold=$3; out=$4
mkdir -p "$out"
work=$(mktemp -d /tmp/rv-r72b-XXXXXX)
trap 'rm -rf "$work"' EXIT
{ echo "candidate: $cand"; md5sum "$cand" "$ptyhold"; date +%Y-%m-%dT%H:%M:%S; } > "$out/inputs.txt"

r="$work/rs-root"
cp -a "$root" "$r"
cp "$cand" "$r/sbin/procd-rs"; chmod 0755 "$r/sbin/procd-rs"
cp "$ptyhold" "$r/sbin/ptyhold"; chmod 0755 "$r/sbin/ptyhold"
chown -R 0:0 "$r/usr/share/acl.d" 2>/dev/null || true
mkdir -p "$r/tmp/out" "$r/tmp/rcd" "$r/dev/pts"; chmod 1777 "$r/tmp/out"
cat > "$r/tmp/rcd/S10ok" <<'X'
#!/bin/sh
echo "rc ran $1" >> /tmp/out/rc.txt
X
chmod 0755 "$r/tmp/rcd/S10ok"
rm -rf "$r/etc/rc.d"; ln -s /tmp/rcd "$r/etc/rc.d"
cat > "$r/tmp/ttymark.sh" <<'X'
#!/bin/sh
# This exact BusyBox image has no tty applet. The shell's -t test checks
# terminal attachment; readlink names the fd without requiring that applet.
[ -t 0 ] && echo "activated on $(readlink /proc/self/fd/0)" >> /tmp/out/ttymark.txt
exec sleep 600
X
chmod 0755 "$r/tmp/ttymark.sh"
# The inittab id field is [a-zA-Z0-9]* -- a slash cannot appear, so pts/0
# is unusable directly (the C regex has the same shape and would parse the
# id as "0"). The slave is bind-mounted to /dev/ttyP0 instead.
cat > "$r/etc/inittab" <<'X'
::sysinit:/etc/init.d/rcS S boot
ttyP0::askfirst:/bin/sh /tmp/ttymark.sh
X

container=1 timeout -s KILL 90 unshare --mount --net --pid --fork --kill-child /bin/sh -c '
	root=$1
	mount --make-rprivate /
	mount -t proc proc "$root/proc"
	mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
	mknod -m 666 "$root/dev/null" c 1 3
	mkdir -p "$root/dev/pts"
	mount -t devpts -o newinstance,ptmxmode=0666 devpts "$root/dev/pts"
	ip link set lo up
	chroot "$root" /sbin/ptyhold /tmp/out/rc.txt /tmp/out/banner.txt &
	i=0
	while [ ! -e "$root/dev/pts/0" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
	touch "$root/dev/ttyP0"
	mount --bind "$root/dev/pts/0" "$root/dev/ttyP0"
	exec chroot "$root" /sbin/procd-rs
' sh "$r" > "$out/pid1.log" 2>&1 || echo "ns exit $?" >> "$out/pid1.log"
umount "$r/dev/ttyP0" "$r/dev/pts" "$r/proc" "$r/dev" 2>/dev/null || true
for f in rc.txt ttymark.txt banner.txt; do cp "$r/tmp/out/$f" "$out/$f" 2>/dev/null || true; done

# ---- verdict (R73 hygiene). Single-sided: the C cannot be put on this
# fixture identically (its banner text is the assertion source, from
# inittab.c), so the checks are the inittab.c behaviors themselves.
rc=0
grep -q "Please press Enter to activate this console" "$out/banner.txt" 2>/dev/null \
	|| { echo "r72b: FAIL: no askfirst banner on the pty" >&2; rc=1; }
grep -q "activated on /dev/" "$out/ttymark.txt" 2>/dev/null \
	|| { echo "r72b: FAIL: Enter did not activate the command on a tty" >&2; rc=1; }
[ -s "$out/rc.txt" ] || { echo "r72b: FAIL: rcS never ran" >&2; rc=1; }
[ "$rc" -eq 0 ] && echo "r72b: ok" || echo "r72b: FAILED" >&2
echo "r72b: done -> $out"
exit $rc
