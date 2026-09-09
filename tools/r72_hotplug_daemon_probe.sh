#!/bin/sh
# r72a: `procd -h <rules>` -- the standalone hotplug daemon preinit runs.
# Both binaries listen in identical namespaces with /sys mounted; a real
# kernel uevent is provoked with `echo add > /sys/class/net/lo/uevent` and
# the observable effects of the rules are compared: an exec ran with the
# event's variables in its environment, and makedev created the node.
# Usage: r72_hotplug_daemon_probe.sh <rootfs> <candidate> <outdir>
set -eu
root=$1; cand=$2; out=$3
mkdir -p "$out"
work=$(mktemp -d /tmp/rv-r72a-XXXXXX)
trap 'rm -rf "$work"' EXIT
{ echo "candidate: $cand"; md5sum "$cand"; echo "rootfs: $root"; date +%Y-%m-%dT%H:%M:%S; } > "$out/inputs.txt"

for tag in c rs; do
	r="$work/$tag-root"
	cp -a "$root" "$r"
	cp "$cand" "$r/sbin/procd-rs"; chmod 0755 "$r/sbin/procd-rs"
	mkdir -p "$r/tmp/out"; chmod 1777 "$r/tmp/out"
	cat > "$r/tmp/hp-rules.json" <<'X'
[
	[ "if", [ "eq", "SUBSYSTEM", "net" ],
		[
			[ "exec", "/bin/sh", "-c", "echo action=$ACTION if=$INTERFACE devpath=$DEVPATH >> /tmp/out/hp.txt" ],
			[ "makedev", "/dev/p31-%DEVICENAME%", "0644" ]
		]
	]
]
X
	cat > "$r/tmp/go.sh" <<'X'
#!/bin/sh
tag=$1
if [ "$tag" = c ]; then bin=/sbin/procd; else bin=/sbin/procd-rs; fi
"$bin" -h /tmp/hp-rules.json > /tmp/out/hpd.log 2>&1 &
hpd=$!
sleep 2
echo add > /sys/class/net/lo/uevent
sleep 3
echo "--- hp.txt:"; cat /tmp/out/hp.txt 2>/dev/null || echo "(none)"
echo "--- node: $(ls -l /dev/p31-lo 2>/dev/null || echo missing)"
echo "--- daemon alive: $(kill -0 $hpd 2>/dev/null && echo yes || echo no)"
echo "--- hpd.log:"; cat /tmp/out/hpd.log
kill -9 $hpd 2>/dev/null || true
X
	chmod 0755 "$r/tmp/go.sh"
	timeout -s KILL 60 unshare --mount --net --pid --fork --kill-child /bin/sh -c '
		root=$1; tag=$2
		mount --make-rprivate /
		mount -t proc proc "$root/proc"
		mount -t sysfs sysfs "$root/sys"
		mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		ip link set lo up
		chroot "$root" /bin/sh /tmp/go.sh "$tag"
	' sh "$r" "$tag" > "$out/$tag.log" 2>&1 || echo "outer exit $?" >> "$out/$tag.log"
done

# ---- verdict (R73 hygiene). The two logs must agree byte-for-byte after
# scrubbing what legitimately varies: the daemon's own stderr lines (each
# side prints its own startup noise) and node timestamps.
rc=0
for tag in c rs; do
	grep -q "action=add if=lo" "$out/$tag.log" || { echo "r72a: FAIL($tag): exec never saw the uevent env" >&2; rc=1; }
	# No node assertion: a net uevent has no MAJOR/MINOR, so BOTH sides skip
	# makedev (R72). The node line still goes through the cross-side diff, so
	# one side creating it while the other skips would go red there.
	grep -q -- "--- daemon alive: yes" "$out/$tag.log" || { echo "r72a: FAIL($tag): daemon died" >&2; rc=1; }
	sed -n '/^--- hp.txt:/,/^--- daemon alive:/p' "$out/$tag.log" \
		| sed -e 's/[A-Z][a-z][a-z] *[0-9]* *[0-9:]* /DATE /' > "$out/$tag.scrubbed"
done
if ! diff -u "$out/c.scrubbed" "$out/rs.scrubbed" > "$out/r72a.diff" 2>&1; then
	echo "r72a: FAIL: scrubbed effect logs differ (see $out/r72a.diff)" >&2
	rc=1
fi
[ "$rc" -eq 0 ] && echo "r72a: ok" || echo "r72a: FAILED" >&2
echo "r72a: done -> $out"
exit $rc
