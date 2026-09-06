#!/bin/sh
# P1.2: drive the SAME client sequence against the C ubusd and against
# ubusd-rs, each in its own copy of the exact rootfs in a private net+mount
# namespace, and diff the transcripts. The clients are the device's real
# libubus CLI, so the candidate server is never validated only by our own
# client. Object providers: the real rpcd where it runs, plus the CLI's own
# object registration via `ubus listen`/`ubus send`.
#
# Usage: r36_ubusd_diff.sh <rootfs-files> <ubusd-rs-musl-binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r36-out}
mkdir -p "$out"

run_one() {
	# $1 = tag (c|rs), $2 = daemon path inside the rootfs
	tag=$1; daemon=$2
	tmp=$(mktemp -d /tmp/owrt-r36-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	# ubusd skips acl.d files it does not see as root-owned
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n cp "$cand" "$root/sbin/ubusd-rs"; sudo -n chmod 755 "$root/sbin/ubusd-rs"
	sudo -n cp "$(dirname "$0")/r36_inner.sh" "$root/tmp/inner.sh"
	# test-only uid dropper: this rootfs's busybox has no `su`
	[ -x /tmp/asuser ] && { sudo -n cp /tmp/asuser "$root/tmp/asuser"; sudo -n chmod 755 "$root/tmp/asuser"; }
	sudo -n setsid -w unshare --mount --net --fork /bin/sh -c '
		root=$1; daemon=$2
		mount --make-rprivate /
		mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
		chroot "$root" /bin/sh /tmp/inner.sh "$daemon"' sh "$root" "$daemon" > "$out/$tag.txt" 2>&1 || true
	sudo -n cp "$root/diagnostics.txt" "$out/$tag-diagnostics.txt" 2>/dev/null || true
	sudo -n chown "$(id -u):$(id -g)" "$out/$tag-diagnostics.txt" 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c /sbin/ubusd
run_one rs /sbin/ubusd-rs

echo "== transcripts: $out/c.txt $out/rs.txt"
if diff -u "$out/c.txt" "$out/rs.txt" > "$out/diff.txt"; then
	echo "RESULT: identical transcripts"
	exit 0
fi
echo "RESULT: transcripts differ"
cat "$out/diff.txt"
exit 1
