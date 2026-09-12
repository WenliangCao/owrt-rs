#!/bin/sh
# The two limits the contract names but nothing had exercised: the message-size
# cap (UBUS_MAX_MSGLEN, taken from upstream's default rather than confirmed) and
# the per-client transmit cap, past which the daemon silently drops.
#
# Usage: r41_limits.sh <rootfs-files> <bench-musl> <c-ubusd> <rs-ubusd> [outdir]
set -eu
rootfs=$1; bench=$2; cbin=$3; rsbin=$4; out=${5:-/tmp/r41-out}
HELPERS=${HELPERS:-/tmp/r36-helpers}
mkdir -p "$out"

run_one() {
	tag=$1; daemon=$2
	tmp=$(mktemp -d /tmp/owrt-r41-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n cp "$daemon" "$root/sbin/ubusd-under-test"; sudo -n chmod 755 "$root/sbin/ubusd-under-test"
	sudo -n cp "$bench" "$root/tmp/bench"; sudo -n chmod 755 "$root/tmp/bench"
	sudo -n cp "$HELPERS/busprobe" "$root/tmp/busprobe"; sudo -n chmod 755 "$root/tmp/busprobe"
	sudo -n cp "$(dirname "$0")/r41_inner.sh" "$root/tmp/inner.sh"
	sudo -n setsid -w unshare --mount --net --fork /bin/sh -c '
		root=$1; mount --make-rprivate /
		mount -t proc proc "$root/proc"; mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		trap "umount $root/dev 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
		chroot "$root" /bin/sh /tmp/inner.sh' sh "$root" > "$out/$tag.txt" 2>"$out/$tag-err.log" || true
	sudo -n rm -rf "$tmp"
}

run_one c "$cbin"
run_one rs "$rsbin"
python3 "$(dirname "$0")/audit_checks.py" r41 "$out"
if diff -u "$out/c.txt" "$out/rs.txt" > "$out/diff.txt"; then
	echo "RESULT: identical"
	cat "$out/c.txt"
	exit 0
fi
echo "RESULT: differ"
cat "$out/diff.txt"
exit 1
