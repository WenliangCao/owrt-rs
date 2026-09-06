#!/bin/sh
# Does the lookup_all gap grow with the number of objects? If it does, the cost
# is per object (allocation per entry) rather than a fixed per-call cost.
# Both daemons run inside the rootfs sandbox: the C ubusd is musl-linked and
# will not start on a glibc host.
#
# Usage: r40_lookup_scaling.sh <rootfs-files> <bench-musl> <c-ubusd> <rs-ubusd> [outdir]
set -eu
rootfs=$1; bench=$2; cbin=$3; rsbin=$4; out=${5:-/tmp/r40-out}
mkdir -p "$out"

run_one() {
	tag=$1; daemon=$2
	tmp=$(mktemp -d /tmp/owrt-r40-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n cp "$daemon" "$root/sbin/ubusd-under-test"; sudo -n chmod 755 "$root/sbin/ubusd-under-test"
	sudo -n cp "$bench" "$root/tmp/bench"; sudo -n chmod 755 "$root/tmp/bench"
	sudo -n cp "$(dirname "$0")/r40_inner.sh" "$root/tmp/inner.sh"
	sudo -n setsid -w unshare --mount --net --fork /bin/sh -c '
		root=$1; mount --make-rprivate /
		mount -t proc proc "$root/proc"; mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		trap "umount $root/dev 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
		REPS="$2" chroot "$root" /bin/sh /tmp/inner.sh' sh "$root" "${REPS:-5}" > "$out/$tag.txt" 2>"$out/$tag-err.log" || true
	sudo -n rm -rf "$tmp"
	sed "s/^/$tag /" "$out/$tag.txt"
}

run_one c "$cbin"
run_one rs "$rsbin"
