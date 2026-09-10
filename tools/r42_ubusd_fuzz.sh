#!/bin/sh
# Wire-protocol fuzzing differential. components/ubusd/examples/fuzz.rs sends a
# fixed table of adversarial messages plus seeded random mutations, so both
# daemons see byte-identical input and their verdicts can be compared. A real
# provider is on the bus so the malformed traffic has something to disturb.
#
# Usage: r42_ubusd_fuzz.sh <rootfs-files> <fuzz-musl> <c-ubusd> <rs-ubusd> [outdir]
set -eu
rootfs=$1; fuzzer=$2; cbin=$3; rsbin=$4; out=${5:-/tmp/r42-out}
mkdir -p "$out"

run_one() {
	tag=$1; daemon=$2
	tmp=$(mktemp -d /tmp/owrt-r42-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n cp "$daemon" "$root/sbin/ubusd-under-test"; sudo -n chmod 755 "$root/sbin/ubusd-under-test"
	sudo -n cp "$fuzzer" "$root/tmp/fuzz"; sudo -n chmod 755 "$root/tmp/fuzz"
	sudo -n cp "$(dirname "$0")/r42_inner.sh" "$root/tmp/inner.sh"
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

python3 "$(dirname "$0")/audit_checks.py" r42 "$out"
if diff -u "$out/c.txt" "$out/rs.txt" > "$out/diff.txt"; then
	echo "RESULT: identical"
	echo "cases: $(grep -c . "$out/c.txt")"
	grep -E '^(mutated|survived|final)' "$out/c.txt"
	exit 0
fi
echo "RESULT: differ"
head -40 "$out/diff.txt"
exit 1
