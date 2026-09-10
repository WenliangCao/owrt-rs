#!/bin/sh
# R83: ubusd ACL and wire-fidelity differential (audit R81 F02/F27/F24).
# Same harness as r36: the C ubusd and ubusd-rs each run in a private copy of
# the exact rootfs; the same client sequence -- the device's own `ubus` CLI
# as root/network/nobody plus the wire probe -- is run against both and the
# transcripts are diffed. What r36 could not see: non-root callers of the
# pathless system objects (event/acl/monitor), HUP with an empty or missing
# acl.d, dotfiles in acl.d, per-copy event sequence numbers, MONITOR
# attribute order, NOTIFY(ACTIVE=0) on release, `acl query` blobmsg types.
#
# Usage: r83_ubusd_acl.sh <rootfs-files> <ubusd-rs-musl> <wireprobe-musl> [outdir]
#   wireprobe is components/ubusd/examples/wireprobe.rs built for the target
#   (cargo build --release --examples --target aarch64-unknown-linux-musl).
# Red-proof: pass the pre-fix ubusd-rs (R81 baseline) as <ubusd-rs-musl>;
# every line under "--- 1", "--- 2" and the events/monitor/release/aclquery
# probe lines then differ from the C transcript.
set -eu
rootfs=$1; cand=$2; probe=$3; out=${4:-/tmp/r83-out}
HELPERS=${HELPERS:-/tmp/r36-helpers}
mkdir -p "$out"
[ -x "$HELPERS/asuser" ] || sh "$(dirname "$0")/r36_build_helpers.sh" "$HELPERS"

run_one() {
	tag=$1; daemon=$2
	tmp=$(mktemp -d /tmp/owrt-r83-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	# ubusd skips acl.d files it does not see as root-owned
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n cp "$cand" "$root/sbin/ubusd-rs"; sudo -n chmod 755 "$root/sbin/ubusd-rs"
	sudo -n cp "$probe" "$root/tmp/wireprobe"; sudo -n chmod 755 "$root/tmp/wireprobe"
	sudo -n cp "$HELPERS/asuser" "$root/tmp/asuser"; sudo -n chmod 755 "$root/tmp/asuser"
	sudo -n cp "$(dirname "$0")/r83_ubusd_inner.sh" "$root/tmp/inner.sh"
	sudo -n setsid -w unshare --mount --net --fork /bin/sh -c '
		root=$1; daemon=$2
		mount --make-rprivate /
		mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
		chroot "$root" /bin/sh -x /tmp/inner.sh "$daemon"' sh "$root" "$daemon" > "$out/$tag.txt" 2> "$out/$tag-trace.log" || true
	sudo -n rm -rf "$out/$tag-logs"
	sudo -n cp -a "$root/tmp/out" "$out/$tag-logs" 2>/dev/null || true
	sudo -n chown -R "$(id -u):$(id -g)" "$out/$tag-logs" "$out/$tag-trace.log" 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c /sbin/ubusd
run_one rs /sbin/ubusd-rs

echo "== transcripts: $out/c.txt $out/rs.txt"
# a transcript that stopped early compares nothing: both must reach the end
for t in c rs; do
	grep -q '^daemon_alive: yes$' "$out/$t.txt" || { echo "RESULT: $t transcript incomplete"; exit 1; }
done
if diff -u "$out/c.txt" "$out/rs.txt" > "$out/diff.txt"; then
	echo "RESULT: identical transcripts ($(grep -c . "$out/c.txt") lines)"
	exit 0
fi
echo "RESULT: transcripts differ"
cat "$out/diff.txt"
exit 1
