#!/bin/sh
# F24: byte-level RPC through the real blobmsg protocol, including ACL denial.
# Usage: r83_rpcd_bytes.sh <rootfs> <rpcd-rs> <raw_bytes-musl-example> [outdir]
set -eu
rootfs=$1; candidate=$2; probe=$3; out=${4:-/tmp/r83-rpcd-bytes}
mkdir -p "$out"
work=$(mktemp -d /tmp/r83-bytes.XXXXXX)
trap 'sudo -n rm -rf "$work"' EXIT
for side in c rs; do
    root=$work/$side
    sudo -n cp -a "$rootfs" "$root"
    sudo -n chown -R root:root "$root/usr/share/acl.d"
    sudo -n mkdir -p "$root/tmp/out"
    sudo -n cp "$candidate" "$root/sbin/rpcd-rs"
    sudo -n cp "$probe" "$root/tmp/raw_bytes"
    sudo -n chmod 755 "$root/sbin/rpcd-rs" "$root/tmp/raw_bytes"
    sudo -n timeout 35 unshare --mount --net --pid --fork sh -eu -c '
        root=$1; side=$2
        mount --make-rprivate /
        mount -t proc proc "$root/proc"
        mount -t tmpfs tmpfs "$root/dev"
        mknod -m 666 "$root/dev/null" c 1 3
        mknod -m 666 "$root/dev/urandom" c 1 9
        ip link set lo up
        mkdir -p "$root/var/run/ubus"
        chroot "$root" /sbin/ubusd >"$root/tmp/out/bus.log" 2>&1 &
        sleep 1
        if [ "$side" = c ]; then bin=/sbin/rpcd; else bin=/sbin/rpcd-rs; fi
        chroot "$root" "$bin" >"$root/tmp/out/rpcd.log" 2>&1 &
        i=0
        while ! chroot "$root" ubus list file >/dev/null 2>&1 && [ $i -lt 8 ]; do i=$((i+1)); sleep 1; done
        chroot "$root" /tmp/raw_bytes
    ' sh "$root" "$side" >"$out/$side.txt" 2>"$out/$side-errors.txt" || {
        cat "$out/$side.txt" "$out/$side-errors.txt"
        sudo -n cat "$root/tmp/out/rpcd.log"
        exit 1
    }
done
diff -u "$out/c.txt" "$out/rs.txt"
cat "$out/rs.txt"
echo 'r83 rpcd byte transport: PASS'
