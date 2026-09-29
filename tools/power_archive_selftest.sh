#!/bin/sh
# Exercise the exact image's shell/gzip, including interrupted compaction.
set -eu
[ ! -f /etc/openwrt_release ] && [ "$(id -u)" -eq 0 ]
root=$1; script=$2; out=$3
[ ! -e "$out" ]; mkdir -p "$out"
testroot=$(mktemp -d /tmp/owrt-power-archive.XXXXXX)
trap 'rm -rf "$testroot"' EXIT
cp -a "$root/." "$testroot/"
cp "$script" "$testroot/tmp/archive.sh"
mkdir -p "$testroot/dev"
[ -e "$testroot/dev/null" ] || mknod -m 666 "$testroot/dev/null" c 1 3
cat > "$testroot/tmp/test.sh" <<'EOF'
set -eu
base=/tmp/evidence
mkdir -p "$base/boots/old" "$base/boots/current"
for name in snapshots.log netlink.hex wan.pcap events.log; do
    printf 'retained evidence\000\001\377\n' > "$base/boots/old/$name"
    cp "$base/boots/old/$name" "$base/boots/current/$name"
done
(cd "$base/boots/current" && sha256sum *) > /tmp/before.sha256
sh /tmp/archive.sh "$base" current
for name in snapshots.log netlink.hex wan.pcap events.log; do
    [ ! -e "$base/boots/old/$name" ]
    gzip -dc "$base/boots/old/$name.gz" > "/tmp/$name"
    cmp "$base/boots/current/$name" "/tmp/$name"
done
(cd "$base/boots/current" && sha256sum -c /tmp/before.sha256)
echo 'PASS: completed boot round-trips byte for byte; current boot untouched'

sh /tmp/archive.sh "$base" current
cp "$base/boots/current/wan.pcap" "$base/boots/old/wan.pcap"
sh /tmp/archive.sh "$base" current
[ ! -e "$base/boots/old/wan.pcap" ]
echo 'PASS: repeated run and interruption after compressed-copy rename resume safely'

mkdir "$base/boots/partial"
cp "$base/boots/current/wan.pcap" "$base/boots/partial/wan.pcap"
echo interrupted > "$base/boots/partial/wan.pcap.gz.partial"
sh /tmp/archive.sh "$base" current
gzip -dc "$base/boots/partial/wan.pcap.gz" > /tmp/recovered
cmp /tmp/recovered "$base/boots/current/wan.pcap"
echo 'PASS: interrupted temporary output is rebuilt from retained source'

mkdir "$base/boots/bad"
cp "$base/boots/current/wan.pcap" "$base/boots/bad/wan.pcap"
echo corrupt > "$base/boots/bad/wan.pcap.gz"
if sh /tmp/archive.sh "$base" current; then exit 1; fi
cmp "$base/boots/bad/wan.pcap" "$base/boots/current/wan.pcap"
printf 'different valid gzip payload' | gzip > "$base/boots/bad/wan.pcap.gz"
if sh /tmp/archive.sh "$base" current; then exit 1; fi
cmp "$base/boots/bad/wan.pcap" "$base/boots/current/wan.pcap"
echo 'PASS: corrupt or mismatched compressed copies never delete original evidence'
EOF
chroot "$testroot" /bin/sh /tmp/test.sh > "$out/test.log" 2>&1
cat "$out/test.log"
touch "$out/COMPLETE"
