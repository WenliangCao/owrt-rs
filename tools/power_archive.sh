#!/bin/sh
# Lossless compaction of completed boots. Never touch the current boot.
# Sync the verified compressed copy before removing its uncompressed source.
set -eu
BASE=${1:?usage: power_archive.sh BASE CURRENT_BOOT}
current=${2:?missing current boot}
for old in "$BASE"/boots/*; do
    [ -d "$old" ] && [ ! -L "$old" ] || continue
    [ "${old##*/}" != "$current" ] || continue
    for name in snapshots.log netlink.hex wan.pcap events.log; do
        source=$old/$name
        [ -f "$source" ] && [ ! -L "$source" ] || continue
        expected=$(sha256sum "$source" | awk '{print $1}')
        packed=$source.gz
        if [ ! -e "$packed" ]; then
            gzip -1 -c "$source" > "$packed.partial"
            gzip -t "$packed.partial"
            actual=$(gzip -dc "$packed.partial" | sha256sum | awk '{print $1}')
            [ "$actual" = "$expected" ] || exit 1
            sync
            mv "$packed.partial" "$packed"
            sync
        fi
        # Also covers a power cut after rename but before source removal.
        gzip -t "$packed"
        actual=$(gzip -dc "$packed" | sha256sum | awk '{print $1}')
        [ "$actual" = "$expected" ] || exit 1
        printf '%s  %s\n' "$expected" "$name" >> "$old/compressed.sha256"
        sync
        rm "$source"
        sync
    done
done
