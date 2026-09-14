#!/bin/sh
# Read-only file-page observation after the window's normal identity gate.
# Usage: file_pages.sh stock|rust FILE_RESIDENCY_HELPER NEW_OUTPUT_DIRECTORY
# No file contents are read by this probe and no caches are dropped.
set -eu
mode=$1; helper=$2; out=$3
case "$mode" in stock|rust) ;; *) exit 2 ;; esac
[ -x "$helper" ] && [ ! -e "$out" ]
umask 077
mkdir -p "$out"
monitors=1
printf '/proc/1/exe\n' > "$out/active-paths.txt"
for component in ubusd netifd rpcd logd httpd; do
    name=$component
    case "$component:$mode" in
        rpcd:rust|logd:rust|httpd:rust) name=$component-rs ;;
        httpd:stock) name=uhttpd ;;
    esac
    pid=$(pidof "$name")
    case "$pid" in ''|*[!0-9]*) exit 1 ;; esac
    monitors=$monitors,$pid
    printf '/proc/%s/exe\n' "$pid" >> "$out/active-paths.txt"
done
printf '/sbin/uci\n/sbin/fw4\n/sbin/reload_config\n' >> "$out/active-paths.txt"
printf '%s\n' "$monitors" | tr ',' '\n' | while IFS= read -r pid; do
    awk '$6 ~ /^\// {print $6}' /proc/"$pid"/maps
done | sort -u > "$out/mapped-paths.txt"
: > "$out/bundle-paths.txt"
for directory in /root/r84/bins /root/r89-before-r90/bins /root/r90-before-r92/bins; do
    for name in procd-rs ubusd-rs netifd-rs rpcd-rs logd-rs httpd-rs uci-rs fw4-rs reload_config_rs; do
        [ ! -f "$directory/$name" ] || printf '%s\n' "$directory/$name" >> "$out/bundle-paths.txt"
    done
done
cat /proc/meminfo > "$out/meminfo-before.txt"
/root/r84/bins/owrt-benchmark snapshot "$monitors" > "$out/snapshot-before.json"
for group in active mapped bundle; do
    while IFS= read -r path; do "$helper" "$path"; done < "$out/$group-paths.txt" > "$out/$group.tsv"
done
/root/r84/bins/owrt-benchmark snapshot "$monitors" > "$out/snapshot-after.json"
cat /proc/meminfo > "$out/meminfo-after.txt"
printf 'mmap(PROT_NONE)+mincore; page cache is not exclusive RSS; overlay aliases may share pages\n' > "$out/method.txt"
touch "$out/COMPLETE"
