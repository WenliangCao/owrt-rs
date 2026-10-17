#!/bin/sh
# The probe and synthetic upstream are siblings; only the probe owns targets.
set -eu
root=/tmp/dnsmasq-perf-v022-20261017
[ "$#" = 3 ]
mode=$1
artifact=$2
label=$3
case "$mode:$artifact" in helper:k|helper:candidate|resolver:k|resolver:candidate) ;; *) exit 2;; esac
case "$label" in ''|*[!a-z0-9-]*) exit 2;; esac
out=$root/runs/$label
[ ! -e "$out" ]
mkdir "$out"
mkdir "$out/trials"
upstream=
probe=
cleanup() {
    # Both are our direct, unreaped children; PIDs cannot be reused before wait.
    [ -z "$probe" ] || kill -TERM "$probe" 2>/dev/null || :
    [ -z "$upstream" ] || kill -TERM "$upstream" 2>/dev/null || :
    [ -z "$probe" ] || wait "$probe" 2>/dev/null || :
    [ -z "$upstream" ] || wait "$upstream" 2>/dev/null || :
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# fexecve(AT_EMPTY_PATH) uses the source dentry for comm. Give both exact
# images the production basename outside timing, without copying ELF pages.
mkdir "$out/input"
binary=$out/input/dnsmasq
ln "$root/artifact-$artifact" "$binary"
[ "$(stat -c '%a:%u:%g' "$binary")" = 755:0:0 ]
sha256sum "$binary" > "$out/elf.sha256"
sha256sum "$root/device_selfexec_lifecycle" "$root/m6a_upstream" \
    "$root/safe_v022_startup_case.sh" "$root/safe_v022_startup_group.sh" > "$out/tools.sha256"
readlink /proc/self/ns/net > "$out/netns.txt"
if [ "$mode" = resolver ]; then
    "$root/m6a_upstream" --port 15354 --output "$out/upstream.json" \
        --ready-file "$out/upstream.ready" > "$out/upstream.stdout" 2> "$out/upstream.stderr" &
    upstream=$!
    # Bounded readiness wait belongs to the fixture, outside all startup timing.
    tries=0
    while [ ! -s "$out/upstream.ready" ]; do
        kill -0 "$upstream"
        tries=$((tries + 1))
        [ "$tries" -lt 100 ]
        sleep 0.02
    done
    proc_mode=present
else
    proc_mode=absent
fi
"$root/device_selfexec_lifecycle" "$mode" "$binary" "$out/trials" "$proc_mode" 1024 4096 \
    > "$out/startup.jsonl" 2> "$out/startup.stderr" &
probe=$!
status=0
wait "$probe" || status=$?
probe=
printf '%s\n' "$status" > "$out/probe.exit"
if [ -n "$upstream" ]; then
    kill -TERM "$upstream"
    upstream_status=0
    wait "$upstream" || upstream_status=$?
    upstream=
    printf '%s\n' "$upstream_status" > "$out/upstream.exit"
fi
[ "$status" = 0 ]
sha256sum "$binary" > "$out/elf-after.sha256"
printf 'complete\n' > "$out/COMPLETE"
