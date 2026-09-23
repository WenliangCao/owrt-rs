#!/bin/bash
# R134 ubusd correctness gates on Oracle (exact rootfs, private namespaces):
# seven wire transcripts and FD placement vs exact C with R131 as the prior
# Rust side, then the r92 functional/recovery ubusd set.
# usage: ubusd_gates.sh CANDIDATE_UBUSD EXAMPLES_DIR OUT_DIR
set -euo pipefail
cand=$(realpath "$1"); examples=$(realpath "$2"); out=$3
before=/home/ubuntu/r131-event-batch/maps/r131
rootfs=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
repo=/home/ubuntu/r134/repo
probe=/home/ubuntu/r131-event-batch/correctness-01/probe-tools
mkdir -p "$out"; out=$(realpath "$out")
mkdir "$out/bundle" "$out/tools"
cp "$examples/wireprobe" "$out/bundle/owrt-benchmark"
cp "$cand" "$out/bundle/ubusd-rs"
cp "$before" "$out/bundle/before-rs"
cp /home/ubuntu/r90-batch1/baseline/ns-exec "$out/bundle/ns-exec"
cp "$probe/isolated.sh" "$probe/r98_ubusd_events.sh" "$repo/tools/r134/ubusd_fd_boundary.sh" "$out/tools/"
for spec in events fd; do
    case $spec in events) script=$out/tools/r98_ubusd_events.sh ;; fd) script=$out/tools/ubusd_fd_boundary.sh ;; esac
    mkdir "$out/$spec" "$out/$spec-work"
    rc=0
    sudo -n "$out/bundle/ns-exec" /bin/sh "$script" --namespace "$rootfs" "$out/bundle" ubusd rs "$out/$spec" 1 "$out/$spec-work" "$script" > "$out/$spec.log" 2>&1 || rc=$?
    sudo -n chown -R ubuntu:ubuntu "$out/$spec" "$out/$spec-work" 2>/dev/null || true
    if [ -e "$out/$spec/COMPLETE" ]; then echo "GATE $spec PASS"; else echo "GATE $spec FAIL rc=$rc"; fi
done
mkdir "$out/bins"
cp -a /home/ubuntu/r95/final/bins/. "$out/bins/"
cp "$cand" "$out/bins/ubusd-rs"
cd "$repo"
export RUSTUP_TOOLCHAIN=1.98.1-aarch64-unknown-linux-gnu PATH=/home/ubuntu/.cargo/bin:$PATH
rc=0
python3 tools/r92_validate.py "$rootfs" "$out/bins" "$out/gates" --baseline /home/ubuntu/r90-batch1/baseline \
    --examples /home/ubuntu/r95/final/target-examples/aarch64-unknown-linux-musl/release/examples \
    --fw4-source /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/sources/components/firewall4 \
    --network-config /home/ubuntu/p6-recovery-20260909/evidence/network \
    --wireless-config /home/ubuntu/p6-recovery-20260909/evidence/wireless \
    --helpers /home/ubuntu/r92-recovery-compat/helpers-canonical --target-dir "$out/native" \
    --groups functional recovery --gates ubusd-r36 ubusd-r36-user ubusd-r83 ubusd-r42 ubusd-r41 r92-recovery > "$out/r92.log" 2>&1 || rc=$?
echo "GATE r92 rc=$rc"
