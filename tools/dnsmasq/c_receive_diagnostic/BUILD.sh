#!/bin/sh
# Excluded diagnostic, selected only for a released non-timing build slot.
# Preserve the original matching image build and every failed/partial output.
# Usage: sh BUILD.sh NEW_PRIVATE_WORK_DIRECTORY
# This makes a real independent copy, never hard-links the frozen build tree.
set -eu
[ "$(uname -s)" = Linux ]
[ "$#" -eq 1 ]
original=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/h1-3a/build/openwrt
work=$1
case "$work" in /home/ubuntu/dnsmasq-perf-20261015/*/private/*) ;; *) exit 2;; esac
[ ! -e "$work" ]
[ ! -L "$work" ]
bundle=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
recipe=package/network/services/dnsmasq
source=build_dir/target-aarch64_cortex-a53_musl/dnsmasq-nodhcpv6/dnsmasq-2.93
# Existing evidence binds this companion to the exact image via sstrip -z.
# These checks do not claim that the new diagnostic ELF will be byte-identical.
[ "$(sha256sum "$original/$recipe/Makefile" | cut -d ' ' -f1)" = afb49b97f9291fd387c6c3798c212d59a38c1b7c02a6fbd704225be90cfe1c76 ]
[ "$(sha256sum "$original/$source/src/forward.c" | cut -d ' ' -f1)" = ac05784d4233ed10bd166da5fe91e464afecf2883d3c2a0063305d3e81692f95 ]
[ "$(sha256sum "$original/$source/src/dnsmasq" | cut -d ' ' -f1)" = 79cb9590a6113bca41034155ec45569eac58a2dccde80819c9863ef316f740da ]
[ "$(sha256sum "$original/staging_dir/host/bin/sstrip" | cut -d ' ' -f1)" = 075cfbd820f6ab37adab771a65a2560a55339abaca69bdf39f791504b26025da ]
[ "$(sha256sum "$bundle/c-receive.patch" | cut -d ' ' -f1)" = 7e96c153a952292c110f086593ae2e7b1b8381e14f4a316155baaf4cf5d66609 ]
mkdir -p "$work"
sha256sum "$original/.config" "$original/$recipe/Makefile" \
  "$original/$source/src/forward.c" "$original/$source/src/dnsmasq" \
  "$original/staging_dir/host/bin/sstrip" > "$work/original.sha256"
# Recheck the already retained companion-to-image relationship, without
# compiling a second control or writing into the original build directory.
cp "$original/$source/src/dnsmasq" "$work/stock-restripped"
"$original/staging_dir/host/bin/sstrip" -z "$work/stock-restripped"
[ "$(sha256sum "$work/stock-restripped" | cut -d ' ' -f1)" = 097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87 ]
# May be large without reflink support; perform only if this experiment is chosen.
cp -a --reflink=auto "$original" "$work/openwrt"
# cp -a preserves symlinks. Rebase links into the copied tree before make can
# write through one; refuse unexplained links into other home-directory trees.
python3 - "$original" "$work/openwrt" > "$work/rebased-links.json" <<'PY'
from pathlib import Path
import json, os, sys
original, copied = map(lambda value: Path(value).resolve(), sys.argv[1:])
links = []
for parent, directories, files in os.walk(copied, followlinks=False):
    for name in directories + files:
        path = Path(parent) / name
        if path.is_symlink():
            links.append((path, path.resolve()))
changed = []
for path, target in links:
    if target.is_relative_to(original):
        replacement = copied / target.relative_to(original)
        old = os.readlink(path)
        path.unlink()
        path.symlink_to(os.path.relpath(replacement, path.parent))
        changed.append({'path': str(path.relative_to(copied)), 'old': old,
                        'new': os.readlink(path)})
for path, _ in links:
    target = path.resolve()
    assert not target.is_relative_to(original), (path, target)
    assert not target.is_relative_to(Path('/home/ubuntu')) or target.is_relative_to(copied), (path, target)
print(json.dumps(changed, indent=2))
PY
cmp "$original/.config" "$work/openwrt/.config"
# Keep compiler, libc, dependencies, .config, feature selection and package flags
# from the matching image build. Never use the -O2 native reference builder.
make -C "$work/openwrt" "$recipe/clean" V=s -j1 > "$work/clean.log" 2>&1
cp "$bundle/c-receive.patch" "$work/openwrt/$recipe/patches/999-receive-diagnostic.patch"
make -C "$work/openwrt" "$recipe/compile" V=s -j1 CONFIG_AUTOREMOVE= > "$work/compile.log" 2>&1
cp "$work/openwrt/$source/src/dnsmasq" "$work/dnsmasq-c-receive-prestrip"
cp "$work/dnsmasq-c-receive-prestrip" "$work/dnsmasq-c-receive"
"$work/openwrt/staging_dir/host/bin/sstrip" -z "$work/dnsmasq-c-receive"
sha256sum -c "$work/original.sha256" > "$work/original-unchanged.log"
cmp "$original/.config" "$work/openwrt/.config"
sha256sum "$work/dnsmasq-c-receive" "$work/dnsmasq-c-receive-prestrip"
# No daemon is started or staged here. When selected, the SAME diagnostic ELF
# uses DNSMASQ_UDP_STAGE=full or receive and DNSMASQ_UDP_STAGE_OUT=<private file>.
# Existing exact image C remains a separate calibration control. A full-mode
# deviation can include rebuild/code-layout and the eligibility/counting hook.
# Receive mode sends exactly 48-byte A / 60-byte AAAA replies, flags 0x8180,
# one echoed question + pointer-0xc00c answer, addresses192.0.2.1 /2001:db8::1,
# fixedTTL120; first1000 eligible requests follow the original path.
# Required fixture: bound IPv4 127.0.0.1 UDP, q0000..q031f.m6a.test, no OPT,
# QDCOUNT1/A|AAAA/IN and exact32-byte query. Other traffic uses original code.
# The cut precedes the original clear-unused-packet-tail/admission/logging/cache/
# EDNS/metrics work, as G receive does. It retains original eventloop/poll,
# socket setup, recvmsg, send_from/sendmsg and C's retry/error behavior.
# It is residual loop/syscall/userspace work, NOT an irreducible kernel floor.
# FixedTTL/cache-state, compiler/layout and C-vs-G instrumentation differences
# prevent additive component attribution or product correctness claims.
