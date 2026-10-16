# Remaining cache-dump body in 025's owner step

Read-only inspection of frozen `025c2f2c5ca11758c01dd7e58e2b49c4d087ed5c`
and its 6ab parent identifies the existing SIGUSR1 request gate as the largest
remaining outlining boundary. In 025's local final ELF, the admitted dump
body occupies `0x293810..0x2958cc` (end exclusive): 8,380 bytes, or 62.37% of
the 13,436-byte `SinglePoll::step`. With no dump request, `0x2937f0` branches
directly to `0x2958cc`. The parent has the corresponding 8,484-byte body at
`0x29284c..0x294970` inside its 17,608-byte step.

At frozen 025 `components/dnsmasq/src/main.rs:4538`, ALARM handling precedes
the existing `CACHE_DUMP_REQUESTED.fetch_update` gate at line 4552. Only the
successful-request body at lines 4558–4569 needs an outline boundary: preserve
the metrics snapshot, borrow order, current-time read, logger callback and
`tcp_high_water` reset together. Keep ALARM handling and one-request atomic
consumption in place. No new readiness state or cold annotation is needed.

`dns/daemon_dump.rs:33` constructs the server `BTreeMap` and deduplication
`HashSet`; lines 54–109 format hosts, leases and cache rows. The existing
machine code calls `metrics` at `0x293830`, BTree iterator `dying_next` at
`0x294c88`, and dump `row`/`sanitise` plus `Logger::emit` throughout the body.
Its iterator setup at `0x294c34..0x294c54` uses stack slots through `sp+0x3e0`.
The shared step unconditionally reserves 1,312 bytes (`0x60 + 0x4c0`), but
other temporaries share these slots; this inspection predicts no exact frame
reduction, maximum stack requirement or runtime gain.

Both existing ELFs, both step code ranges and assembly files were rehashed
against the retained inspection receipt; `main.rs` matched the exact 025 Git
blob. Local ELF SHA-256 values:

- Parent: `770968457bc471009c3fe818a77161388c2f851569eada7810e098ba39794bff`.
- 025: `b106612afd20485dad1146b093166e5fadfe9d790d52d77c28914d39c0fdbc92`.

The detailed private receipt is retained at
`/Users/USER/Developer/owrt-perf-post185-screen-prep-20261016/private/perf-opt-20261015/025-owner-cold-branches/source-elf-review.json`,
SHA-256 `28e47990ada1ac6185b8698843860d2ca698cbbc17273a2d1c976f83a401ac41`.
It binds source, ELF/code/assembly hashes, byte ranges and call evidence.
The raw assembly and `inspection-v3.json` remain in the 025 worktree under
`private/dhcp-ready-frame/cross-daemon-final/`.

This is existing bundled-musl/lld codegen evidence, not canonical SDK or
physical-device performance evidence. No source, test, build or remote state
was changed during review. The later gate-body extraction `5c995a85` is a
separate child of 025; its implementation and codegen are not reviewed here.
