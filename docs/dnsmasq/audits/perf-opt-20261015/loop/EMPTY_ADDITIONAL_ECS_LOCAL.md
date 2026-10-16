# Skip the absent-Additional ECS scan

Independent6ab child `86a8d59d` only changes `client_subnet_cacheable`.
A short header or ARCOUNT0 returns true immediately. The original helper
already returns true when question parsing fails or finds no OPT, and skips
answer/authority records when ARCOUNT0. Undeclared trailing bytes remain
ignored. Nonzero Additional counts retain the original last-OPT selection,
malformed-record handling and strict ECS TLV loop byte-for-byte.

The regression keeps a declared nonzero-mask ECS uncacheable, then clears
ARCOUNT and checks every truncation under question counts0/1/2/65535, plus an
invalid label. Local Mac726pass/8ignored and Linux-musl all-target checks pass.
Independent source review `5170ad8b` passes; this is not full Linux qualification.

Local final Linux-target codegen removes the `find_pseudoheader` call from
this helper's ordinary no-Additional path. It still reserves its96B frame.
The helper grows252→308B; process_udp4660B and find_pseudoheader1264B are
unchanged in size. Whole bundled-musl/lld ELF grows64B. Nonempty Additional
packets pay an extra header branch. These are static tradeoffs, not SDK size
or a measured CPU saving; no allocation is removed.

Keep this local experiment behind803opt2 and bare1df. The original G sample
assigns3.129% of all user-cycle periods to find_pseudoheader across all callers;
removing one caller cannot establish that entire share as savings. It does
not by itself explain the remaining A53 C/G gap or replace the current queue.

[Local receipt and exact codegen identities](empty-additional-ecs-local.json).
