# Reverse typed-transfer exact-C baseline

The separately frozen Stage 4 matrix completes **21 cases in 126 C processes**:
20 deterministic cases have **184 observations** whose six native/SDK-musl
traces agree exactly. One further case retains **12 ordering observations**;
its native and SDK executions produce two distinct exact traces. Those 12
observations are not included in the deterministic pass count. The original
307-observation transfer fixture is unchanged.

All C processes use unchanged `cache.c`, actual child `cache_end_insert`, a
real kernel pipe and actual parent `cache_recv_insert`. The new driver reuses
the pinned non-cache objects from the previous source baseline after verifying
their hashes, every patched source/header, SDK inputs and image loader/libraries.
The matching-source SDK-musl executable is newly linked; it is not the stock
image's existing dnsmasq ELF. Every process runs in the Linux isolation wrapper.

The measured parent contract is:

- Reverse records retain target-name case, address family, address bytes and
  absolute deadline. Import replaces dynamic records by family/address while
  preserving forward records of either the old or new target name.
- Local reverse records and imported dynamic PTRs coexist; address lookup
  returns the local row first. A parent local forward name at another address,
  or a configured CNAME with the same target name, does not reject reverse
  insertion. This is different from the forward local-conflict contract.
- Forward and reverse entries share capacity and LRU. Selecting a reverse
  victim removes its address RRset and increments `live_freed` once, even when
  that removes two records. Only committed parent entries increment `inserted`.
- An empty successful child commit sends a transaction and clears previous
  parent pending state. Uncommitted or failed child insertion sends nothing.
- When a complete imported reverse replacement precedes an expired record,
  parent commit fails but the earlier removal persists. The next start clears
  the uncommitted prefix without restoring the removed record.
- Parent import ages the child's absolute deadline and does not repeat min/max
  TTL clamps. The two tested source compilers saturate past deadlines to zero;
  that conversion remains outside any stock-image-ELF claim.

Before any address lookup, the multiple-PTR case shows child LRU in insertion
order and parent LRU in reverse insertion order, proving that export order and
parent commit order are preserved. After address lookup, native and SDK traces
have different target orders and corresponding LRU orders. All six complete
outputs and per-process hash bucket diagnostics remain intact. No sort, set
comparison, selected favorable runtime or ignored victim/order difference is
used to manufacture one expected order. Rust must compare against the retained
exact traces and report the unresolved order boundary separately.

The source-predicted expiry, local-coexistence, empty-cleanup and pre-lookup
multi-PTR order anchors all calibrate on the first complete run. Every schedule
has an exact row-count check. Identical trace, altered-row and missing-row
comparator calibrations pass. No C preparation or corpus attempt failed.

Freeze commit: `0a3a9d5`. The [sanitized JSON](REVERSE_TRANSFER_C_BASELINE.json)
pins all six per-case output hashes, tool/driver identities and new native/SDK
artifacts. Raw evidence is retained in the independent gate worktree's ignored
`private/` and on oracle under
`/home/ubuntu/dnsmasq-reverse-transfer-20261001/work01/private/c-baseline-01/`.

This is a primitive source baseline. Local ownership fixtures use real cache
publication/configuration entrypoints but do not prove DHCP service reachability.
No Rust pass, TCP transport adoption, partial pipe EOF, allocation/OOM, resource
cost, stock-image service, router or performance acceptance follows.
