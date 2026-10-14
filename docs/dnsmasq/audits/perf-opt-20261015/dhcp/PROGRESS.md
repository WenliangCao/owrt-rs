# DHCP / hosts screening progress

2026-10-15. Branch `perf/dnsmasq-dhcp-20261015`, base `51b03959`.
No product change yet. Root's freeze `d358c3a0` has been read and optimization is
authorized. Oracle workspace: `/home/ubuntu/dnsmasq-perf-20261015/dhcp`; shared
dependency caches, one build job, and no timing without root scheduling.

Ownership: `src/hosts.rs`, `src/dns/hostsdir*.rs`, DHCP store/persistence/parser
modules, and `src/dns/lease_names.rs` (agreed with DNS agent). Avoid DHCP daemon,
service, main and DNS cache/engine/local files owned by the other agents.

Read `PERF_DEVICE_20261014.md` and `PERF_RESEARCH_UDP_DHCP_RELOAD.md`. The complete
frozen device matrix and decision thresholds belong to the root agent; the
standalone probe here is a cheap mechanism screen, not a replacement benchmark.

## Existing interface and boundaries

- `LeaseStore` commits DHCP state before `LeasePersistence::update`; durability
  failure retains dirty state and never rolls back an accepted lease. Output
  order is newest lease first, with extension rows after all basic rows.
- `update_dns` publishes a complete source synchronously before sending ACK.
  Hosts precedence, old-generation TCP snapshots, reverse ownership, cache
  conflict effects and failures cannot be bypassed for unchanged lease names.
- Hosts ingestion uses fallible allocations. A replacement generation must be
  discarded on failure; published owners and TCP views must remain usable.
- DHCP receives a fresh interface snapshot for every admitted packet. This
  research does not cache interface state across packets.

## Initial hypotheses

1. Lease serialization formats each hardware/client byte through `fmt`, and
   `write_leases` allocates/sorts a newest-first list twice. Count write calls,
   allocations and instruction costs before considering a bounded stack encoder
   or reusing the first ordering inside the same call.
2. Full lease publication copies input/name/key repeatedly; lookup allocates
   lowercased names even when the caller already supplied lowercase bytes.
   Count calls/bytes using actual production APIs. Do not skip publication
   side effects or alter the public behavior.
3. Hosts loading duplicates lowercase name keys and allocates index vectors;
   test whether the cost is material before changing the fallible index design.

`count_hotpaths.rs` exercises serialization, ordering, publication, lookup and
hosts loading. Its allocator instrumentation is standalone, never linked into
the daemon. Output bytes/hashes check that encoder screens preserve bytes;
correctness acceptance still requires all frozen tests and exact-C comparisons.

## Initial deterministic counts

Apple AArch64, Rust 1.98.1, production release library (opt3/LTO), same-source
standalone probe, one operation, 2026-10-15. These are mechanism counts, not
device performance claims. Private raw: `counts-baseline-mac.json`.

| Operation | Records | Allocations | Allocated bytes | Write calls | Output bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Lease serialization | 6 | 2 | 96 | 192 | 336 |
| Lease serialization | 150 | 2 | 2400 | 4665 | 8592 |
| Newest-first ordering | 150 | 1 | 1200 | 0 | 0 |
| Lease publication | 6 | 51 | 2630 | 0 | 0 |
| Lease publication | 150 | 1079 | 84950 | 0 | 0 |
| Lowercase lease lookup | 150 | 150 | 3000 | 0 | 0 |
| Hosts ingestion | 150 | 489 | 95539 | 0 | 0 |

First screen: replace per-byte `fmt` hex encoding with bounded stack formatting,
retaining writer/error semantics and byte order. Publication and lowercase
lookup remain independent directions. Full same-ABI Oracle profiling follows.

## D1 — bounded hex serialization

Implemented a 192-byte stack encoder, independent of lease or field size. This
removes per-byte `fmt`; it retains all separators, long extension fields,
partial writes and errors. 19 lease unit tests pass, including a new check over
all byte values, chunk edges and partial-write failures.

Deterministic screen: write calls 192 → 96 for 6 leases; 4665 → 2400 for 150.
Output lengths and rolling hashes are identical (336 bytes /
18024159028762036603; 8592 bytes / 931816954775507130). Allocation counts unchanged.
Pending Oracle instruction counts; not yet a fully qualified candidate.
