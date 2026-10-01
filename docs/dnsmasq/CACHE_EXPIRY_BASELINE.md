# EPS1 pressure baseline and implementation review

The pre-candidate local pressure gate passes: **37 scenarios, 26,992 commands
per implementation, zero C/C or C/Rust differences**. Exact C ran in three
fresh processes for each scenario; every output row was identical. No order
normalization was used. No EPS1 implementation or performance measurement has
been run, and the product cache source was not changed by this work.

[CACHE_EXPIRY_SCREEN_V1.md](CACHE_EXPIRY_SCREEN_V1.md) was committed as
`72d7e8d` before these results. Its source/capacity/TTL, correctness, CPU and
storage gates remain unchanged. The generated source, binaries and traces are
in ignored `private/dnsmasq-rewrite/cache-expiry-eps1/baseline-01/`.
[Derived identities and vector index](CACHE_EXPIRY_BASELINE.json) records the
input hashes, source hashes, compiler, C/Rust binary hashes and manifest hash.

## What the baseline establishes

The existing `dns_cache_diff.py` builder extracts the pinned patched C cache
functions and relevant header declarations; this new runner snapshots Rust
`cache.rs` and `wire.rs` from Git `bb0a923`. It does not compile a concurrently
changing working tree. All inputs are written and hashed before execution.
The C output is the expected result; Rust supplies no expected answers.

| Fixed pressure family | Capacities | Commands across the three capacities |
| --- | --- | ---: |
| Full unexpired cache / LRU spill | 8, 64, 1000 | 2246 |
| Simultaneous expiry | 8, 64, 1000 | 2246 |
| Mixed expired/live records | 8, 64, 1000 | 2246 |
| Removed earliest expiry | 8, 64, 1000 | 2255 |
| Replacement with an earlier expiry | 8, 64, 1000 | 2255 |
| Failed commit / pending abort cleanup | 8, 64, 1000 | 2270 |
| Preserved CNAME target replacement and later expiry | 8, 64, 1000 | 2261 |
| Backward supplied time and later expiry | 8, 64, 1000 | 2246 |
| Name-wide negative markers | 8, 64, 1000 | 2246 |
| Whole-RRset eviction | 8, 64, 1000 | 2216 |
| Finite stale allowance, including its exact boundary | 8, 64, 1000 | 2246 |
| Forever stale policy with capacity pressure | 8, 64, 1000 | 2246 |
| Independent known-output calibration | 1 | 13 |

Comparison retains success/failure, hit/miss, record type/value, expiry,
remaining TTL, negative/stale bits and row/record order. The calibration checks
successful insertion, exact expiry, rejected zero TTL, failed commit and
invalid CNAME-link behavior. Deliberately changing a returned value is
detected by the comparator. All C runs exit successfully without reported
ASan/UBSan errors; the Rust driver also exits successfully.

These are **native Darwin arm64 primitives**, compiled with Apple clang 21.0.0
(`-O1 -g`, ASan/UBSan) and Rust 1.98.1 (ordinary functional driver build).
Their flags intentionally are not comparable performance flags. The C harness
uses small source-driver stubs, including a zeroing allocator and an explicitly
disabled parent cache pipe. This gate does not exercise allocation failure,
daemon packet parsing, reverse/local records, full build/dependency identity,
TCP IPC or physical-target behavior. It supplements the former pressure-light
primitive corpus; it does not replace the full C-object/service gate.

## Space and smallest reviewable prototype

The same local compiler reports baseline `size_of::<Cache>() = 160` bytes and
`size_of::<Entry>() = 120` bytes. These are struct layouts, not total heap
footprint. `size_of::<i64>() = 8` bytes is the proposed bound payload.
The candidate's actual layout/allocation delta is **not yet measured**; the
screen caps fixed Cache growth at 16 bytes after alignment, with no additional
heap allocations or per-entry storage and unchanged resource limits.

The smallest prototype has four changes, all confined to cache bookkeeping:

1. Add an `i64` expiry lower-bound field; initialize it to `i64::MAX` in
   construction and `clear`.
2. Lower the field when each valid pending entry becomes committed. Do not
   add failed, aborted or discarded pending entries.
3. At the existing occupied-tail pressure branch, call the unchanged global
   scan only when `policy.expired(bound, now)` is true. During a real scan,
   retain the original removal order and recompute the minimum from committed
   survivors. Do not put dangling-CNAME removal into this expiry-only pass.
4. Leave the bound unchanged on ordinary removals, including the new selective
   DHCP publication invalidation. It can become conservatively early, causing
   an extra scan, but can never hide an expired committed record.

No delete-time heap repair, new ownership layer, per-slot generation index or
lazy tombstone cleanup is needed. Existing CNAME generation, name-conflict,
pending-insert, LRU and whole-RRset code stays authoritative. An expiry setter
or stale-policy mutation added later would require updating the invariant;
the reviewed cache has neither API.

The next integration step belongs on the source that includes the concurrent
selective-invalidation/shared-cache changes. First re-run these exact-C
pressure vectors against that source and the candidate, plus old/new Rust
trace comparison for regression detection. Then complete the planned exact
full-C-object pressure gate and affected service tests before timing.
Existing baseline success cannot be assigned to an unbuilt candidate.

Reproduce the local baseline into a fresh ignored directory:

```sh
python3 tools/dnsmasq/cache_expiry_baseline.py \
  --rustc rustc \
  --output private/dnsmasq-rewrite/cache-expiry-eps1/baseline-02
```

`--prepare-only` freezes source snapshots and input vectors without compiling
or executing either driver. This tool does not run a benchmark or modify
`components/dnsmasq/src/dns/cache.rs`.
