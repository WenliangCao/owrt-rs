# Final 238E: same-ELF rotation, memory and cross-name order gates

Frozen product: `238e7ca4374b1889696f91816c1c239d7fe32baa`. Every Rust run below
uses Oracle `/dev/shm/full-f10-product-20261014/private/release-238e/dnsmasq-rs`,
SHA-256 **`2692c760be3719b15f4bcadb6c5a1445a9f37993a11c1369619550218e4c76eb`**,
2,122,208 bytes. Exact-image C remains
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
These are fresh final-product runs, not results transferred from B99E or 4FF6.

| 60k-record case | C peak bytes | Rust peak bytes | Rust rolling start/end PSS KiB | Raw C/Rust replies |
| --- | ---: | ---: | --- | --- |
| Parent warmup / 20 held TCP / 64 MiB | 16,551,936 | 26,931,200 | — | 20/20 equal |
| Original repeated-address rolling / 64 MiB | 16,756,736 | 26,673,152 | 25,704 / 25,732 | 6,020/6,020 equal |
| Unique-address rolling / 64 MiB | 16,965,632 | 34,504,704 | 33,500 / 33,528 | 6,020/6,020 equal; relative also equal |

Each side completes 20/20 connections, final UDP and, in rolling cases, 2,000
accept-before-drop cycles. OOM/kill counts are zero; cgroups empty and remove
successfully. Rust warm-parent to 20-client PSS is 26,228 → 26,644 KiB in the
warm case and 34,020 → 34,432 KiB in the unique case. The seed client closes
before client 20, so the endpoint includes old-page reclamation and is not a
per-client allocation measurement. Both rolling cases grow only 28 KiB across
2,000 cycles. These specific measured cases support bounded snapshot retention;
they do not establish a universal memory or performance bound.

The original repeated-address driver is unchanged, SHA
`30f7e009761ac96991269823651b17d05aeadcf8d6a798defb6a9318d00aaa8b`.
It is the same driver that exposed the retained 188/6,020 failure. Warm and
unique use unchanged delivery driver
`66f29e7cf865072124b6773d56f3f63cf064cd629ab7e673f769aa924be4a758`.
Every raw reply is retained; no normalization is needed for these three final
comparisons. All original failed controls and previous candidate evidence stay
at their existing paths.

The unchanged [cross-name query-order driver](../query-order/REVIEW.md) also
passes on this same ELF. A fixed 200-name pool yields 201 complete TCP PTR
owners. Each process observes a real query-caused crossing, then HUP-reduces to
five records without restarting. The C run selected `y196.test`; the Rust run
selected `y184.test` under its own actual seed. Both minimal sequences are:

1. TCP PTR: `[selected, x.test]`.
2. Parent UDP A x.test: `[192.0.4.1, 192.0.2.1]`.
3. TCP PTR: `[x.test, selected]`.

All minimal responses have RCODE=0 and TC=0. The derived report preserves each
process's selected input and raw packets separately. This gate verifies the
same observed transition under each actual bucket state; it does not claim
byte equality between different selected names or exempt other initial-order
differences. The old B99E failure remains a negative control.

[summary.json](summary.json) was recomputed with the unchanged
[candidate collector](../rotation-4ff6/collect.py). Its assertions check ELF
identities, complete observation counts, health, OOM counters, cgroup cleanup
and each minimal transition. [identity-after.json](identity-after.json) binds
the final Oracle files and ELF to fresh hashes and records no task processes or
host mounts under these four output prefixes.

Raw Oracle outputs are under `/dev/shm/full-f10-product-20261014/private/`:
`rotation-final238e-warm`, `rotation-final238e-repeated-original`,
`rotation-final238e-unique`, `ptr-collision-final238e`. Twenty-four result/driver/
stderr files match the ignored offline backup
`private/f10-rotation-final238e/oracle/`; `evidence.tar.gz` and
`backup-manifest.json` sit alongside it. Generated rootfs stages are excluded.

The staged-line boundary correction is exercised by its separate source-level
unit/probe and final unit-test suite. This receipt does not relabel that evidence
as C wire testing. No additional workload or physical router action was added.

To replay, use the commands in the earlier rotation/query-order reports with
the frozen `release-238e/dnsmasq-rs` and fresh private output paths. To recompute
this report's machine-readable results from the offline backup:

```sh
python3 docs/dnsmasq/audits/full-20261014/f10-contract/rotation-4ff6/collect.py \
  --evidence private/f10-rotation-final238e/oracle --label final238e \
  --commit 238e7ca4374b1889696f91816c1c239d7fe32baa \
  --rust-sha256 2692c760be3719b15f4bcadb6c5a1445a9f37993a11c1369619550218e4c76eb \
  --output private/f10-rotation-final238e/recomputed-summary.json
```
