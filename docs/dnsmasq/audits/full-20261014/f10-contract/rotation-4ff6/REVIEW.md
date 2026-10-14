# 4FF6: actual hash-chain order and bounded TCP memory

This receipt tests only frozen product
`4ff6a8a27f6a835b5e8cb90a256211fa96383eb5`, Oracle ELF
`/dev/shm/full-f10-product-20261014/private/release-4ff6/dnsmasq-rs`, SHA-256
`a2e4fa11516a39c8018b7fb40bd94ec91ff5df5e15366b160309dbf0d2a07df4`,
2,114,016 bytes. It does not transfer these results to the later incremental
DHCP repair. Every case ran fresh against the unchanged exact-image C ELF.

| 60k-record case | C peak bytes | Rust peak bytes | Rust rolling start/end PSS KiB | Raw comparison |
| --- | ---: | ---: | --- | --- |
| Warm / 20 TCP / 64 MiB | 17,051,648 | 27,119,616 | — | 20/20 equal |
| Original repeated-address rolling / 64 MiB | 16,584,704 | 26,755,072 | 25,780 / 25,808 | 6,020/6,020 equal |
| Unique-address rolling / 64 MiB | 16,842,752 | 34,988,032 | 33,540 / 33,568 | 6,020/6,020 equal; relative also equal |

All sides complete 20 connections, final UDP and 2,000 rolling accept-before-drop
cycles where requested. OOM counters remain zero; cgroups are empty and removed.
Rust warm-parent to 20-client PSS changes from 26,300 to 26,712 KiB (repeated)
and 34,060 to 34,472 KiB (unique). The seed connection closes before client 20,
so this endpoint includes reclamation of its old pages; it is not a per-client
allocation measurement. Rolling adds 28 KiB over 2,000 cycles in both cases.
These measured workloads retain bounded behavior after introducing actual
global hash links; they do not establish a universal memory limit.

The original repeated-address driver remains byte-identical to the driver that
exposed 188/6,020 errors. Warm/unique use the prior committed delivery driver.
Old OOM and wire failures, and the B99E evidence, remain untouched.

The [five-line same-process counterexample](../query-order/REVIEW.md) was also
rerun using this same 4FF6 ELF. The unchanged bounded driver loads its 200-name
pool, records 201 complete TCP PTR owners, observes the effect of a parent A
query, then HUP-reduces to five records without restarting the daemon. Each
implementation selects its own observed colliding name under its process seed:
C selected `y133.test`, Rust selected `y098.test`.

Both minimal sequences now produce PTR `[selected, x.test]`, A x.test
`[192.0.4.1, 192.0.2.1]`, then PTR `[x.test, selected]`. All minimal replies have
RCODE=0 and TC=0. This proves the measured query-caused cross-name transition
under each actual process's bucket state. It does not claim raw equality of
different selected names, suppress unrelated order differences, or turn one
observed ordering into a universal rule. B99E's unchanged PTR result remains
preserved as a negative control.

[summary.json](summary.json) retains the selected five-line inputs, raw minimal
replies, process identities, metrics and original result hashes;
[collect.py](collect.py) recomputes those gates. [identity-after.json](identity-after.json)
rehashes Oracle evidence and verifies no processes or host mounts under these
four output prefixes remain. Twenty-four raw files are backed up in ignored
`private/f10-rotation-4ff6/oracle`, with archive and manifest alongside it.
Generated rootfs stages are excluded.

Oracle prefixes under `/dev/shm/full-f10-product-20261014/private`:
`rotation-4ff6-warm`, `rotation-4ff6-repeated-original`, `rotation-4ff6-unique`,
`ptr-collision-4ff6`. Replay commands are the same as the linked B99E rotation
and query-order receipts, substituting `release-4ff6` and fresh output paths.
No physical router operation was performed.
