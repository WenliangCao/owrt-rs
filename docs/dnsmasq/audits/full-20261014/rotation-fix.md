# FULL-PERF-TCP: inherited multi-address order amplification

Product fix: `2f658ea4302088a80d6f0241e141fc869e4802c9`, based on integrated
`1d535cb9bd1499a3c4bae0fc6e76e285a933b5bf`. Worktree:
`/Users/USER/Developer/owrt-dnsmasq-full-rotation`, branch
`fix/dnsmasq-full-rotation-20261014`. No main merge, push or router operation.

## Artifact identities

- Old integrated Oracle ELF:
  `/dev/shm/full-integrated-fix-20261014/private/release/dnsmasq-rs`,
  SHA256 `e2b075617d39cafa7d9443abfabbd18f9d2602dc0b535eed6393ac62ee9bbf77`.
- Fixed Oracle ELF:
  `/dev/shm/full-rotation-check-20261014/private/release/dnsmasq-rs`,
  SHA256 `0b3bba7b38c6baf4f6ff363ac715717042ea709e37171698cadc879254769aab`,
  2,089,440 bytes.
- Fixed source: `/dev/shm/full-rotation-check-20261014/source`, a Git archive of
  the product commit above. Build receipt: `private/release/build.json` under
  the same directory's parent; product-input hashes: `private/product-inputs.json`.
  Target is independent (`/dev/shm/full-rotation-check-20261014/target`), with
  unchanged opt3, musl/PIE flags and allocator.
- Exact C: `/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files/usr/sbin/dnsmasq`,
  SHA256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.

All evidence below is under Oracle
`/dev/shm/full-rotation-check-20261014/private/`. Old evidence is retained.

## Reproduction and cause

Each name has two legal IPv4 hosts records. Hold one TCP connection so the
records are shared; query every name over parent UDP; accept 20 new TCP clients,
query one two-address name per client, and keep them open. Retire the original
seed immediately before accepting the twentieth new client to respect C's
20-child limit. The parent and all C children share one cgroup budget, with
swap disabled.

The previous `rotate_shared` copied the entire inherited order map on each
child's first multi-address query. The 50k-record case did not OOM at 64 MiB, but
its actual memory multiplication was measurable. At adjacent 60k records the
same normal connection pattern killed the daemon twice.

| Evidence directory | Rust result | Exact C result |
| --- | --- | --- |
| `pss-50k-cold` | 20 clients, PSS 18,436 KiB | 8,446 KiB |
| `pss-50k-warm` | warm parent 19,868; 20 clients 58,304 KiB | 8,737 KiB final |
| `cgroup64-50k-warm` | 20/20; UDP alive; peak 58,634,240 B, no OOM | peak 14,987,264 B, no OOM |
| `pss-60k-warm` | 20 clients, PSS 89,684 KiB | 9,187 KiB |
| `cgroup64-60k-warm` | connection 13 failed, daemon -9, UDP lost, oom_kill=1 | 20/20, UDP alive, peak 16,928,768 B |
| `cgroup64-60k-warm-repeat` | same failure at connection 13, peak 67,108,864 B | 20/20, UDP alive, peak 16,777,216 B |
| `cgroup64-60k-cold` | 20/20, UDP alive, peak 23,392,256 B | 20/20, UDP alive |

## Fix and cost

Partition order maps by stable host entry ID into 64-ID pages. TCP snapshots
share each immutable page. A mutation copies only its page, preserving the
accepted parent order, private child rotation and the immutable records/index
snapshot. Failed fallible reservations preserve the previous usable order.
There is no delta/history chain or lifetime registry.

Snapshot handle tables still scale with the highest entry ID divided by 64;
this is not absolute O(1). A modified page can contain at most 64 name-order
vectors, and copying cost includes those vectors' addresses. Thus the allocation
bound measured for two-address names is not a universal bound for arbitrarily
large individual address lists. This change adds no dependency and does not
change the loader's owned/fallible clone contract.

The standalone allocation probe uses 30k paired names. On the previous source,
the first child query allocated 2,642,744 bytes and failed its small-page budget.
With the fix, twenty snapshots allocate 960,512 bytes in total; the largest
child query allocation is 2,680 bytes; twenty children retain 1,018,272 extra
bytes. Two thousand parent-query / accept-before-drop iterations peak at
1,069,496 extra bytes. Dropping the clients leaves 60,032 bytes of parent page
publication overhead. No production allocator instrumentation is used.
The probe also rejects allocations of at least 512 bytes during a shared-page
query: the answer keeps its previous order and rotation resumes after the
failure is removed. Evidence: `rotation-alloc-v2.json` and its probe sources.

## Fixed validation

- `fixed-cgroup64-60k-warm` and `fixed-cgroup64-60k-warm-repeat`: all twenty TCP
  answers and subsequent UDP succeed; oom_kill=0; Rust peaks 28,147,712 and
  27,750,400 bytes. C peaks 16,715,776 and 16,683,008 bytes.
- `fixed-pss-50k-warm`: Rust final PSS 22,012 KiB, versus old 58,304 KiB.
- `fixed-cgroup64-60k-cold`: twenty clients, UDP alive, Rust PSS 24,024 KiB and
  peak 23,683,072 bytes, no OOM.
- `fixed-cgroup64-60k-rolling-unique`: sixty thousand unique-address records,
  twenty held clients followed by two thousand rolling accept-before-drop
  cycles. All 6,020 C/Rust wire observations match (parent UDP, new TCP and old
  TCP); Rust PSS remains 35,476 KiB from rolling start to end; peak 36,642,816
  bytes, no OOM. C peak 16,957,440 bytes. A repeat with the final raw-wire
  driver (`final-cgroup64-60k-rolling-unique`) has three order differences for
  `host000500`; both Rust runs are identical, and the two C runs differ on those
  same three observations. Raw order across C restarts is therefore not a
  reliable invariant for this large table.
- `relative-cgroup64-60k-rolling-unique` and its `-repeat`: record each daemon's
  first warmup answer per name, preserve all raw replies, and also compare the
  subsequent sequence relative to that observed initial order. Both 6,020-row
  comparisons pass, including parent/old/new views, with stable rolling memory
  and no OOM. These two runs also happen to match all raw replies. The test
  reports raw and relative results separately; it does not erase a raw mismatch.
- `fixed-snapshots`: the existing IPv4/IPv6, independent family rotation, HUP,
  configured-record and inotify snapshot test matches exact C on all 42 wire
  observations.
- Eleven standalone hosts unit tests pass on both macOS and Oracle. Added
  checks cover a warmed parent and twenty private children, and 2,048 rolling
  accept-before-drop cycles with per-parent and per-child order references and
  page-owner reclamation. Oracle log: `hosts-tests.log`.

The additional repeated-address rolling test is **not** claimed to match C:
`fixed-cgroup64-60k-rolling` has 188 order differences over 6,020 observations.
Running the old ELF independently (`old-60k-rolling`) gives 191 differences;
its Rust output is byte-for-byte identical to the fixed Rust output for all
6,020 observations. The two C runs differ on three observations. This is a
pre-existing boundary exposed by this stronger test, whose cause remains
unresolved; repeated-address reverse ownership is a hypothesis, not a finding.
The unique-address relative-order controls above and the existing family/HUP
snapshot case pass. The old and fixed raw failing controls remain available.

## Direct commands on Oracle

Each output directory must be fresh. The committed driver is
`tools/dnsmasq/hosts_rotation_memory.py`; its exact Oracle copy is
`/dev/shm/full-rotation-check-20261014/hosts_rotation_memory-delivery.py`
(SHA256 `66f29e7cf865072124b6773d56f3f63cf064cd629ab7e673f769aa924be4a758`).

```sh
rotation_root=/dev/shm/full-rotation-check-20261014
image_root=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
audit_tools=/home/ubuntu/full-audit-20261014/private/source/tools/dnsmasq
rust_fixed=$rotation_root/private/release/dnsmasq-rs

# Original failing workload, repeated on the fixed product.
sudo -n sh "$audit_tools/run_isolated.sh" env PYTHONPATH="$audit_tools" \
  python3 "$rotation_root/hosts_rotation_memory-delivery.py" \
  --image-root "$image_root" --rust "$rust_fixed" \
  --output "$rotation_root/private/replay-warm-$(date +%s)" \
  --names 30000 --warmup --budget-mib 64

# Adjacent cold control: same hosts and connections, without parent warmup.
sudo -n sh "$audit_tools/run_isolated.sh" env PYTHONPATH="$audit_tools" \
  python3 "$rotation_root/hosts_rotation_memory-delivery.py" \
  --image-root "$image_root" --rust "$rust_fixed" \
  --output "$rotation_root/private/replay-cold-$(date +%s)" \
  --names 30000 --budget-mib 64

# C relative-order comparison with rolling clients; raw wires also retained.
sudo -n sh "$audit_tools/run_isolated.sh" env PYTHONPATH="$audit_tools" \
  python3 "$rotation_root/hosts_rotation_memory-delivery.py" \
  --image-root "$image_root" --rust "$rust_fixed" \
  --output "$rotation_root/private/replay-rolling-$(date +%s)" \
  --names 30000 --warmup --budget-mib 64 --rolling 2000 --unique-addresses
```

To reproduce the OOM counterexample, replace `--rust` in the first command with
`/dev/shm/full-integrated-fix-20261014/private/release/dnsmasq-rs`. The driver
persists both sides' evidence before returning nonzero for the failed Rust
health gate. The unmodified original driver used for the first discovery is
also retained as `rotation_resource.py` (SHA256
`a9bf11cd290ea6ec7372251b4a30f604fd5f2f99402c40b1dacfd5f944dd08fe`).
