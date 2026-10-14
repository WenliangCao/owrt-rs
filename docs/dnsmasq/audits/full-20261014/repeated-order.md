# Repeated-address order: exact C reverse groups

The 188/6,020 failing rolling observations are a real, pre-existing compatibility
gap. They are not explained solely by a random initial order, and are not a
regression introduced by the 64-ID pagination change. This diagnosis changes no
product, frozen ELF, reference source, main branch or physical router.

The old integrated ELF is `e2b075617d39cafa7d9443abfabbd18f9d2602dc0b535eed6393ac62ee9bbf77`;
the pagination-fixed ELF is `0b3bba7b38c6baf4f6ff363ac715717042ea709e37171698cadc879254769aab`;
exact-image C is `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
Their paths and product commits remain in [rotation-fix.md](rotation-fix.md).

## Runtime findings

The new probe loads the same 30,000 paired names, warms each once over UDP, and
then queries 12 selected names four times over UDP and four times over one TCP
connection. It runs unchanged C, old Rust, fixed Rust and unchanged C again.
The first run uses the original logging setting; a second run adds C's own
`--log-queries` and SIGUSR1 cache dump. A third uses unique addresses as a control.
This is semantic diagnosis, not a performance measurement.

- Old and fixed Rust have identical 30,000 warmup replies and all 96 probe replies
  in all three cases. The retained rolling test also has identical old/fixed Rust
  output on all 6,020 observations. This proves no new difference in these tested
  sequences; it does not prove general equivalence or satisfy exact C semantics.
- Both C restarts preserve one order for `host000313`, `314`, `375`, `1935`
  (192.0.3.x then 192.0.2.x), and `499`, `1999` (the opposite order), across all
  eight queries. Both Rust versions alternate every query. Adjacent names `312`
  and `500`, plus `0`, `63`, `249`, `250`, alternate in all implementations.
- C's cache dump identifies two different reverse groups for every constant
  name. For example `host000313`: 192.0.3.64 has `4FRI`, while 192.0.2.64 has
  `4F I`. `host000312` has `4FRI` on both entries. No binary instrumentation or
  recompiled C was used to obtain these flags.
- The repeated-address dump has 835 mixed-reverse names among 30,000. All
  **188/188** original fixed/C differences belong to mixed-reverse names:
  136 new-TCP, 26 parent-UDP and 26 old-TCP. The two original C runs also differ
  on three `host000500` observations; that separate initial-order variation
  does not explain the 188 deterministic failures.
- Unique-address control: all 12 names alternate in C and both Rust versions;
  C has zero mixed-reverse names. Each of the four full C dumps (repeated and
  unique, two starts each) agrees with the source-derived model on **60,000/60,000
  reverse flags**, for 240,000 matching observations in total.

See [derived results](repeated-order-summary.json) and
[source identities / cleanup](repeated-order-source.json). The analyzer checks
the raw input hashes, ELF identities, old/fixed equality and all model/dump rows.

## Source mechanism and scope

Matching source is Oracle `dnsmasq-2.93/src/cache.c`, SHA-256
`51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c`.
`cache_find_by_name` (lines 1174–1258) rotates only records sharing the first
matching record's `F_REVERSE | F_IMMORTAL` group. Thus a two-address name with one
reverse owner cannot rotate across the group boundary.

`cache_reload` borrows the packet buffer for a temporary by-address hash.
For these default arguments it has `(1232 + 255 + 10) / 8 = 187` buckets.
`add_hosts_entry` (lines 1321–1385) first performs a duplicate-name lookup, then
checks this reverse hash. Both operations use `crec.next`: the name lookup
rewrites an existing entry's next link for its answer list, with `cache_head`
at the tail, while the temporary reverse hash also follows that link. This can
truncate a previously populated reverse chain. Later records with a repeated
address can consequently receive `F_REVERSE` again; a stable first-address map
does not reproduce those groups.

The small model in `analyze_hosts_repeated_order.py` reproduces those link
operations only. Free cache entries at the answer-list tail cannot match an
IPv4 hosts record and are modeled as a terminating sentinel. It does not model
name-hash bucket ordering, infer raw initial answer order, emulate all loaders,
or claim an upstream fix. The exact runtime dump is the authority for the flags.
Loading/configured-record/incremental/PTR contracts need review before changing
the product. This finding alone authorizes no deployment or compatibility waiver.

## Evidence and replay

Oracle raw evidence: `/dev/shm/full-rotation-followup-20261014/private/`:
`repeated/`, `repeated-dump/`, `unique-dump/`. Each has `result.json`, copied
driver, per-side replies and stderr; dump cases also have each C `daemon.log`.
The driver and its memory-helper copy are in the parent directory. No task
process or host mount remained when checked.

Offline backup: this worktree's ignored `private/rotation-followup/oracle/`,
plus `oracle-evidence.tar.gz` and a 38-file `backup-manifest.json` in
`private/rotation-followup/`. Generated rootfs staging directories are excluded.
The first launch rejected an output outside `private` before starting a daemon;
the next rejected a missing parent directory. Neither is a product result.

Run on Oracle with a new output path:

```sh
root=/dev/shm/full-rotation-followup-20261014
tools=/home/ubuntu/full-audit-20261014/private/source/tools/dnsmasq
sudo -n sh "$tools/run_isolated.sh" env PYTHONPATH="$tools" \
  python3 "$root/hosts_rotation_repeated.py" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --old-rust /dev/shm/full-integrated-fix-20261014/private/release/dnsmasq-rs \
  --fixed-rust /dev/shm/full-rotation-check-20261014/private/release/dnsmasq-rs \
  --output "$root/private/replay-repeated" --c-cache-dump
```

For the unique control, add `--unique-addresses` and use another fresh output.
Recompute the committed summary from the offline backups:

```sh
python3 tools/dnsmasq/analyze_hosts_repeated_order.py \
  --rotation-evidence private/rotation-finalize/oracle/private \
  --followup-evidence private/rotation-followup/oracle/private \
  --output private/rotation-followup/recomputed-summary.json
```
