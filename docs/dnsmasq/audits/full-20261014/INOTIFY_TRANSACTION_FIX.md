# Hostsdir replacement publication (2026-10-14)

Product fix: `340ed73e83e58ba845e0a645eb21e9ead0d0f108`, branch
`fix/dnsmasq-full-inotify-20261014`, based on frozen integrated source
`19bd6162e1b33c92a1e5ea26e864497800c7cfed`. The integrated branch, its ELF,
main and the physical router were not changed. All runtime observations below
come from private Oracle namespaces and synthetic hosts/DHCP fixtures.

## Reproduced boundary

The prior integrated ELF, SHA-256
`fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b`,
failed the existing inotify probe without a held TCP connection: 2000 initial
hosts, 6000 replacement rows, and that process's VmSize +1024 KiB RLIMIT_AS.
The first update reached source EOF, then UDP and fresh TCP returned
`new000000.test` and `new003000.test` but not `new005999.test`; both old samples
were absent. Removing the limit without another update retained this partial
generation. A later close-write update recovered successfully.

The original run and three fresh repeats all showed this partial publication.
Their total ENOMEM counts were 2616, 2592, 2581 and 2592. The first update's
2490/2466/2455/2466 ENOMEMs occurred after source EOF and before client probes;
the second update stopped during staging. Configured DNS, lease DNS, DHCP and
process health remained good. This was missing hosts data, not a daemon crash
or a general client outage.

The exact C daemon, SHA-256
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`,
adopted both complete sampled replacements at +1024 KiB with zero ENOMEM.
Its +512 KiB case also passed; at +256 KiB it exposed partial samples and fresh
TCP failed under pressure, while configured UDP DNS and DHCP stayed healthy.
Its general probe `passed` flag excludes pressure TCP health, which is retained
separately. Unrestricted C and prior Rust controls both adopted complete sampled
generations with zero ENOMEM. The existing C partial-record policy is not claimed
to be identical to Rust's complete-generation policy under allocation failure.

The prior six Rust no-held-TCP cases covered 2000/6000 replacement rows and
+256/+512/+1024 KiB. Five passed; only the 6000/+1024 case published a sampled
partial generation. Prior raw results and the three additional repeats are in
`/dev/shm/full-integrated-edge-20261014/private/inotify-no-held-*`.

## Cause and change

The incremental owner removed the old source and called `Hosts::insert` for each
staged row without observing allocation failure. That API intentionally folds
duplicate and failed insertion into `false`, including best-effort ancestor
index failures. Discarding failed rows could free enough memory for the later
publication copy to succeed, publishing an incomplete replacement.

An adjacent recovery path also discarded an unshared local owner before trying
to copy the daemon view back. A separate allocator diagnostic, using unchanged
`Hosts` and the production retention/restoration branches, showed that persistent
publication and restoration failures leave the local view empty. That diagnostic
is a code-path model, not a claim that the shipped ELF's runtime matrix reached
this second failure.

`Hosts::try_replace_source` now builds a private working copy. Source removal,
source-path copying/indexing, record insertion and ancestor-index allocation must
all succeed. The owner loop then makes the daemon publication copy before
replacing either published owner. Any failure drops the unfinished replacement;
the previous owners require no restoration allocation. Duplicate handling,
query order, source identity and suppressed PTR ownership on deletion retain
their prior rules. Keeping the old local owner deliberately increases the live
tables during an unshared incremental replacement.

The dedicated allocator test calls the same production helper and publication
copy. It walks single and persistent failure cut points with/without a held TCP
snapshot, for replacement and deletion, including duplicate records, ancestor
names, source paths and suppressed PTR ownership. The native allocator suite
passed 8 tests; Linux unit/allocator and the broader combined candidate checks
are recorded separately by the final candidate review.

## Fixed inputs and runtime results

- Source: `/dev/shm/full-inotify-fix-20261014/private/source`, commit `340ed73e`.
  All 647 archived files were compared with their Git blobs and remained unchanged
  after building. Source tar SHA-256:
  `ee39f5ebe9440012a2ec8250ae1674fa093c9dec728b52c1e7bb00c8a3492a4b`.
- ELF: `/dev/shm/full-inotify-fix-20261014/private/release-final/dnsmasq-rs`,
  2,089,440 bytes, SHA-256
  `edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d`.
- Build: Rust 1.98.1, existing matched SDK/musl, feature-off opt3/LTO/static PIE.
  The private build wrapper changes only the output allowlist and Cargo target
  directory. Build flags, receipts and input hashes remain beside the ELF.
- Probe: unchanged `full_r2_hosts_recovery.py`, SHA-256
  `a0fd9f5a57188e6459d7e1707e78df59034ac1d647eced953216440581037ade`,
  identical to the prior `full_r2_hosts_recovery_v2.py`.

Each table row was run twice, with and without a held TCP snapshot; each process
received two close-write updates. No HUP was used.

| Replacement rows | Headroom KiB | ENOMEM total | Source EOF in each update | Parent/fresh TCP samples |
| --- | --- | --- | --- | --- |
| 2000 | 256 | 2 | yes | complete old |
| 2000 | 512 | 2 | yes | complete old |
| 2000 | 1024 | 2 | yes | complete old |
| 2000 | unrestricted | 0 | yes | complete new, then next |
| 6000 | 256 | 215 | no | complete old |
| 6000 | 512 | 262 | no | complete old |
| 6000 | 1024 | 2 | yes | complete old |
| 6000 | unrestricted | 0 | yes | complete new, then next |

All 16 cases passed. The failed prior 6000/+1024/no-held-TCP point then passed
three additional fresh runs, each with two ENOMEMs and complete old samples.
In every EOF-plus-ENOMEM case there was exactly one failure after each EOF.
Syscall evidence does not distinguish working-copy from publication-copy failure.
All pressure, limit-release and later close-write recovery stages passed configured
DNS, lease DNS, UDP/TCP and DHCP ACK checks. Held connections retained their old
snapshot throughout. All daemons exited normally after the tests. Samples cover
old first/last and new first/middle/last names, not an exhaustive name traversal.

The [derived evidence index](inotify-transaction-evidence.json) binds the 17 prior
C/Rust runs and 19 fixed Rust runs to result hashes, resource settings, availability
checks and sample-generation results. Fixed commands/logs/results are in
`/dev/shm/full-inotify-fix-20261014/private/inotify-*`.

Both evidence sets are backed up in this worktree's ignored private directory:

- `private/full-integrated-edge-20261014/evidence.tar.gz`, SHA-256
  `d33f96d854672a5de4fb2319e3f9344e157fd31688053c7d469fdac4d8fc599d`.
- `private/full-inotify-fix-20261014/evidence.tar.gz`, SHA-256
  `e2ae1f6537c4ca8d6b57b85a1d1157a19242a3d287ff3e219d7c3d5b541fa41c`.

The archives retain packets, syscall traces, source/tool identities, commands,
build receipts and the respective ELF. Reproducible staged rootfs copies are
excluded; the fixed archive includes the exact Git source tar.

## Reproduction

Run only on Oracle in a fresh output directory. Add `--held-tcp` for the held
snapshot boundary, or change `--new-rows 6000` to `2000` for the other row set.

```sh
BASE=/dev/shm/full-inotify-fix-20261014/private
TOOLS="$BASE/source/tools/dnsmasq"
sudo -n env PYTHONPATH="$TOOLS" sh "$TOOLS/run_isolated.sh" \
  python3 "$TOOLS/full_r2_hosts_recovery.py" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --rust "$BASE/release-final/dnsmasq-rs" \
  --rust-sha256 edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d \
  --source-commit 340ed73e83e58ba845e0a645eb21e9ead0d0f108 \
  --output "$BASE/reaccept-inotify-6000-no-held" --services shared \
  --initial-rows 2000 --new-rows 6000 --headroom-kib 256,512,1024,none \
  --repeats 1 --hostsdir --sides rust
```
