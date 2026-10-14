# 340ed73e: targeted core regression

These are fresh checks of product source
`340ed73e83e58ba845e0a645eb21e9ead0d0f108` and release ELF
`edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d`.
The exact source/ELF remains under Oracle
`/dev/shm/full-inotify-fix-20261014/private/{source,release-final}`.
They complement [the original inotify counterexample and 19 repaired cases](../INOTIFY_TRANSACTION_FIX.md).
They do not replace the separate frozen-19bd audit or close F10.

| Check | Fresh result |
| --- | --- |
| Linux musl library | 789 passed, 20 ignored |
| Linux musl binary | 78 passed, 3 ignored |
| Native allocator injection | 9 passed, 0 ignored |
| 50k hosts, cache1000, 20 held TCP, 64 MiB, HUP | C/Rust passed; 20 old and 10 new answers retain the correct generations; no OOM |
| Extended TCP/hostsdir/config snapshot fixture | All 42 observations matched exact C wire and semantics |
| Shared DHCP, 2000 to 30000 hosts, held TCP, failed-HUP cache purge and natural expiry, +256/+512/+1024 KiB | All three Rust cases passed atomic samples, DNS/DHCP health, old TCP stability and subsequent recovery |
| Confirmed rollback interrupted after unmount | New-ELF trial passed actual SIGKILL and three DHCP/UDP/TCP health checks |

The 64 MiB case's process-tree cgroup peak was 46,514,176 bytes for Rust and
15,859,712 bytes for C. It exercises bounded connection growth and snapshot
retention, not equality of their absolute memory footprint.

The paired low-memory HUP driver returned **exit 1**, retained verbatim in
[core.json](core.json): exact C timed out on configured `ready.test` UDP at
+256/+512 KiB and produced short frames on fresh TCP at all three headrooms.
C stayed alive and recovered after the limit was removed; cache purge and
held-TCP checks passed. Rust passed all three complete cases. This is not
reported as an all-sides pass, and no failed C row was excluded.

The new allocator test calls the production source-replacement assembler and
publication clone at each allocation failure position until success. It covers
held/unheld owners, replacement/deletion, single/persistent failure, duplicate
records, suppressed PTR ownership, ancestor indexes and source metadata.
The old owners and query ordering stay intact on every injected failure.
The musl binaries were rebuilt and run in isolated namespaces with private
tmpfs `/tmp`; the 23 ignored tests were not executed.

[Trial evidence](trial/report.md) belongs to this new ELF and covers only the
single requested interruption scenario. The original 12-case trial suite
remains attributed to 19bd; the script and 463 tool files are unchanged.
No broad audit was rerun or implicitly promoted to this source revision.

## Reproduction and preservation

[Exact core argv and hashes](core.json) and [the original runner](run_core.py)
identify every tool and output. To replay, use a new output directory in each
recorded argv; never overwrite the evidence paths. The source tests use the
same SDK build script and `cargo +1.98.1 test --frozen --test hosts_allocations`
against this source. No allocator, release profile, RLIMIT_AS headroom or
cgroup budget was relaxed.

Core raw packets, traces, JSON, logs and test executables are backed up in the
ignored `private/inotify-core-20261014/evidence-complete.tar.gz`, SHA-256
`9993148e0cf57c714666f1bcce8e3cf6f2e77a2cbc9938fadf4cfc2137ffd01f`.
Only reproducible staged `rootfs-overlay` directories are excluded. An earlier
unprivileged archive attempt encountered permissions on overlay workdirs and
is retained separately; this complete archive was created with sudo, checked
locally, and used for the derived receipts. No raw artifact is committed.

All work ran on the Oracle test host. No physical router was modified, no
product was merged to main or pushed, and no review branch was deleted.
