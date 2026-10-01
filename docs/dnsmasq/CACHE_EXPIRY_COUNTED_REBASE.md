# EPS1 counted-API rebase: correctness only

EPS1 is rebased in private storage onto Git
`32774048cea392dc8494f71185be580ee9299a5e`, which includes caller-owned cache
counters. The default implementation remains unchanged. No performance run or
gain is assigned to this new source; the earlier 816b955 screen remains a
separate result.

| Identity | SHA-256 |
|---|---|
| New B0 `cache.rs` | `8c73672d4ebe3959d8172cecf5b951afef61f23ec568c52b27f6b00ae081e9a5` |
| Rebased EPS1 `cache.rs` | `4f7fea0dbdbc10eac74910de95595921ca5004fc9546cfa2ea10a77a796a3ee9` |
| Candidate-only patch | `b9d7df1e6b540e6a06d211e1c30b3e5a7fd907978727e3ee6ac4cc83e3d53007` |

The prior patch applied with zero fuzz. Bound maintenance is in
`insert_counted`/`commit_counted`; the preserved ordinary API delegates to those
methods. `clear_counted` delegates to `clear`, so it resets the bound while
resetting the two metrics. The live-victim increment remains after the expiry
pass, and committed-record increments remain after successful insertion.
Neither counter location or wrapping/reset policy was moved.

| Gate | New B0 and rebased EPS1 |
|---|---|
| Pressure | 37 scenarios / 26,992 commands each; three C processes per scenario; zero C/B0/EPS1 or B0/EPS1 differences |
| Existing primitive corpus | 21 scenarios / 22,571 commands each; zero mismatches with the existing 138 cross-generic-type variations; B0/EPS1 raw observations identical |
| Exact full-object C counters | 215/215 ordered snapshots on each source; three C runs per case; counted/ordinary API behavior also agrees |
| Counter negative control | Candidate probe: 214 passed / 1 failed, exit 1, after one expected inserted-count mutation; raw C output unchanged |
| Full-object publication | 70 traces / 1,876 operations each; zero differences |
| Local CNAME/insertion | 32 ordinary cases match; both retain the same two nonzero observations in four reference-layout cases, exit 1; B0/EPS1 observations remain identical |

Measured type layouts are Cache 168 → 176 bytes and caller-owned
`CacheCounters` 8 → 8 bytes. This is layout evidence, not a new allocation or
performance screen. `wire.rs` and `lease_names.rs` retain their prior source
hashes; all other differences in the private candidate are confined to the
expiry-bound patch.

Raw source archives, patch, compiler logs, every scenario, native probes and
nonzero results are retained below ignored
`private/dnsmasq-rewrite/cache-expiry-eps1/counted-3277404/`.
The [derived index](CACHE_EXPIRY_COUNTED_REBASE.json) identifies these artifacts.

The candidate remains ready for further correctness work, not adoption.
Service load/configuration and performance boundaries must wait for the active
stale-cache and producer integration gates to stabilize before being frozen.
No target build, service performance or physical-router acceptance is claimed.
