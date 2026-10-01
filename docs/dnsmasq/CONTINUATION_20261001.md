# Continuation checkpoint — 2026-10-01

The dnsmasq rewrite/optimization remains one ongoing task. Correctness and
performance acceptance are separate; neither full equivalence nor production
acceptance is complete. Preserve user-owned `docs/prompts/` changes and all
failed evidence. Physical-router experiments/deployment need a separate
explicit request and verified recovery gate. Local and build-host isolated
work is already authorized.

The user added automatic cleanup of obsolete branches. `AGENTS.md` now records
the rule. Twelve completed branches were retired after tagging their original
tips and detaching clean worktrees; all evidence directories remain. See
[the branch archive index](BRANCH_ARCHIVE_20261001.md) for replacements of
historical branch names. Active reverse implementation/gate and the latest
private TCP reference keep their branches.

This checkpoint replaces the earlier contradictory in-flight notes. Phase
reports and frozen artifact manifests remain the evidence for each result.
Git history retains the older checkpoint.

## Current handoff after credit interruption

The user replenished platform credit and requested continuation, including
subagents. No account/billing mode was changed. Product HEAD has the units
below; the product worktree contains only user-owned `docs/prompts/` edits.
Do not overwrite those files or private experiment worktrees.

| Current unit | Durable state |
| --- | --- |
| TCP admission/resource recovery | `bb1a664`, `cef8001`: retained listener, shared capacity. Resource61, TCP recovery17, capacity31 passed with negative controls. |
| UDP send retries | `1188018`/`750e8de`: exact helper53, DNS209, service61; source errno/nanosleep edge preserved. |
| Fast retry counters | `1787a08`/`1972dd6`: actual producer and all metrics snapshots. Scoped87/88 retains C wrong-ID/question-case defect; nested doctor18/18, HUP5, initial failure61, state1285. |
| DHCP hosts-derived addresses | `07a7eb5`/`8c34170`:27/27 C snapshots, before10/27; static208, hostfile41, reverse lifecycle87. |
| Typed cache transfer primitive | `1f6a429`/`aa474e5`:36 cases/307 observations native and musl Rust; ordinary allocation vectors unchanged across5 cases. Root ordinary-cache22571 and cache/counter764 regressions pass. No main TCP sender or storage representation adopted. |
| DO/AD/CD and known names | `664079d`/`e0dc08d`/`cdc6383`:750/750 native C and actual image C, AD negative749/1; name predicate108 with negative. Unsigned DO answers forward; CNAME/negative A/AAAA AD paths anchored. DO lookup/LRU side effects are a separate open audit. |
| Independent bogus cache transaction | `5094420`/`220577d`/`5a1505c`:256/256 native and image C; preserved DO750/750; negative detects1. |
| Ordinary CD extraction before commit | `3e3e203`/`0c8f362`: explicit `Unsupported`/`ExtractOnly`/`Commit` modes; native and image134/134. Intermediate removals, pressure eviction and pending cleanup survive suppressed commit. Same ELF preserves DO750, bogus256, policy471, EDNS155 and service210. See `DNS_CD_COMMIT_PHASE.md`. |
| DO lookup before forwarding | `aeba67e`: pressure/victim gate native/image120/120, before112/120; negative119/1. Same ELF preserves native/imageDO750 and nativeCD134; isolated389 library+7 main/16ignored, native/musl Clippy. See `DO_LOOKUP_FIX_VALIDATION.md`. |
| Generic lookup after ordinary miss | `5c15e16`: independent NX/SOA pressure native/image120/120, before108/120 then116/120 after the DO-only repair; direct/CNAME120/120 per reference preserved. Both negative controls detect1. Final isolated389+7/16ignored and native/musl Clippy pass. |
| Generic forward insertion | `4bf072d`: native/image22 configuration+78 forward observations, separateQTYPE0 native/image9. Same ELF preserves DO750 per reference, nativeCD134, both pressure120 per reference and isolated389+7/16ignored/native+muslClippy. First image run had75 matches+1 readiness timeout; complete sequential replay78 passes, failure retained. Malformed generic error propagation is a known source-audit gap under separate C-first qualification. |
| Generic malformed reply propagation | `0fae34f`/`ac8a3b6`: native/image35/35, before14 differences per reference; negative34/1. Prefix removals/evictions remain. Final native normal22+78, policy210, bogus256, isolated389+7/16ignored and native/muslClippy pass. RecordTooLong keeps prior cache-abort/forward behavior; no oversized-data equivalence claim. |
| Private reverse-cache candidate | `702af88`/`19620e3`/`deab8a0`/`62894d6` on `research/dnsmasq-reverse-cache-candidate-20261001`. Shares slots/LRU/counters without new fields/index. Primitive125/125 on19620/deab; real UDP beforedeab91/124, after62894native/image124/124, negative123/1. Target case retained. Local/lease ownership, reverse transfer, multi-target order and resource qualification remain open; no product merge. |

Current agents/ownership:

- After another credit interruption, the old agent manager tree disappeared.
  New workers resumed the existing worktrees rather than restarting experiments.
- `one_index_audit_resume` completed the singleton-index audit in
  `resume-single-index-20261001`; its final report is `089db24` (main `0f64bf0`).
  Like inline16, this candidate is rejected. No new timing is active or pending.
- `tcp_writeback_gates` completed independent doctor/pipe/slot12 and ordinary
  UDP CD134 gates in `../owrt-tcp-writeback-gates`; their tools/reports are merged.
- `cache_rr_resume` completed the normal generic and QTYPE0 gates plus final
  `ac8a3b6` native22+78 regression; tools/reports are merged. It now owns
  reverse Stage3 real UDP/DHCP lifecycle C-first qualification, reusing the
  active reverse gate branch. Stage1 primitive125 and Stage2 UDP124 are
  complete. The separate four-process C-only multi-target cohort retains
  two real output/LRU orders; no sorting or Rust pass is inferred.
  Original unsupported-option attempts and the readiness timeout stay archived.
- `reverse_cache_impl` owns the private candidate worktree at `62894d6`.
  Final native ELF is
  `601550b04418152ba5a865343ee3e44d93c64b610f29440577c1e294a547726e`.
  It is running backward forward-cache/transfer and allocation/layout checks;
  no publication/import/local-composition changes before their C gates.
- `tcp_stream_resume` owns a new active reverse-transfer gate branch, with
  C-first reverse-direction/parent-local/expiry/counter cases. The existing
  typed307 fixture remains unchanged. Its earlier TCP stream reference stays
  private and frozen independently of the newer reverse candidate.
- `tcp_stream_review` completed the C-first malformed generic gate in
  `generic-malformed-gate-20261001` at `c6a1121`: final native/image35 and
  negative34/1. All tools/reports are merged; raw prefix effects and old14
  differences remain. Root implementation validation is separately linked.
- `tcp_reference_resume` completed a private correctness reference, preserved on
  tag `evidence/20261001/dnsmasq-tcp-reference` at `df75fb4`; worktree is
  `private/dnsmasq-rewrite/tcp-private-reference-20261001`. Frozen executable
  source `86b81ab` passes TCP32, native UBus69/69+581 checks, independent12,
  EMFILE17, capacity31, namespace395 library+7 main/16ignored, native/musl
  Clippy. The later stale branch is `2b149fa`, executed source `2a773f8`:
  stale41/41, C164/Rust154 auxiliary checks, normalTCP32, UBus69/69,
  isolated398+7/16ignored and native/musl Clippy. Ten C process-shape checks
  are inapplicable to Rust and are not Rust passes. The same ELF also passes
  CD65/65 and C152/Rust152 checks; CD branch is `e5ee749`. See
  `TCP_STALE_REFERENCE_RESULT.md` and `TCP_CD_POLICY_REFERENCE_RESULT.md`.
  `tcp_stream_resume` then qualified explicit Begin/record/End private source
  `dff7a39`, preserved at branch `research/dnsmasq-tcp-stream-import-20261001`
  / `32f8db3`. PartialEOF improves from19/24 to27/27 (the new format includes
  the previously C-only partial-end case); normal32/stale41/CD65/UBus69,
  EMFILE17/capacity31/writeback12, native/musl transfer307 and isolated398+7
  /17ignored pass. See `TCP_STREAM_IMPORT_REFERENCE_RESULT.md`.
  The shared product does not contain this implementation or `Clone`.
- Root owns integration, reports and source/artifact identity checks. Merged
  DO plus typed-transfer host DNS tests217 passed/5ignored, full Clippy/fmt pass.

Private reference implementation uses highest-free indexed slots, lowest-ready
single-transaction drain, UBus-before-new-drain, a pinned partial-transaction
barrier and clock, joined-worker+EOF release, STOP under admission lock and
actual kernel pipes. It avoids the incorrect one-message queue/doctor dependency
cycle. Raw FD numbers are wake hints only; actual I/O rechecks current owners.
Read `TCP_PRIVATE_REFERENCE_RESULT.md` before resuming or changing this branch.
Deep clone, whole-vector sender allocation/OOM, arbitrary malformed record
lengths, ENOMEM/ENOBUFS and exact native pipe-byte saturation remain unqualified.
The named partial-EOF, stale and CD profiles above are
qualified only on their private native source, not all policy combinations.
A documented early host-namespace unit attempt is not acceptance; final tests
ran through isolation. Do not silently promote this reference to product code.

There is no active quiet performance window. The frozen representation screen
completed48 runs/24000 operations, chunk32 completed24/12000, and inline16
completed24/12000, all without functional errors. Compact, shared-entry,
top-level COW, chunk32, inline16 and singleton-index all failed
at least one unchanged resource/timing guard. No representation is accepted;
no extra rounds or relaxed thresholds were used. Results are in
`TCP_SNAPSHOT_SCREEN_RESULT.md`, `TCP_SNAPSHOT_CHUNK_RESULT.md` and
`TCP_SNAPSHOT_INLINE16_RESULT.md`. Inline16's population guard passes, but
150-full pair1 p95 increases 8.63%, exceeding the frozen 5% guard. Large-cache
CPU gains47.39%/27.85% and heap gains49.20%/52.34% cannot waive that failure.
Both owners were released from the completed quiet window; do not restart it.
The singleton-index screen separately completes24 runs/12000 with0errors:
large-cache CPU gains66.60%/54.60% and heap gains51.59%/54.88%, but worst-pair
population CPU ratios1.504043/1.053962/1.050995 fail the frozen5% guard at all
full profiles. See `TCP_SNAPSHOT_ONE_INDEX_RESULT.md`. Every window is retained;
no extra run, threshold waiver or product representation adoption occurred.

At this checkpoint the product is frozen at `ac8a3b6`; later commits add tools
and derived reports. Its native ELF is
`3d8462fac7a81707e3b24f84b1a25fc8b6903d808b66b14cc4f3ede9e230b692`.
`GENERIC_MALFORMED_IMPLEMENTATION_VALIDATION.md` records the complete final
checks. Snapshot composition has only a source/cost audit in
`TCP_SNAPSHOT_COMPOSITION_REVIEW.md`; no candidate, measurement or adoption
follows from that audit. `TCP_PAIRED_HOST_COST_FEASIBILITY.md` proposes a
diagnostic full-service comparison but identifies configuration, CPU/thread
accounting, drain, resource-budget and symbol prerequisites; no new formal
cost window is authorized by that note. Reverse work now proceeds through
local/lease coexistence and typed transfer after the qualified direction/
expiry/LRU and UDP gates, preserving forward behavior and shared capacity.
The original CD136 image-C calibration failure remains archived; the final
CD134 fixture removes only an unrelated redundant control replacement. The
source-supported hash/layout explanation is not a demonstrated repair.

## Latest committed functional progress

| Unit | Evidence and bounded result |
| --- | --- |
| `9910009`, `53d1290` live UBus integration | Main metrics read actual cache/forward/lease/message owners; UDP doctor and DHCP source events are wired. Native C schedule 68/69 paired matches; TCP parent insertion remains red. See `UBUS_DAEMON_PHASE.md`. |
| `405b7c1` clipped later sections | Complete Answer records may cache despite clipped later sections. `DNS_CLIPPED_CACHE_PHASE.md` preserves the original failures and 96-operation final gate. |
| `bf3a73c`, `58b2231` DHCP source events/reverse names | Source notification precedes file/DNS/socket effects; static reverse-host fallback for ordinary ACK/INFORM passes 28/28. |
| `e77d966` borrowed cache engine | Common record builder/insertion adapter extracted without adding a UDP resolver or owned local-name generation. See `DNS_CACHE_ENGINE_EXTRACTION.md`. |
| `0e12c4d` TCP ownership baseline | Exact C normal foreground (`-k`, not `-d`) establishes 32 cache/snapshot/clock/writeback observations. Rust implementation remains open. |
| `69f24bb`, `7b55df8` ordered cache side effects | 471 policy operations and actual UDP 42 cases/210 replies match; aborted transactions retain C's preceding removals/evictions. Negative controls detect injected errors. |
| `377c8a1` cold empty OPT caching | 32 IPv4/IPv6 cases/64 replies match after 26 original differing cases; first-query cache eligibility does not alter coalescing/retry flags. Eight coalescing/retry cases match. Full EDNS/DNSSEC metadata remains open. |
| `5831e97` reverse-host startup/HUP | 87/87 checks; 14 snapshots equal independently frozen C bytes, prior 70/87 failure retained. ACK/INFORM 28/28 and Linux DHCP 117/117 pass. See `DHCP_REVERSE_LIFECYCLE_PHASE.md`. |
| `630addb`, `bb1a664`, `cef8001` upstream failure/TCP admission | Initial error replies and retained listeners now pass all 61 observations, focused TCP recovery 17/17, shared slot admission 31/31. Original 51-observation partial gate and capacity 23/31 failure remain archived. See `DNS_TCP_ACCEPT_FAILURE_PHASE.md` / `DNS_TCP_CAPACITY_PHASE.md`. |

The empty reverse short-name persistence boundary remains a documented safe
Rust difference; it is not an executed C pass. All counts above belong to
their own frozen sources, not automatically to the latest working tree.

## Coherent integration validation

`RESUMED_INTEGRATION_20261001.md` qualifies committed source `8c34170`:
Linux library381 passed/15 ignored, main6 passed, DHCP→DNS34/34; native/musl
all-target Clippy passes. Native ELF
`ee92c7e2bc43e774a3a63ecfa360e90c1f3fc46a0e9c8144f27ae1d1100d8a0f`.
This is not a new SDK artifact or a whole-C equivalence result.

## Target artifacts and cost status

Latest existing inert SDK source is `405b7c1`, with later cache/lease/error
fixes outside that artifact. Rust ELF is 1,178,407 bytes, SHA-256
`f93fc151e7faabb15ae03264650d271145ef88cbe02851317e546e6e6a501590`.
Exact image C ELF is 269,305 bytes: Rust adds 909,102 bytes (337.6%).
The target UBus gate has 67/69 paired matches and two failures: missing TCP
parent cache insertion and the target musl C doctor's in-place failed-parse
address mutation. Keep the complete gate nonzero; do not emulate that bad
address mutation or silently exclude the case.

Historical `574f5ed` and DYN1 results remain in their separate reports; neither
represents current source. All packages are inert `/usr/libexec/dnsmasq-rs`
stages, not stock replacement, image assembly or production deployment.

`C_COST_RESULT.md`: nine C-only windows, 660,000 correct completions; no paired
Rust or router conclusion. EPS1's private primitive screen and counted rebase
are in `CACHE_EXPIRY_SCREEN_RESULT.md` / `CACHE_EXPIRY_COUNTED_REBASE.md`;
default product cache has not adopted it.

`TCP_SNAPSHOT_SCREEN_ALLOCATION.md`: all four private representations pass
21 scenarios/22,571 operations. Shared-entry snapshots reduce requested heap
49.20%/52.34% at capacities 1,000/10,000, while parent heap rises 2.23%/2.36%
and population adds one allocation per entry. The later `TCP_SNAPSHOT_SCREEN_RESULT.md` completes the frozen 48 runs. Shared
CPU/completion improves 48.67%/29.84%, but its worst population CPU pairs at
150/1,000 full regress 10.63%/13.71%, failing the unchanged 5% guard. Compact
and top also fail. No candidate is accepted and no extra rounds are authorized
by this result. Requested heap is not RSS/exclusive memory.

## Reference and execution environment

- Target: AX3000T, OpenWrt 25.12.5, dnsmasq 2.93-r1 `nodhcpv6`.
  OpenWrt revision `f0a60eee2fe051741c643ea6118718aae1ef17fb`.
  Source/features: `OPENWRT_CONTRACT.md`, `REFERENCE_AUDIT.md`.
- Local matching C source: `private/dnsmasq-rewrite/reference/dnsmasq-2.93`.
- Authorized build host: `ssh oracle`. Exact native C build:
  `/home/ubuntu/dnsmasq-rewrite-20260929/c-native-01`; executable
  `dnsmasq/dnsmasq`, SHA-256
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Exact image C ELF SHA-256:
  `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
  Use the verified private musl runner/identity and all matching libraries.
- Rust 1.98.1; remote Cargo `/home/ubuntu/.cargo/bin/cargo +1.98.1`.
  Build frozen source in a fresh target directory to avoid stale extraction
  mtimes or mixed main/library outputs.
- Run network experiments only through
  `sudo -n sh tools/dnsmasq/run_isolated.sh ...`. Each gets private network,
  mount and PID namespaces; only loopback is enabled. Never bind experimental
  DHCP to the ordinary host network. Raw inputs/ELFs/configs/leases stay private.
- SDK:
  `/home/ubuntu/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64`.
  Use `build_package.py` protected snapshot and recipe restoration.

## Invariants and remaining delivery boundaries

Parent events serialize `event -> DHCP provider -> parent DNS`; socket waits
stay outside the shared lock. Release parent DNS before provider reload,
because its publisher reacquires DNS. Initial lease publication finishes before
workers; DHCP publication precedes ACK. UBus callbacks must not reacquire the
provider after DNS. The one parent cache/table serves every UDP listener and
replies retain their original listener. TCP must acquire an accept-time private
snapshot; sharing the mutable parent cache would break the observed C contract.

Continue actual TCP cache inheritance/writeback/fixed-time/slot cleanup, then
remaining cacheability/PTR/EDNS, dynamic resolver/interface/source-port behavior;
DHCP tags/all options/mixed hosts-lease precedence/relay/PXE/leasequery/helpers;
TFTP main IPv6/multiple listener/source-interface behavior; permissions, logs,
UCI/procd/ujail/ACL/hotplug/odhcpd/rpcd/LuCI and pressure/long-run recovery.
The 169 indexed capability entries are not 169 implemented capabilities.

Known C reference differences remain explicit: SRV uninitialized type, TFTP
stale DATA/FD leak, TCP retry length/inherited OPT, local CNAME object reuse,
stale UBus type IDs, doctor receive-buffer lifetime and musl failed-parse
mutation, duplicate-capacity and failed-coalesced-retry wrong request IDs. The same-bucket incidental
lease expiry under clock rollback also retains a red case. Safe behavior does
not itself resolve compatibility acceptance. Never turn unexecuted tests,
ignored tests, stage artifacts or local screens into full acceptance claims.
