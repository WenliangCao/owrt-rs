# Continuation checkpoint — 2026-10-01

The dnsmasq rewrite/optimization remains one ongoing task. Correctness and
performance acceptance are separate; neither full equivalence nor production
acceptance is complete. Preserve user-owned `docs/prompts/` changes and all
failed evidence. Physical-router experiments/deployment need a separate
explicit request and verified recovery gate. Local and build-host isolated
work is already authorized.

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
| DO/AD/CD and known names | `664079d`/`e0dc08d`/`cdc6383`:750/750 native C and actual image C, AD negative749/1; name predicate108 with negative. Preserves raw-CD suppression and DO lookup bypass; CNAME/negative A/AAAA AD paths anchored. |
| Independent bogus cache transaction | `5094420`/`220577d`/`5a1505c`:256/256 native and image C; preserved DO750/750; negative detects1. Ordinary CD extraction-side-effect gap remains explicitly open. |

Current agents/ownership:

- `do_cache_resume` owns isolated `resume-do-cache-20261001`; completed both
  metadata and bogus units. It now waits for the independently frozen ordinary
  CD prefix-effects baseline before modifying the extraction/commit boundary.
- `tcp_writeback_gates` owns `../owrt-tcp-writeback-gates` on
  `research/tcp-writeback-gates`. Completed independent doctor/pipe/slot gate12/12.
  It now builds a narrow C-first ordinary-CD gate: held reply, CNAME-warmed old
  data, uncommitted replacement/eviction effects, pending cleanup and recovery.
  Only tools/reports; coordinate product API with the DO owner.
- `tcp_reference_resume` completed a private correctness reference, preserved on
  `research/dnsmasq-tcp-reference-20261001` at `df75fb4`; worktree is
  `private/dnsmasq-rewrite/tcp-private-reference-20261001`. Frozen executable
  source `86b81ab` passes TCP32, native UBus69/69+581 checks, independent12,
  EMFILE17, capacity31, namespace395 library+7 main/16ignored, native/musl
  Clippy. The shared product does not contain this implementation or `Clone`.
- Root owns integration, reports and source/artifact identity checks. Merged
  DO plus typed-transfer host DNS tests217 passed/5ignored, full Clippy/fmt pass.

Private reference implementation uses highest-free indexed slots, lowest-ready
single-transaction drain, UBus-before-new-drain, a pinned partial-transaction
barrier and clock, joined-worker+EOF release, STOP under admission lock and
actual kernel pipes. It avoids the incorrect one-message queue/doctor dependency
cycle. Raw FD numbers are wake hints only; actual I/O rechecks current owners.
Read `TCP_PRIVATE_REFERENCE_RESULT.md` before resuming or changing this branch.
Deep clone, whole-vector allocation/OOM, abnormal partial-EOF, exact pipe-byte
saturation, stale TCP and later CD/policy composition remain unqualified.
A documented early host-namespace unit attempt is not acceptance; final tests
ran through isolation. Do not silently promote this reference to product code.

There is no active quiet performance window. The frozen representation screen
completed48 runs/24000 operations, and chunk32 completed24/12000, all without
functional errors. Compact, shared-entry, top-level COW and chunk32 all failed
at least one unchanged resource/timing guard. No representation is accepted;
no extra rounds or relaxed thresholds were used. Results are in
`TCP_SNAPSHOT_SCREEN_RESULT.md` and `TCP_SNAPSHOT_CHUNK_RESULT.md`.

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
