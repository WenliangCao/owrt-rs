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

## Session recovery and ownership

The user requested continuation of session
`01a0f416-2ee3-7bf0-9920-10283e5c1cde`, including its subagents. The resumed
coordinator recovered its original requirements and local transcript. Some
original subagents continued running in a separate agent tree and modifying
the shared checkout; they are not automatically attached to this tree's
collaboration tools. Do not start competing edits in their files.

Observed original ownership at recovery:

- `dns_cache_effects`: upstream send EINTR/EAGAIN retry work in `upstream.rs`
  after the committed initial socket/send-error fallback. Its draft is not a
  completed gate. `daemon_poll_tests.rs` has a formatting-only draft.
- `dhcp_static`: TCP cache snapshots, fixed connection clock and actual parent
  transaction writeback. No product snapshot representation is accepted yet.
- `lease_dns`: completed reverse-host lease lifecycle, then auditing address
  derivation for `dhcp-host` without an explicit address.

Current coordination work (initial recovery and subsequent handoff):

- Root owns integration/report reconciliation and the target-reference tool
  changes, committed as `31d6056`. Those tool bytes match the archived target
  SDK gate identities; CLI import/help/syntax checks passed.
- `workspace_audit` owns a minimal listener-survival fix in the detached worktree
  `private/dnsmasq-rewrite/resume-fd-listener-20261001`, based on `630addb`.
  The equivalent original-agent fix `bb1a664` was retained; `cef8001` integrates shared admission. Final actual gates pass 61/61 resource failure, 17/17 TCP recovery, and 31/31 capacity.
- `evidence_recovery` independently audits the existing `405b7c1` target SDK
  stage and writes `PACKAGE_405B7C1_RESULT.md`; it does not rebuild artifacts.
- `tcp_slot_contract` owns a separate real-service C baseline for admission at
  `max-tcp-connections`. The pre-fix 23/31 gate is now 31/31; negative 30/31 exits 1. No cache implementation is delegated to this agent.

Original subagent logs ceased activity together at 16:05 local time. Their
remaining tasks have been assigned to isolated continuation worktrees so any
later original-tree edits cannot overwrite these candidates:

- `workspace_audit`: `private/dnsmasq-rewrite/resume-send-retry-20261001`, base
  `10b9d19`, with original upstream draft copied in; finish exact C transient
  send retry oracle/implementation/regressions.
- `tcp_slot_contract`: `private/dnsmasq-rewrite/resume-dhcp-hosts-20261001`, same
  base; establish ordinary hosts-derived DHCP address C baseline before a fix.

No quiet performance window is active. Keep formal snapshot timing paused
until the build host is explicitly coordinated; correctness builds/tests may
continue. This is scheduling, not a requirement for new user permission.

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
and population adds one allocation per entry. Formal CPU/tail timing has not
run; no candidate is accepted. Preserve `TCP_SNAPSHOT_SCREEN_V1.md`'s frozen
48-run schedule and thresholds. Requested heap is not RSS/exclusive memory.

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
DHCP tags/all options/hosts address fallback/relay/PXE/leasequery/helpers;
TFTP main IPv6/multiple listener/source-interface behavior; permissions, logs,
UCI/procd/ujail/ACL/hotplug/odhcpd/rpcd/LuCI and pressure/long-run recovery.
The 169 indexed capability entries are not 169 implemented capabilities.

Known C reference differences remain explicit: SRV uninitialized type, TFTP
stale DATA/FD leak, TCP retry length/inherited OPT, local CNAME object reuse,
stale UBus type IDs, doctor receive-buffer lifetime and musl failed-parse
mutation, duplicate-capacity wrong request ID. The same-bucket incidental
lease expiry under clock rollback also retains a red case. Safe behavior does
not itself resolve compatibility acceptance. Never turn unexecuted tests,
ignored tests, stage artifacts or local screens into full acceptance claims.
