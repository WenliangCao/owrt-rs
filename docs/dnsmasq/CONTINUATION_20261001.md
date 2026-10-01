# Continuation checkpoint — 2026-10-01

The same task remains active. Full functionality, zero-known-defect delivery,
paired performance/resource improvement and production acceptance are **not
complete**. Continue after each milestone; no inherited two-hour limit.
Preserve user-owned `docs/prompts/` changes. Never access or change the physical
router without a separate explicit request and verified recovery gate.

## Reference and environment

- Target: AX3000T, OpenWrt 25.12.5, dnsmasq 2.93-r1 `nodhcpv6`.
  Exact revision/archive/features: `OPENWRT_CONTRACT.md`, `REFERENCE_AUDIT.md`.
- Reference source: `private/dnsmasq-rewrite/reference/dnsmasq-2.93`.
- Authorized build host: `ssh oracle`; native exact C build:
  `/home/ubuntu/dnsmasq-rewrite-20260929/c-native-01`.
- Native C ELF SHA256:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Rust 1.98.1, remote Cargo `/home/ubuntu/.cargo/bin/cargo`. Set
  `RUSTUP_TOOLCHAIN=1.98.1` when a snapshot omits the root toolchain file.
- Network tests: `sudo -n sh tools/dnsmasq/run_isolated.sh ...`; execute
  already-built tests under sudo, not root rustup. Private configuration,
  lease files, ubus and loopback only. Never start DHCP on the host network.
- Sync without `target`/`__pycache__`; each gate gets a source identity and a
  new private output path. Preserve failures, unexecuted cases and old evidence.

## Completed integration

- `f6d3cf8`: one parent UDP cache/forward table across listeners, original
  listener retained per recipient. C shared-state gate: before 1/7, after 8/0.
- `3d01558`: synchronous lease DNS before ACK and atomic parent HUP. Actual
  C/Rust 34/34 ordered events; first restored-name query, immediate ACK lookup,
  prior forward/negative cache, A/FQDN/PTR/CNAME, TCP, release and idle expiry.
- `a5de38f`, `816b955`: DNS-disabled startup skips hosts/resolver FIFOs,
  DNS cache/forwarder/entropy and listeners. Prepare every engine before workers.
  TFTP 7/7; DHCP 72/72 with negative 71/1. Startup status classes are explicit.
- Ordinary static CLID/MAC/name/options12/15/81: config 86 matched/8 unsupported,
  service 208/0, dynamic 114/0, restored FQDN 20/20. Ordinary DHCP host files/HUP:
  20 parser reloads and 41/0 actual combined observations, negative 40/1.
  Unsupported-selector pause/recovery is a separate Rust boundary (11/0).
- Dedicated lease DNS/COW expiry/selfmx: 21 scenarios/1,238 observations/564
  replies and 10 clock cases. See `LEASE_NAMES_PHASE.md`/`DNS_LEASE_CACHE_PHASE.md`.
- `40f3943`, `846bd3f`, `75828d0`: selective publication invalidation,
  late-response local blockers and safe cached local CNAME targets. Publication
  1,876 operations; local-target gate 36 cases/269 observations/95 queries.
  Its 32 ordinary cases match; four reference-layout cases retain two differences
  and nonzero full-gate exit. Never report the complete result as zero.
- `39705d0`: a failed completion/recipient no longer discards successful
  siblings. Bounded diagnostics; no timeout SERVFAIL. C state 1,271 operations,
  UDP caller 84/84 and deliberate whole-batch-loss mutation caught.
- `0529905`, `579167d`: UDP admission/public daemon/GroupFull hooks and
  default 40-second validity. Helper 35 cases; actual service 40 datagrams/43
  observations with zero differences. Main hooks committed in `2415216`; the
  real 11-second reply/41-second late drop/42-second recovery window passed.
  C lazy FD reclamation still differs from the initial Rust proactive timeout.
- `e068336`, `9bc1f2b`, `d57a877`: ubus transport/controller/doctor
  standalone gates: C 256/256, controller 83/83, doctor 473/474 (one C lifetime
  defect retained). Not yet wired into the real main service.
- `fc13ba3`: real LeaseStore allocation/prune counters and provider snapshot:
  exact full-object C 47 cases/3,764 observations; negative 3,763/1. Restored
  zero-address leases really use prune6 even under NO_DHCP6.
- `3a4b15b`: caller-owned cache counters: 25 cases/215 snapshots, C repeated
  three times, negative 214/1. Cache layout unchanged; external counters 8 B.
  Daemon counted insertion/commit/reset integration committed in `97b637e`:
  764 observations/164 queries/382 counter snapshots all match; negative 763/1.
- Frozen `2415216` integration: host library 328 passed/6 ignored and main 6;
  Linux library 331 passed/14 ignored; actual shared state 8/8 and DHCP/DNS
  34/34. Native release ELF SHA256
  `1334f0dfbd9af3a38279a0fb69199be8193f7b5a3e710787a48fb33b37d786be`.
  Evidence is `private/dnsmasq-rewrite/integration-20261001/`. Later code does
  not inherit this whole-snapshot qualification without affected checks.
- `6162f6e`: actual stale-cache refresh gate is red: four cases, 40 ordered
  event rows plus four upstream traces, 13 differences. C works; Rust serves
  old data without refreshing. `DNS_STALE_REFRESH_PHASE.md` and private before
  trace retain the result and the initial comparison-denominator correction.

## State invariants

`ParentDns { local, daemon: Option<DnsDaemon> }` owns the shared UDP generation.
TCP takes a static hosts/cursor snapshot and share-then-COW lease snapshot at
accept. `LeasePublisher` installs names before ACK. HUP rebuilds hosts and
clears the forward cache, then reloads DHCP host files and forces publication.
Lock order: **event RwLock → DHCP provider → DNS parent**. Release the DNS mutex
before provider reload because publication reacquires it. Initial publication
finishes before workers. Socket waits stay outside the shared DNS lock.

Use `local::configured_hosts` before files and UDP `*_with_local` methods.
`LocalProvider::lease_counters()` includes restoration; do not reset it on HUP.
Cache/lease snapshots cannot substitute for all actual DNS/DHCP/TCP events.

## Active ownership and immediate work

Latest in-flight checkpoint (after the entries above):

- `ad7e2a7` commits C forwarding lifetime and `Client.reply_requested`.
  Default daemon/main use `Lifetime::ForwardTable`; explicit primitive waits
  retain `Fixed(Duration)`. Default clients request replies, background clients
  can suppress delivery while retaining common cache insertion. Source C state
  1,285 operations and 178 DNS tests passed; new service replay is being archived.
- `994e6e0` commits actual DHCP message counters: 16 scenarios/88 observations
  match on host and Linux, negative 87/1, 99 DHCP tests. Provider exposes
  `message_counters()`. Quiet-DHCP early returns follow C. Main publication is open.
- `8b98b16` commits doctor packet traversal: 36/38 C matches, two explicit safe
  length-handling differences (full gate remains nonzero), negative 35/38.
- `c371925` freezes C stale metadata: five profiles, 1,100 commands/685 queries,
  1,131 calibrations. Eight `stale=1` observations have no answer; those must
  not trigger a client-delivered stale refresh. Raw baseline is under
  `private/dnsmasq-rewrite/stale-metadata-20261001/baseline-01`.
- Root stale implementation is in an isolated worktree:
  `private/dnsmasq-rewrite/stale-work`, now based on `ad7e2a7`. It is **not yet
  merged**. Pre-rebase checkpoint object is recorded in
  `private/dnsmasq-rewrite/stale-work-checkpoint.txt`.
  `CachedAnswer { packet: Option<Vec<u8>>, stale: bool }` preserves no-answer
  metadata; main sends stale first, then calls `refresh_udp_on_listener` with
  original bytes and `reply_requested=false`. Old NX/typed priority is fixed
  in the candidate. HUP exclusion now spans reply/send/refresh.
- Stale service candidate remote: `/home/ubuntu/dns-stale-refresh-20261001`.
  `gate-01` matched the original 44 protocol/trace checks but a new kernel
  timestamp check caught its early upstream-send order: `send-order-negative-01`
  is 44 matches/4 ordering failures. Corrected send-before-refresh `gate-02`
  is **48/48**, ELF `0c133de5b76c3df1490c52507193ea61ad0705a7ac9cbabebcac837ed6b05566`.
  Subsequent metadata/no-answer/HUP guard edits still need the new 1,100-command
  C gate and final affected regressions; do not silently attach the old ELF to them.
- The oracle quiet window is **over**. EPS1 frozen 24 timed runs completed
  with no extra rounds. Relative to Rust B0 primitive CPU/operation: unexpired
  median -81.8628%, mixed -71.1418%; hot worst pair +0.6858%, no claimed tiny hot
  gain. Same heap requests/bytes/end-live, drop delta zero, Cache +8 B, Entry
  unchanged. Only retain for later service gate; default cache unchanged and
  current counted-API rebase still required. No C/service/router speed claim.

1. **Root:** finish isolated stale candidate, integrate the metadata driver,
   run precise C gate and affected main/cache/HUP checks, then merge the worktree
   changes without overwriting other owners. Main/daemon are now released.
2. **dns_policy:** deadline windows passed and failed readiness round retained.
   Working on explicit transport `Lifetime::ForwardTable` versus `Fixed`:
   daemon should keep C wall-clock/lazy frec behavior, primitive explicit
   timeouts remain fixed. This avoids fake deferred unanswered bookkeeping and
   permits clock rollback to retain C reply validity. Owns forward/upstream and
   API/default migration is committed; daemon/main released. Finish service
   replay and real forwarded/unanswered counters. DuplicateFull original-ID
   refusal is in source but its explicit C difference needs the service record.
   Upstream poll/receive error currently cancels where C retains; independent
   ICMP/retry failure gate remains necessary.
3. **lease_dns:** 43/43 admission evidence is local under
   `private/dnsmasq-rewrite/udp-admission-20261001/{freeze-01,pair-01}`.
   DuplicateFull C-only gate found a wrong stash ID/question in the refusal;
   retain as a reference defect, never normalize that ID. Now owns DHCP
   message counters are committed. Now auditing ordinary BOOTP service: source
   shows the ordinary chain is already connected despite stale documentation.
   Actual C gates will cover dynamic/static/file/DNS; potential client hostname
   and PRL differences need fixing, not a new redundant adapter.
4. **ubus_contract:** doctor and C metadata committed. Now writes the new
   `daemon_stale_tests.rs` inside root's private worktree and main-tree
   `tools/dnsmasq/stale_metadata_diff.py`; root registers the module. New type/API
   above is agreed. Full live metrics/doctor controller wiring remains open.
5. **dhcp_static:** EPS1 private-only candidate at B0 `816b955`; product cache
   unchanged. Pressure 37 scenarios/26,992 commands (C×3), legacy 22,571 and
   publication 1,876 match for B0/EPS1. Known local-CNAME differences persist
   identically. Preparing timed/allocation vectors and C calibration, no timing
   yet. Coordinate a quiet build-host interval before measurement.

## Costs, artifacts and open contracts

`C_COST_RESULT.md`: nine C-only windows, 660,000/660,000 correct completions.
CPU/completion hot 39.10–40.65 µs, mixed 47.69–48.36 µs, TCP 228.53–230.66 µs
including children. Full scans consume 11.07%/21.54% self cycles in mixed/TCP.
No paired Rust or router conclusion. EPS1 is frozen in
`CACHE_EXPIRY_SCREEN_V1.md`: one conservative bound, no extra heap/per-record
allocation, same cleanup order. Its eventual port must change the counted
insert/commit bodies; do not alter frozen workloads or acceptance thresholds.

The old product `574f5ed` inert SDK stage remains APK 520,797 B, Rust ELF
989,991 B versus target C 269,305 B: **+720,686 B / +267.6%**, still open.
DYN1 is 870,915 B (12.03% below old Rust, still +601,610 B versus C), default
recipe unchanged. Neither artifact includes later code or establishes acceptance.

Open contracts: upstream PTR, full cacheability/EDNS/stale, TCP cache
inheritance/writeback, dynamic resolver/interfaces/pktinfo/source ports;
DHCP tags/all options/hosts fallback/relay/PXE/leasequery/helper; TFTP main
IPv6/multiple listeners; actual metrics/doctor/events and UCI/procd/ujail/ACL/
hotplug/odhcpd/rpcd/LuCI lifecycle, permissions and resource pressure.

Known C differences remain explicit: SRV uninitialized type, TFTP stale DATA/
FD leak, TCP retry length/inherited OPT, cache CNAME reuse, stale ubus type IDs,
doctor receive-buffer lifetime and duplicate-capacity wrong ID. Duplicate
restored DHCP addresses are rejected by Rust. Same-bucket incidental lease
expiration under clock rollback retains a red case. Preserve correct/safe
behavior and incomplete acceptance; no answer to the prior clarification exists.
