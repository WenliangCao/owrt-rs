# Reverse cache and real lease-service before result

The corrected frozen [six-profile service gate](REVERSE_LEASE_SERVICE_PLAN.md)
calibrates **62/62 ordered observations against native C** and **62/62 against
the actual image**. The saved native/image observations also compare 62/62
without another daemon run. Each C variant passes 113 auxiliary DHCP checks
and 266 fixture/UBus/cleanup checks; these are separate from the 62 observations.

The unchanged Rust source `62894d6` completes five profiles: **54 compared,
40 match and 14 differ**. The sixth profile is rejected at startup because
`dhcp-fqdn` is parsed but explicitly unwired; its eight events never execute.
There is no 62-row Rust pass or after implementation in this report.

| Profile | Native C | Image C | Rust observed / differences |
| --- | --- | --- | --- |
| Dynamic PTR before lease publication | 13/13 | 13/13 | 13 / 8 |
| Expired PTR before publication, time-zero ownership | 8/8 | 8/8 | 8 / 4 |
| Held upstream reply, lease publication, late coexistence | 11/11 | 11/11 | 11 / 1 |
| Static host priority and release/HUP | 10/10 | 10/10 | 10 / 0 |
| Explicit PTR priority and active-lease HUP | 12/12 | 12/12 | 12 / 1 |
| FQDN-only publication | 8/8 | 8/8 | 0 / startup rejection; 8 unexecuted |
| **Total** | **62/62** | **62/62** | **54 compared / 14 differences; 1 rejected profile** |

These are real daemon observations: 36 ordinary DNS exchanges, one held DNS
request and its delivered reply, 21 DHCP events and three completed HUPs. There
are 37 DNS replies; OFFER/ACK/RELEASE and HUP are not counted as DNS packets.
Two fixed functional TTL waits are excluded from that count and are not
performance measurements. Real private lease files, DHCP replies, DNS packets,
upstream events and all UBus metrics are retained.

## Measured caller behavior and current gaps

When a dynamic positive PTR already owns an address, actual DHCP ACK publication
creates the lease's forward names but does not take reverse ownership. After
the dynamic entry expires, the existing lease publication still does not gain
PTR automatically. A second real lease ACK forces a new generation, after the
expired entry was removed by lookup, and the first lease then acquires reverse
ownership. The same first-owner suppression occurs when the dynamic PTR has
already expired before ACK but remains indexed: C publication deliberately
looks up the address at time zero. This effect is established through real DHCP,
not a direct cache_add_dhcp_entry command or hand-created blocker.

The Rust before candidate gives the first lease reverse ownership immediately.
Its PTR therefore returns the local FQDN instead of the dynamic target, and
still returns that FQDN where C forwards after expiry. These produce two primary
answer differences in the first profile and one in the second, followed by
counter differences carried into later events: eight and four differing rows
respectively. The source's `PublicationCache::reverse_owned` still explicitly
returns false, matching the observed missing contract.

The late-response scenario is concretely reachable. A client sends PTR and its
actual upstream request is held. Real DHCP then allocates/names/persists the
lease and returns ACK. A separate PTR query sees only the local FQDN. Releasing
the held reply caches the dynamic PTR; the next C query returns **local FQDN
first, then dynamic target**, with separate TTLs and AA cleared by the dynamic
record. Rust returns only the local FQDN and retains AA. That is one differing
row; subsequent release preserves the dynamic record, and HUP clears it as C
does. The gate goes through main's real UDP local/cache ordering and cannot
hide this difference by testing answer_records alone.

The static-host group matches all ten Rust observations. An authoritative
configured DHCP client name prevents this profile from accidentally testing
static-host hostname fallback instead of reverse priority. Both forward lease
names are published; the static reverse owner survives lease release and
changes after the real hosts reload.

An explicit ptr-record at the full reverse name outranks an address-cache hit.
A different decimal spelling reaches the same address but has no matching
explicit record. With the lease active, C retains the dynamic owner for that
alternate spelling while Rust incorrectly selects the lease: one differing
row. HUP while the lease is active clears the dynamic cache and forces a new
publication, so both then select the lease FQDN for the alternate spelling.
After RELEASE, the explicit full-owner PTR remains and the alternate spelling
misses. These actual HUP/release/forward-name observations otherwise match.

The FQDN-only group completes in both C variants: the FQDN and PTR are local,
the short name forwards, and release removes FQDN/PTR. Rust emits the explicit
configuration error before its UBus object or either tested service appears.
All raw startup logs and cleanup checks are retained; those eight unexecuted
observations are never converted into ordinary comparison passes or differences.

## Observer correction and retained failed calibration

The initial plan had 61 observations and was never executed. Before the first
execution, active-lease HUP/republication coverage was added to the explicit-PTR
profile, yielding the final 62-event schedule.

`lease-native-baseline-01` and `lease-image-baseline-01` each complete every
one of those 62 events without DHCP/process failure. Both fail one observer
predicate and therefore report only 54 calibrated observations: fqdn-only's
short-name query is the process's first forwarded request, so its SERVFAIL
sends once rather than the initially assumed twice. Later failed probes send
twice. Source `forward.c:429` sets forwardall when last_server is -1;
`forward.c:1255` retries SERVFAIL only when forwardall is zero.

Commit `1da969c` corrects only that explicit row's send-count predicate. Packets,
configuration, event order and denominator do not change. Both original runs
and their original tool SHA remain preserved. New `lease-native-baseline-02`
and `lease-image-baseline-02` then calibrate 62/62. No Rust execution preceded
this correction, and no expected answer was derived from Rust.

## Small implementation boundaries supported by this evidence

1. Implement the existing publication ownership callback through the real
   time-zero reverse lookup. Preserve its lookup effects and the already
   established local-host/earlier-lease checks. Expiry alone must not rewrite
   an existing lease's reverse flag; a publication is the ownership decision.
2. Integrate local and dynamic address-PTR selection in the real query path,
   preserving configured PTR/static/interface precedence, one lookup's expiry
   and LRU effects, local-first record order and resulting flags. Fixing only
   the lower-level cache answer API would leave main's observed early local
   return unchanged. Do not append dynamic records to explicit ptr-record
   responses, which this gate independently shows should win outright.
3. Wire dhcp-fqdn through its actual parser and all runtime consumers. In
   source `62894d6`, `dhcp/daemon.rs` hardcodes false in persistence::update_dns,
   configured/restored-name updates and the live request context. The matching
   C parser (`option.c:6306`) also requires a default domain. Removing only the
   option rejection would not implement these separate caller requirements.

These are recommendations from measured before results plus exact source;
this tool/report unit does not change candidate code. Multi-target dynamic PTR
ordering, synthetic negative reverse records, IPv6 DHCP, incremental hostsdir,
lease-file failures, scripts, transfer and resource/production acceptance remain
outside this stage.

## Identities and preservation

- Initial plan commit: `9128a23`; final pre-execution tool/62-event plan:
  `a750d14`; observer correction: `1da969c`.
- Original tool SHA-256:
  `055e4a231170d4c44d7c1d41736fdfd06e84348578bd6767cf615ae2d672a1fb`.
- Corrected tool SHA-256:
  `76e97c4dedc1026411e80ef985764050d8f0808c20f10588a5582530251146ee`.
- Rust before source: `62894d657341827f3ea1e903375a6263dbe4de82`.
- Rust native daemon ELF SHA-256:
  `601550b04418152ba5a865343ee3e44d93c64b610f29440577c1e294a547726e`.
- Rust source archive SHA-256:
  `d20889ad0c6ccfbecc5737bfb533e3b5691730e571f4c379ccb102c0a0a38134`.
- Native C ELF:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Actual image C ELF:
  `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`;
  its runner, musl loader and library identities are checked before each run.

All six C profiles detect one altered DNS result and reject missing rows in
saved-row comparator calibration. A standalone paired negative awaits a fully
passing Rust candidate. Comparison retains flags, order, original-case PTR
names, address/lease identity, counters, local/DHCP TTLs and actual durable-file
state. Only dynamic cached PTR TTL may differ by one second; absolute lease
expiry is checked against its ACK before representing the shared 600s relation.

The five complete attempts, including both failed initial calibrations and the
Rust startup rejection, are retained under ignored
`private/dnsmasq-rewrite/reverse-cache-gate-20261001/private/`, mirrored from
`/home/ubuntu/dns-reverse-cache-20261001/work01/private/`.
`lease-before-evidence-sha256.json` covers 703 files; the saved C cross-comparison
is `lease-native-image-comparison.json`. The earlier Stage 1/2 gates keep their
own identities and are not relabelled by this stage. All executions are isolated;
no router or performance window is involved.
