# Correctness progress — 2026-10-15

Branch `perf/dnsmasq-correctness-20261015`; coordinator owns router scheduling.
No optimization product code is written here. No router connection was made.

- Freeze: `4ef4b8bc`; gate expectations remain unchanged.
- Baseline source `51b039597af13f9c9cf07c9f80e388e25cd8ae5d`, fresh musl tests:
  lib **808 passed / 0 failed / 20 ignored**; bin **81 passed / 0 failed /
  3 ignored**. Each used its own namespace and tmpfs `/tmp`, serial execution.
- Allocation integration binary and the 23 explicitly ignored cases are pending.
- Exact-image F10 original C reference recovered byte for byte. All 13 original
  case JSON hashes and the 909,279-byte full JSON hash match the existing Git
  index; canonical hash also matches the unchanged approved manifest. See
  [F10_RECOVERY.md](F10_RECOVERY.md). This removes the missing-reference blocker.
- Matching C source restored into a private copy from retained upstream sources
  plus the two matching OpenWrt patches. `forward.c`, `dnsmasq.c`, `util.c`,
  `cache.c` hashes all equal the existing source identities. Native C/UBus helper
  build completed; it is an auxiliary fixture dependency, not image authority.
- Oracle work is paused at a clean boundary for the coordinator’s timing slot.
  No correctness test/build process was running at the handoff.

Independent static reviews completed, all with no behavioral blocker identified:

| Candidate | Review scope / remaining qualification |
| --- | --- |
| `2256fcf7` DNS name validation | Expanded length, pointer hops, cursor/extra/error ordering and validation-only callers preserved; full gates pending |
| `c5b461e8` DHCP hex encoding | 191/192-byte bounds, delimiters, lowercase, partial writes and persistence error path preserved; full gates pending |
| `f489317e` TCP framing | Prefix/payload offsets, fragmented input, 100-query close and stale refresh sequencing preserved; retained answer Vec capacity can increase waiting-client memory and must be measured; full gates pending |

Coordinator device controller review found and corrected guardian PID-reuse and
case-completion coverage gaps before baseline start. The updated controller checks
PID/starttime/executable at group entry, polling and completion. Error exits before
archiving still require preservation of the attempted run and guard logs; this was
explicitly handed back. The measurement C sources were not modified in this review.

Next: finish baseline allocation/ignored tests, create canonical family asset
identity, replay all 44 families and the protocol/F10/TCP gates. Review subsequent
DNS, lease-name and hosts-index candidates before integrated eligibility.
