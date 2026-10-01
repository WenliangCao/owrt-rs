# TCP cache transaction source baseline

The unchanged C cache implementation completes **36 cases / 307 observations**
under both the audited native reference and a matching-source SDK-musl oracle.
Every case runs three times per runtime: **216 processes / 1,842 observations**,
with identical repeated and cross-runtime outputs. This establishes the narrow
transfer primitive baseline before Rust changes; it is not a Rust or stock-image
daemon pass. The real-service 32-observation baseline remains separate in
[DNS_TCP_CACHE_PHASE.md](DNS_TCP_CACHE_PHASE.md).

`cache_transfer_driver.c` includes the exact `cache.c`, forks a real child,
lets it call `cache_end_insert` against a real pipe, and calls the unchanged
`cache_recv_insert` in the parent. Parent-side mutations between fork and import
exercise genuinely different child/parent state. The fixture observes local and
parent lookups and actual insertion/eviction counters. A six-row C calibration
is anchored explicitly; altering its insertion counter produces one detected
difference. Every run's observation count and exit status are checked.

The source identity SHA256 is
`62cec0e9dda0265cb9c4f6af27f7d23067aed967afab3c74e37370149a8326e9`;
`cache.c` is
`51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c`.
The source/version/COPTS match the image recipe. The native fixture links the
audited native objects, with only `main` renamed and `cache.o` replaced by the
driver's unchanged inclusion. Recovered non-main object identities match the
earlier independent native audit.

The target fixture recompiles the same 42 source inputs using the pinned SDK
GCC 14.3.0 and exact feature flags. Per-function/data sections and linker GC
remove unreachable reference code, including UBus. The executable is run with
the image's verified musl loader and image `libgcc_s`; both loaded-library hashes
are recorded. This is a **matching-source target-runtime oracle**, not the
image's existing dnsmasq ELF. GCC flags, all object identities and dependency
resolution are retained. The build retains 262 warning/loader lines.

| Boundary | Observed C behavior |
| --- | --- |
| Successful commit | Transfer committed records in reverse pending order; even a successful empty commit sends a transaction. |
| Child abort/failure | Send nothing. Earlier child removals remain private; parent contents/counters stay unchanged. |
| Parent import | Start one transaction, preserve each immediate removal/eviction even if a later record fails, then attempt one commit. |
| TTL clamps | Clamp only during child insertion. Import ages the absolute deadline using parent time and bypasses a second min/max clamp. |
| Zero remaining TTL | Abort import when stale caching is disabled; accept at parent time when stale caching is enabled. |
| Already-past deadline | Both tested compilers/runtimes convert the negative remaining difference to zero. Disabled stale aborts; enabled stale stores expiry equal to parent time. |
| CNAME | Relink to the immediately preceding received insertion result. No child pointer/slot identity crosses the boundary. |
| Multi-address answer | Reversal happens at export and again at parent commit; parent/child lookup orders can differ. |
| Current parent local name | Equal address can supply a local CNAME target without dynamic insertion; a conflicting address aborts import. |
| Child-local CNAME target | The local target is not transferred. An alias received without a preceding target is dropped, even if the parent has that local name. |
| Negative/SOA | Negative authority association and separate opaque SOA-block bytes survive transfer in the source-defined order. |
| Resource failure after eviction | A long-name allocation-quota failure retains the preceding live eviction while inserting no new parent record. |

The past-deadline observation involves C's floating-to-unsigned conversion of an
out-of-range value. Its observed result is compiler/platform dependent; this
source probe does not establish the existing image ELF's behavior for that
case. Ordinary positive deadlines and zero are kept separate from it. SOA tests
exercise opaque block transfer and authority association, not SOA wire parsing.

Two preparation failures remain alongside the final run. `baseline-01` omitted
the recipe's `VERSION` define when compiling the full target sources.
`baseline-02` linked against sectionless image DSOs, which GNU ld rejected;
trying GC before compiling separate function sections also failed. Neither
attempt ran the corpus. `baseline-03` contains the completed schedule and
recovered artifacts, under ignored
`private/dnsmasq-rewrite/tcp-transfer-20261001/`. The companion
[sanitized JSON](TCP_CACHE_TRANSFER_BASELINE.json) pins identities and counts.

The next prerequisite is opt-in, owned transaction capture and parent import.
It must distinguish a successful empty transaction from no commit, keep
uncaptured UDP commits free of journal allocations, and count only real parent
effects. An owned vector adds allocation/failure boundaries that need explicit
accounting. No production sender, pipe-backpressure or memory-pressure
equivalence is established by this baseline. Snapshot representation, fixed
connection clock, slot drain lifetime and full TCP service acceptance remain
open. No physical router was accessed.
