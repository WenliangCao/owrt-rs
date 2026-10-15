# DHCP / hosts screening progress

Current selection: D1/D2 entered root A; clean D3d/D4 commits `5c2c985b` and
`745212bb` passed exclusive plain micro timing and entered root B. D6/D7 passed
native instruction and exclusive plain micro timing; clean selected commits
`cd9aff4b` / `de2a446f` are ready for root's complete candidate gates. No device
access or device-performance claim.

2026-10-15. Branch `perf/dnsmasq-dhcp-20261015`, base `51b03959`.
Root's freeze `d358c3a0` has been read and optimization is authorized.
Oracle workspace: `/home/ubuntu/dnsmasq-perf-20261015/dhcp`; shared
dependency caches, one build job, and no timing without root scheduling.

Ownership: `src/hosts.rs`, `src/dns/hostsdir*.rs`, DHCP store/persistence/parser
modules, and `src/dns/lease_names.rs` (agreed with DNS agent). Avoid DHCP daemon,
service, main and DNS cache/engine/local files owned by the other agents.

Read `PERF_DEVICE_20261014.md` and `PERF_RESEARCH_UDP_DHCP_RELOAD.md`. The complete
frozen device matrix and decision thresholds belong to the root agent; the
standalone probe here is a cheap mechanism screen, not a replacement benchmark.

## Existing interface and boundaries

- `LeaseStore` commits DHCP state before `LeasePersistence::update`; durability
  failure retains dirty state and never rolls back an accepted lease. Output
  order is newest lease first, with extension rows after all basic rows.
- `update_dns` publishes a complete source synchronously before sending ACK.
  Hosts precedence, old-generation TCP snapshots, reverse ownership, cache
  conflict effects and failures cannot be bypassed for unchanged lease names.
- Hosts ingestion uses fallible allocations. A replacement generation must be
  discarded on failure; published owners and TCP views must remain usable.
- DHCP receives a fresh interface snapshot for every admitted packet. This
  research does not cache interface state across packets.

## Initial hypotheses

1. Lease serialization formats each hardware/client byte through `fmt`, and
   `write_leases` allocates/sorts a newest-first list twice. Count write calls,
   allocations and instruction costs before considering a bounded stack encoder
   or reusing the first ordering inside the same call.
2. Full lease publication copies input/name/key repeatedly; lookup allocates
   lowercased names even when the caller already supplied lowercase bytes.
   Count calls/bytes using actual production APIs. Do not skip publication
   side effects or alter the public behavior.
3. Hosts loading duplicates lowercase name keys and allocates index vectors;
   test whether the cost is material before changing the fallible index design.

`count_hotpaths.rs` exercises serialization, ordering, publication, lookup and
hosts loading. Its allocator instrumentation is standalone, never linked into
the daemon. Output bytes/hashes check that encoder screens preserve bytes;
correctness acceptance still requires all frozen tests and exact-C comparisons.

## Initial deterministic counts

Apple AArch64, Rust 1.98.1, production release library (opt3/LTO), same-source
standalone probe, one operation, 2026-10-15. These are mechanism counts, not
device performance claims. Private raw: `counts-baseline-mac.json`.

| Operation | Records | Allocations | Allocated bytes | Write calls | Output bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Lease serialization | 6 | 2 | 96 | 192 | 336 |
| Lease serialization | 150 | 2 | 2400 | 4665 | 8592 |
| Newest-first ordering | 150 | 1 | 1200 | 0 | 0 |
| Lease publication | 6 | 51 | 2630 | 0 | 0 |
| Lease publication | 150 | 1079 | 84950 | 0 | 0 |
| Lowercase lease lookup | 150 | 150 | 3000 | 0 | 0 |
| Hosts ingestion | 150 | 489 | 95539 | 0 | 0 |

First screen: replace per-byte `fmt` hex encoding with bounded stack formatting,
retaining writer/error semantics and byte order. Publication and lowercase
lookup remain independent directions. Full same-ABI Oracle profiling follows.

## D1 — bounded hex serialization

Implemented a 192-byte stack encoder, independent of lease or field size. This
removes per-byte `fmt`; it retains all separators, long extension fields,
partial writes and errors. 19 lease unit tests pass, including a new check over
all byte values, chunk edges and partial-write failures.

Deterministic screen: write calls 192 → 96 for 6 leases; 4665 → 2400 for 150.
Output lengths and rolling hashes are identical (336 bytes /
18024159028762036603; 8592 bytes / 931816954775507130). Allocation counts unchanged.
Pending Oracle instruction counts; not yet a fully qualified candidate.

Oracle native AArch64 release PMU, 150 leases × 10,000 serializations, five
counter runs pinned CPU 3: instructions 4,180,126,703 → 2,222,502,690 (−46.83%);
user cycles 1,262,003,688 → 672,029,066 (−46.75%; reported counter variation
0.09% / 0.15%). Same probe, byte/hash sink, source API and compiler flags on both
sides. This is an instrumented mechanism screen, not daemon wall-time or device
performance. D1 advances to complete timing/correctness screening.

## D2 — borrow canonical lease lookup keys

`LeaseNames` lookup/expiry/existence methods now borrow already-lowercase names
and allocate only when a key contains uppercase bytes. Case-insensitive lookup
and expiry behavior are unchanged. 9 existing lease-name unit tests pass.
150 lowercase lookups: 150 allocations / 3000 bytes → 0 / 0. Coordinate with DNS
agent's `local.rs` work to avoid counting the same removed copies twice.

## D3 — remove a redundant hosts forward index

The separate `HostsRecords.forward` map was never used by answer selection,
duplicate detection, PTR ownership or rotation; all those use `HashOrder`.
Its only reader was `name_exists`. That check now traverses the authoritative
name bucket and consults the same non-terminal set. This removes one duplicate
name key and one per-name index vector, plus hash table storage and clone/remap
work. Lowercase ingestion borrows the parser-owned name for ancestor processing.

Deterministic 150-host ingestion: 489 → 182 allocations (−62.8%), requested
allocation bytes 95,539 → 62,791 (−34.3%). New 1000-host count is 1074 allocations
/ 225,239 bytes; matching extended baseline pending. Existence lookup now makes
zero allocations on lowercase input. Potential cost is scanning the existing
short bucket rather than a second HashMap; explicitly screen its instructions.

23 existing hosts tests and all 15 existing `hosts_allocations` tests pass.
One internal test read the removed map; it now reads the same records through
`addresses`, keeping the exact-C expectation (835 mixed reverse-name groups)
and all other expectations unchanged. This direction is not accepted until the
independent review and full frozen correctness gate pass.

## D4 — eliminate discarded publication keys

Publication now borrows a canonical input name while creating its single owned
forward key. Updating an already-present ancestor changes its expiry in place
instead of allocating a parent key that `HashMap::entry` immediately discards.
No publication, cache conflict, warning, TTL or reverse-owner work is skipped.
The 9 lease-name tests still pass. With 150 dotted records: allocations
1079 → 631 (−41.5%), allocated bytes 84,950 → 79,715. A separate 150 short-name
screen gives 628 allocations; its matching baseline is pending. The real frozen
DHCP workload sets a domain, so it publishes FQDN plus short names per lease;
that combination will be separately screened, not inferred from a single-name
microbenchmark.

At this stage D1/D2 are screened in; D3 was subsequently rejected below.

## D3 rejection after instruction screening

Do not integrate D3 (`83f57066`). Five-run native PMU showed hosts ingestion
instructions down 23.35% at 1000 hosts / 20.19% at 8 hosts, but presence-hit
instructions increased 83.24% and missing-name checks increased 37.39%. These
paths are uncommon in the frozen normal-address workload, but hiding that
regression would violate the research intent. The shared C-like bucket hash and
chain scan are more expensive here than the original second HashMap despite
eliminating lookup allocations. Product hosts code is restored to its D2 state.

Next D3b retains the HashMap existence index, replaces its per-name vector with
one representative record index, and borrows canonical lookup names. Source
removal may find a replacement representative in the already-remapped chain.
This seeks the reload allocation reduction without a query-path regression.

D2's independent lookup instruction screen: −22.15%; all 1.5 million lowercase
lookup allocations disappear. D1's exclusive five-pair native timing passed:
6 leases −45.97% (W 0.225%, 5/5); 150 leases −46.75% (W 0.522%, 5/5). Full raw
identities/derived measurements are in `d1-screen.json`.

## Current continuation state

- Root's first combined candidate A includes D1/D2. It owns complete correctness,
  daemon timing and all device work; this agent never connects to the router.
- D3b: product `b838a2c6`, regression `cebe0529`. One representative per indexed
  name; all 23 existing hosts tests plus 15 allocation-failure tests pass. The
  added test covers surviving same-name source and retained DHCP prefix nodes.
  At 1000 hosts, allocations 3084 → 2084 and allocation bytes 477827 → 380355.
  Native instruction screens, including hit/miss/ancestor/empty/source-removal,
  are pending. Initial independent static review found no blocker.
- D4: `0ffb74f4`. Instrumented native paired FQDN/short publication instructions
  −9.224%; allocations 1832 → 1234 for 150 leases / 300 records. Single dotted
  and short-name instructions −11.24% and −7.12%. Keep these separate from
  complete daemon measurements and repeat without allocator-counter overhead.
- D5: `9111b803`. Serialize the bounded 94-byte numeric/hardware prefix through
  a 128-byte stack slice and share one sorted lease list between basic/extension
  sections. Relative to D1, 150 leases use 750 instead of 2400 writer calls and
  one instead of two allocations. Output length/hash unchanged. 20 store tests
  pass, including maximal u64/u32/hardware/IP prefix and partial-write tests.
  Native PMU pending; do not treat it as accepted yet.

The latest probe adds empty/present/missing/ancestor and source-removal paths,
plus FQDN/short publication. `--cfg uninstrumented` omits the allocator wrapper
entirely for separate instruction/timing runs. Earlier allocator-counter PMU
results include the cost of counting; removing allocations also removes those
counter instructions. Do not interpret that part as a product speedup.

After the current native build completes, run D3b/D5 counter screens, then
compile plain probes from the cached same-source libraries for confirmation.
Request another exclusive timing slot only for directions that remain effective.
Retain every rejected variant and its raw files; no Oracle cleanup is needed.

## Later screening decisions

Plain probes omit the allocator wrapper. They confirm D2 lookup instructions
−19.50% and D4 FQDN/short publication −5.69%; the larger instrumented percentages
are not used as product-cost estimates.

D5 is rejected and its entire product change is reverted to D1. Plain
serialization instructions increased 26.81% at 150 leases and 22.39% at 6,
despite fewer writer calls. Extra formatting into a slice, zeroing and copying
cost more than the saved calls. Isolated newest-first ordering costs 5224.9
instructions versus D1's 237937.6 per 150-lease serialization: eliminating one
ordering has an upper bound of 2.20% of this component, and a smaller fraction
of full DHCP processing. It does not justify a separate candidate by itself.

D3b's plain source-removal screen regressed 9.15% (clone plus removal with
same-name entries in two sources), so it remains unaccepted. A linear live-name
repair version, `bd5eeec8`, passed 24 unit and 16 allocation tests but would hash
all surviving names even when only one representative is removed. It is
superseded before timing by the simpler D3d count index: the HashMap stores the
number of live static records for each name. Removal decrements only removed
names, then drops zero counts; no representative repair, secondary chain or
per-name index vector remains. Uppercase normalization uses one fallibly
reserved scratch buffer before any published state mutation. This also passed
24 hosts tests and all 16 allocation-failure tests. Plain PMU is next.

## D3d / D4 exclusive plain timing result

Root reserved Oracle CPU 3; every competing research task paused. Five
alternating pairs, plain System allocator (no counter wrapper):

| Component | Relative median | Max relative range W | Direction |
| --- | ---: | ---: | --- |
| 8-host load | −4.40% | 2.43% | 5/5 faster |
| 1000-host load | −9.50% | 1.95% | 5/5 faster |
| Clone + cross-source removal | +0.42% | 1.81% | 3/5 slower; within variation |
| 150 leases, FQDN + short publication | −6.36% | 0.655% | 5/5 faster |

D3d and D4 advance to root's whole-daemon/correctness gate, not directly to the
device. Clean selected branch `perf/dnsmasq-dhcp-b-20261015` starts from actual A
`a7164697`: `5c2c985b` is D3d plus new tests; `745212bb` is D4 alone. Original
experiment commits remain preserved on this research branch. See
`d3d-d4-screen.json` for artifact identities, full ranges and raw SHA256.

Next small experiment D6 stores a single DHCP forward record ID inline, using a
Vec only for actual multi-record names. It avoids 300 allocations in a 150-lease
FQDN+short publication: 1234 → 934, requested bytes 145499 → 135899. Ten
lease-name unit tests pass. The new mixed-order test's first draft incorrectly
ordered finite before immortal reverse records; its failed pre-change test log
is retained, the expectation was corrected to the existing implementation
before D6 was applied, and no frozen test/C result was changed. D6 still needs
plain PMU, including singleton/multiple-name lookup and duplicate publication.

## D6 plain screen and D7 ownership prototype

D6 plain PMU versus D4: paired publication −11.08%; triples +0.11%; one repeated
name −1.89%. Lookup instructions increase 1.03% / 0.79% / 0.12% for singleton,
triples and repeated-name shapes. Field size remains 24 bytes, the original Vec
size. No query-path tradeoff is hidden; exclusive timing is queued before any
selection. All ten lease-name unit tests pass.

D7 replaces only the already-infallible DHCP name ownership allocations:
`LeaseNames::build/add/rebuild` previously use `to_vec`, `collect` and HashMap
insert, with no TryReserveError return boundary. A single immutable `Arc<[u8]>`
now backs an input, its answer entry and its lowercase key when bytes are
identical. Mixed case retains a separate canonical key. No new allocation is
inserted in any hosts fallible copy/replacement closure.

Type-only consumers adapted: main retained-lease iterator (`as_ref` borrow),
the same iterator in `hosts_allocations`, construction in the lease-cache unit
probe and `tools/dnsmasq/lease_names_probe`, and a unit assertion's actual-value
borrow. Existing C input/output lines and expected bytes are unchanged. Initial
compiler errors identified these consumers and are retained in private logs.
11 lease-name tests and all 16 allocation-failure tests pass; full local library
tests are running. A new mixed-case test checks original input/forward/PTR
spelling before and after rebuild. No unsafe allocator or custom Arc is used.

The paired publication allocation screen is 934 → 334 allocations and
135899 → 114179 requested bytes relative to D6. D7 still requires plain PMU,
timing, complete Linux/C gates and actual A53 timing: Oracle LSE atomics cannot
stand in for the router's LL/SC cost.

## D6/D7 complete owner-publication screening

The new `publication-owner` probe includes `update_dns` ordering and record-vector
construction, actual Hosts/Cache publication preparation, outer Arc replacement,
and release of the previous generation. A nonempty hosts source prevents an
empty-source shortcut. Both sides run the same probe, Rust 1.98.1 release
libraries and plain System allocator; compiler/source/binary/raw identities are
recorded in `d6-d7-screen.json`. An initial attempt using default Rust 1.98.0
failed the package version check before compilation and is retained; all
reported probes explicitly use Rust 1.98.1.

Five-run native instruction screens:

| Comparison | Owner, 6 leases | Owner, 150 leases |
| --- | ---: | ---: |
| D6 versus D3d/D4 | −6.27% | −8.59% |
| D7 versus D6 | −11.82% | −17.61% |

D7 also reduces bare paired publication instructions 20.13%, mixed-case 7.09%,
three-record names 12.96%, and 150 records at one name 8.95%. Lookup instructions
change +0.138%, +0.135%, and +0.007% for singleton, triple and repeated-name
shapes. No allocator-wrapper cost is included in those figures.

Root granted exclusive reservation `micro-dhcp-20261015-1025`; all other remote
research work paused. Five alternating pairs on CPU 3 compare D3d/D4 with D6+D7:

| Component | Median change | Maximum relative range W | Faster pairs |
| --- | ---: | ---: | ---: |
| Owner publication, 6 leases | −15.15% | 1.21% | 5/5 |
| Owner publication, 150 leases | −18.20% | 7.19% | 5/5 |
| Triple-name publication, 150 records | −6.02% | 0.46% | 5/5 |
| Singleton-name lookup, 150 records | −1.29% | 0.68% | 5/5 |
| Triple-name lookup, 150 records | +0.256% | 12.60% | 1/5 |

The wide 150-owner and triple-lookup windows are retained without replacement.
Both owner publication gains exceed W; the triple-lookup difference is within
variation. These are component screens, not whole-daemon or device acceptance.
Independent static review found no semantic blocker: ordering, retained hidden
inputs, mixed-case PTR spelling and fallible hosts allocation boundaries remain
intact. Local library tests: 698 passed, eight existing ignored; all 16 hosts
allocation tests pass. Frozen Linux/C/ELF gates remain mandatory.

Clean selected branch `perf/dnsmasq-dhcp-c-20261015`, based on root `95403890`:
`cd9aff4b` combines the D6 index and its final multi-record growth refinement;
`de2a446f` contains D7 plus the five necessary product/test/probe adaptations.
Research commits and every rejected variant remain preserved separately.

## Residual cost and next small screen

A 150-lease native instruction profile after D7 reports no lost samples.
`Hosts::addresses` and `Hosts::lookup` account for 9.41% and 9.15% respectively;
both hash the same publication name. `Cache::names_for` contributes 7.85% and
has been handed to the DNS owner. Forward/reverse HashMap growth is 6.11% and
Arc atomic helpers 4.39%; `update_dns` itself is 0.70%. Inlined generation work
is charged to the probe publisher, so those samples are not a full attribution
of generation operations.

The simplest remaining hosts direction is sharing only a name-bucket calculation
within a synchronous publication call. Any experiment must keep the all-family
blocker scan before the existing IPv4-only round-robin side effect, retain the
same fallible answer allocation, and avoid a long-lived stale bucket hint.
Replacing Arc with Rc is incompatible with shared TCP reader ownership; an
arena or custom reference-counted name would enlarge the ownership API and is
not warranted before actual A53/whole-daemon evidence. This profile does not
justify skipping publication, cache conflict processing or persistence fsync.
