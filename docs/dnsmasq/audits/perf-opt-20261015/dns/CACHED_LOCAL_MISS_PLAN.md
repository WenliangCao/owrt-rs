# Restrict the local bypass to an existing fresh address cache entry

Independent source `54bd1e56` is based on writer refinement `b343df11`.
Product change `11a33c95` moves the local miss check into LocalAnswerer, after
the original lease expiry and cache-name inspection. Only a single fresh,
nonnegative A/AAAA of the requested family and valid data length can reach the
additional ownership check. Ordinary absent-cache, local, multi-record and
cached-CNAME paths keep their original lookups, with a small eligibility test
where applicable. Local/cache coexistence still requires the conservative
ownership check and falls back when a local answer is possible.

The existing fresh selector's exact read-only guards are factored into a shared
`&self` method. It checks Name identity, cache owner/root/revision, entry
generation, type/data/negative status and the original valid/stale boundaries.
Only the original cache-answer mutator performs unlink/link_head after local
ownership is resolved. No LRU promotion or expiry removal happens in selection.
The helper reuses the already converted lease lookup name, or uses its own
253-byte stack buffer when that name does not exist. It does not rerun lease
expiry, create a service callback, or cache local-ownership decisions.

This responds to measured integration behavior: hit microbenchmarks improved
25–31%, but hosts/lease answer scenes regressed about14%/30%. Repeated ownership
and lease checks are a plausible mechanism, not proven CPU attribution. The
new scope intentionally gives up accelerating ordinary misses. It also enters
the original local frame before the shortcut and may lose some prior hit gain.
All15 scenes must remain in the next result; neither zero cold-path overhead
nor the previous31% hit improvement is assumed.

Tests preinstall an actually eligible fresh A/AAAA cache entry alongside hosts,
raw records, configured CNAMEs and literal/local-only rules for UDP and TCP,
checking answer owner, RDATA and query logging. Another test preserves live
lease precedence and sticky expiry through100→160→100. A direct selector check
proves it leaves LRU unchanged before local resolution. Existing converter and
576 cache/general reply controls remain. Final Mac719/8 and musl all-target
checking pass; exact related Linux gates are in progress.

A separate test-only fix `16a95086`, applied as `54bd1e56`, repairs an existing
hosts fixture's missing bucket precondition. The unchanged F code and original
retained failed executable reproduce the process-dependent failure. Matching
C source and fixed collision/noncollision controls explain it; the fix changes
only the target fixture's filler name to establish the intended different-bucket
input. Its original finite/immortal assertions remain. See the independently
committed `correctness/retained-lease-fixture-repair.json`. This is a fixture
repair, not a behavior repair or a change to frozen C expectations. The initial
failure and the unrelated initial test import error remain in private logs.

[The fixed screen](cached-local-miss-native-plan.json) reuses the original
15-scene240-window F comparison, source/probe hashes, operation counts, PMU/plain
pair counts and W/direction rules. Exact Linux gates and the unchanged SDK build
precede screening. A supported artifact may continue to the fixed32-window SDK
low/high owner diagnostic and independent ten-window A53 comparison. No source
or result from the completed integration8d/c44 rounds changes; no prior samples
are pooled. No new candidate is selected or fully qualified by this preparation.

[Thirty local allocation controls](cached-local-miss-local-allocation.json)
retain every output checksum and zero live-byte deltas. Ordinary, uppercase
and typed-config hits save two allocations/85 fixture bytes; hits with leases
save only the64-byte IDs vector, retaining the original lease-expiry conversion.
Miss, host, lease-address, raw, synthetic, RRset and configured-CNAME allocation
counts match F. Dynamic CNAME saves one23-byte terminal-name allocation;
CNAME-with-leases stays equal. Host-localise's independent process-dependent
rotation variation remains: −0.08625 reallocations and86.8 requested bytes per
operation in this pair, without a causal savings claim. All34 commands/log hashes
were rechecked. Related Linux qualification now passes938 tests on exact54bd;
SDK and runtime CPU measurements remain pending.
