# Static alias upstream service integration

The native static-alias service gate passes **97/97 observations**. This
establishes the listed static consumer scope, not full DNS feature equivalence
or target/router acceptance. No ubus subscriber callback is connected here.

Static DNS aliases belong to one admitted upstream reply. Configuration stores
the rules newest first; runtime copies the four validated fields once into
`AddressPolicy.static_aliases`. The address rewrite uses the existing doctor
primitive with no ubus callback. There is no new matching algorithm.

The shared `apply_static_aliases` boundary retains C's original full RCODE,
opcode and TC gates. UDP first evaluates `ignore-address` against the original
authenticated upstream packet, before completing its forwarding transaction.
After envelope handling and known-local NXDOMAIN conversion, the caller applies
the static doctor once, before bogus wildcard checks, rebind checks and cache
insertion. Recipient copies and cache hits must not reapply the doctor: rules
A→B and B→C must return B for the first answer, cache hit and every merged
recipient. Local answers also bypass this upstream-only stage.

`process_admitted_reply` deliberately omits a second ignore-address scan.
It also preserves the original NXDOMAIN RCODE when deciding whether to run
bogus wildcard processing, even if known-local handling changed the header to
NODATA. Repeating known-local conversion after the doctor would incorrectly
restore AA, so that conversion shares the single upstream boundary too.

| C source contract | Service coverage |
|---|---|
| `forward.c::reply_query`, pre-completion ignore-address | Original source address can suppress UDP replies; rewritten destination cannot. TCP does not apply this UDP admission predicate. |
| `forward.c::process_reply`, envelope and eligibility | UDP/TCP, client EDNS present/absent, full extended RCODE, non-QUERY opcode, TC, SERVFAIL and NXDOMAIN. |
| `forward.c::process_reply`, known-local then doctor | Local name NXDOMAIN conversion precedes static rewriting; resulting AA remains cleared when a rule matches. |
| `rfc1035.c::do_doctor` | Answer and Additional A records change, Authority does not; CNAME target addresses change; AAAA, unknown types and non-IN records remain unchanged. Rule precedence, range endpoints and unchanged-byte zero-mask matches are covered. |
| `forward.c::process_reply`, doctor before bogus/rebind/cache | Source/destination bogus checks, public/private address rewrite decisions, EDE, UDP cache miss/hit and merged recipients. |
| Local-answer paths | Static hosts answers retain their original address. |

## Evidence and reproduction

`tools/dnsmasq/dns_alias_service_diff.py` requires `run_isolated.sh`, verifies the
exact C ELF identity and runs C first for each shared configuration. It compares
reply protocol semantics and upstream query bytes/counts in event order.
Both transports use IPv4 loopback inside a fresh network namespace; AAAA data
coverage here is distinct from IPv6 transport coverage.
Forwarded random IDs are normalized only in the upstream observation; client
IDs, flags, errors, addresses, section and record order remain significant.
All record TTLs compare exactly except the five predefined cache-hit
observations, where the allowed difference is bounded by the measured window
from the priming query through the cache reply, rounded up to account for an
integer clock boundary. Raw TTLs remain recorded. OPT's TTL-shaped flags/RCODE
field always compares exactly. Comparator calibration accepts a one-tick
clock difference within that window, rejects a larger TTL difference and
rejects even a one-bit OPT change.

The frozen schedule has 97 observations. Some observations contain two merged
client replies or the deliberate UDP ignore timeout, so this count is not a
request throughput measurement. Comparator calibration checks equality, a
deliberate field mismatch and a missing observation; `--inject-error` corrupts
one decoded Rust flag without changing the saved raw reply.

Raw evidence remains under ignored
`private/dnsmasq-rewrite/dns-alias-config-20261001/`:

- `service-c-baseline-01/`: incomplete first C baseline, preserved with its
  calibrator failure. The test mistakenly treated documentation-range addresses
  as public for C's rebind policy. This was a test expectation error; the
  revised rebind cases use public address bytes inside isolated test packets.
- `service-c-baseline-02/`: 97/97 C observations, zero failures, preceding Rust
  consumer integration.
- `service-diff-01/`: 93/97 matches. All four failures were ordinary UDP EDNS
  queries immediately following a no-EDNS cache fill: C used the cache while
  Rust forwarded again. The upstream query totals were 90 versus 94; the
  section records and AAAA AA flag also differed where cached reconstruction
  differed from the upstream answer. These failures are retained; they are
  not waived as an alias-only exclusion.
- `source02/private/service-diff-02/`: 96/97 matches after allowing ordinary
  empty OPT cache lookup. The remaining case exposed erroneous caching of a
  non-QUERY upstream reply; its repeated query should still be forwarded.
- `source03/private/service-diff-03/`: **97/97 matches** after adding the
  missing cache-admission opcode gate. Both sides observe 98 client requests,
  97 replies, one expected ignore timeout and 90 upstream queries. Wire RCODE
  counts are equal: 79 NOERROR, 12 NXDOMAIN, 4 SERVFAIL and 2 extended errors.
- `source03/private/service-calibration-01/`: a deliberate decoded AA-bit
  change gives **96 matches / 1 failure**, exit 1; original replies stay intact.
- `alias-config-runtime-01/`: **72/72** configuration/CLI matches and **748**
  doctor observations; all 33 accepted alias-bearing configurations now pass
  readiness. Earlier parser-only evidence remains intact.
- `source03/private/tcp-caller-regression-03/` and
  `source03/private/udp-policy-regression-03/`: **235/235** TCP caller cases and
  **84/84** real UDP policy cases. The earlier valid source01 runs are retained.
- `source03/private/lib-isolated-regression-03.log`: 359 passed, one outdated
  poll-test expectation failed, 15 ignored. The old unit expected a clipped
  Answer to disappear; C returns SERVFAIL. The corrected poll regressions and
  the subsequent cache-prefix fix pass the source04 isolated library run:
  **361 passed / 0 failed / 15 ignored**.

The source02 network-size and partial-record policy gates are documented in
[the upstream receive-boundary report](DNS_UPSTREAM_RECEIVE_BOUNDARY_PHASE.md).
Source03 changes only cache admission, leaving those
cache-disabled observations valid. Source04 adds safe overlong-address cache
extraction and the corrected poll regression; its
[155-step frozen-time cache gate](DNS_CACHE_EDNS_PHASE.md) supplies the new
affected evidence. Ordinary 4/16-byte service records, the alias transform and
TCP policy are unchanged, so the valid source03 service evidence is reused.

Source snapshots `service-source-01` through `service-source-04` include
per-file SHA-256 manifests. The source03 release ELF used by the passing real
service gate has SHA-256
`f07d30f0aa47ab27f8c7cfb6e3dbebee08a57d5a464a8f425faeb0df68bd7bb8`.
Each run retains configurations, raw replies, ordered upstream observations,
ELF identities and failed attempts under ignored private storage. These
snapshots do not imply that unrelated later workspace changes passed a build.

On an isolated Linux build host, reproduce with fresh private output paths:

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh python3 tools/dnsmasq/dns_alias_service_diff.py \
  --c "$C_REFERENCE" --rust "$RUST_BINARY" --output private/alias-service-run
RUSTC="$PINNED_RUSTC" python3 tools/dnsmasq/cache_edns_diff.py \
  --reference-build "$REFERENCE_BUILD" --cargo "$PINNED_CARGO" --out private/cache-edns-run
```

The static aliases have no additional effect on the target's DNSSEC validation
state: this target does not build DNSSEC validation. The doctor still reports
`clear_cache_secure` for a future consumer. Synchronous ubus subscriber calls,
general TCP cache insertion, DO/AD and other EDNS cache metadata, unsupported
unsafe short-RDLEN C behavior, target
packaging and router validation remain separate acceptance work. This phase
does not claim full DNS equivalence or any performance improvement.
