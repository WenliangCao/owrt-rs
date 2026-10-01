# Frozen cache-rr and generic forward-cache gate

The interface is `cache-rr=<RR-type>[,...]`, repeatable. In the exact patched
C source, `option.c:3575` parses decimal or case-insensitive `typestr` names,
then stores an unsigned-short list node. Defined in-range `int` values wrap
when assigned to that field; list value zero never matches. `ANY` (255)
enables storage for otherwise unsupported query types. This does not make a
QTYPE=ANY response cache its component answers. CNAME queries are explicitly
excluded from positive insertion.

`rfc1035.c:879` enables generic storage for SRV and PTR by default. At line 974,
`rrfilter_desc` identifies embedded names, which are decompressed and converted
to lower-case standalone wire names. Unknown RR types retain opaque bytes,
including bytes which resemble a compression pointer. Small opaque RDATA uses
C's immediate representation; this gate compares behavior, not its layout.
CD/no-cache still runs ordered extraction and gates only final commit.

PTR replies for literal reverse IPv4/IPv6 owners take a distinct `F_REVERSE`
address-index path (`rfc1035.c:803`), while an alias to PTR may take the generic
path. Reverse PTR is a separate C-only group below and is never claimed
implemented by mapping it to Generic(12). The established SRV NODATA without
SOA undefined-read evidence remains outside paired acceptance; no arbitrary
reference bytes will be imitated.

## Configuration group: 22 syntax-only cases

Run complete C `--test` results before Rust. Accepted expectations:
`TXT`, `txt`, `16`, `65280`, `ANY`, `255`, comma/repeated lines, duplicates,
`0`, `65536` (wraps to zero), `65552` (wraps to TXT), `65535`, `2147483647`
(defined int value), empty value, trailing empty comma item and leading empty
comma item. Rejected expectations: unknown name, `TYPE16`, `-1`, `+16`, `1.6`
and `0x10`. Record stdout/stderr/exit, compare acceptance status; executable
names, usage diagnostics and accepted-command text are not a byte contract.
Numeric overflow beyond signed-int range remains unqualified.

## Forward group: 78 packet observations

Twenty three-step positive/negative schedules perform seed and two replays:

1. TXT and unknown 65280 without enabling them: each query forwards, no insert.
2. TXT enabled with small and large (> immediate storage) payloads.
3. Numeric unknown 65280 with opaque data containing pointer-looking bytes.
4. Numeric 65552 enabling TXT through unsigned-short conversion.
5. ANY enabling TXT and unknown 65281, in distinct profiles.
6. Comma/repeated options enabling compressed MX data.
7. Default positive SRV and non-address PTR, with compressed RDATA names.
8. Explicit SOA with two compressed names and trailing integer fields.
9. TXT-only configuration with an MX question: forwards without caching.
10. ANY configuration with QTYPE=CNAME and QTYPE=ANY, separately: neither
    positive answer is cached.
11. Three-record TXT RRset with round-robin enabled: ordering is compared.
12. CNAME-to-TXT chain: alias and generic target commit and replay together.
13. TXT NODATA and default SRV NODATA with a valid SOA, separately.
14. Unenabled TXT NXDOMAIN with `neg-ttl=120`: C caches the name-wide negative
    even though its positive TXT path is disabled.

All other profiles use no-round-robin. Empty version-zero OPT is used, with
no DO/AD expansion in this unit. Seed RDATA TTL is 120 seconds (alias 90).
Profiles which commit use exact source-derived insertion deltas: one direct
record, three TXT records, two alias/target records, two SOA+negative records,
or one SOA-free NXDOMAIN. Replays add no insertion; disabled/CNAME/ANY seeds
and replays add none and always forward.

Three six-step CD schedules seed owner TXT and a sentinel TXT into capacity 3,
then query a new alias whose CNAME points to that owner and whose TXT answer
would replace the old value. Normal control commits alias/new target and
retains sentinel. Request-CD and raw-reply-CD run extraction, remove the old
owner, suppress commit, and retain sentinel. Probe owner, alias, sentinel in
that order. Forwarded probes return SERVFAIL with the existing two-send retry
and never insert. Request CD and raw reply CD are separate flags; replies must
restore the client's CD. Exact full metrics and packet sequences, including
intermediate counts, are compared.

## Separate reverse-PTR reference group: 9 C-only observations

Three seed/two-replay profiles cover IPv4 reverse owner, IPv6 reverse owner and
reverse-owner CNAME-to-generic-PTR. Record the actual C cache-hit behavior,
record order, TTLs and all metrics. The direct profiles should insert one
reverse record; the alias profile should insert alias plus generic PTR target.
This group runs against native/image C only and is explicitly excluded from
Rust paired counts. Its existence is not a Rust acceptance claim.

## Procedure and boundaries

Freeze tooling before execution. Complete and calibrate all native C groups,
then verified image C groups, before starting old Rust. Each paired run itself
also runs its entire C schedule before Rust. C supplies expected decoded DNS
answers. Preserve name/RDATA semantics, flags, TTL, record order, query identity,
upstream count/order and all 30 UBus fields; decode known embedded names so
valid compression choices can differ. Normalize only upstream transaction IDs
and at most one second of cached TTL phase. Keep unknown RDATA opaque.

Reject missing rows and detect one deliberately changed decoded observation.
Standalone paired negative control requires a fully passing frozen Rust ELF.
All configurations, packets, executable identities, logs and failed attempts
stay under ignored `private/`. All executions use `run_isolated.sh` on the
build host. No physical router, performance round, deployment or flash.

The gate does not qualify reverse cache integration, malformed generic RDATA,
DNSSEC, arbitrary EDNS metadata, int-overflow parsing, complete RRtype parser
coverage, or the retained SRV no-SOA C defect. Each unsupported or failed group
must remain visible; no aggregate all-pass label may hide it.
