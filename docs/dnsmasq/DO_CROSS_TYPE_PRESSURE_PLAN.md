# Frozen NXDOMAIN and generic-record lookup pressure gate

This independent second unit retains the completed 120-observation
[direct/CNAME gate](DO_LOOKUP_PRESSURE_RESULT.md) unchanged.

The exact C `answer_request` looks up CNAME/NXDOMAIN before address lookup,
then looks up all `F_RR|F_NXDOMAIN` records if no answer was produced (line
2283), before matching the requested RR type or rejecting DO (line 2295).
Ordinary NXDOMAIN insertion clears address and `F_RR` flags (line 1149).
A same-name TXT cache record can therefore gain LRU priority from a DO or plain
A/AAAA query even though it cannot answer that query. The plain cross-type
case may be an independent existing Rust difference; do not conflate it with
the initial DO fix or infer expected results from Rust.

## Frozen schedule

Twelve fresh-daemon profiles cross A/AAAA touch type, NXDOMAIN/TXT seed and
untouched/plain/DO touch. Capacity is 3; no round-robin; `cache-rr=TXT` enables
TXT storage explicitly; `neg-ttl=120` gives SOA-free NXDOMAIN one cache slot.

1. Seed owner as SOA-free NXDOMAIN for the chosen address qtype, or as one TXT
   RR by querying TXT. Seed sentinel B and sentinel C as addresses, in order.
2. Touch owner with the chosen A/AAAA qtype and plain/DO flags. Untouched
   control queries an unrelated missing name.
3. Insert sentinel D as the chosen address qtype.
4. Probe B, owner, C, D. Owner probe uses its seed qtype (TXT for a TXT seed).

All forwarded touches/probes receive SERVFAIL; C's two-send default retry is
part of the oracle. NXDOMAIN plain touch is cached; TXT plain touch still
forwards. DO always forwards. The source-derived victim is owner for untouched
and B for both plain/DO touch. Probes do not insert records. Each profile
therefore performs 9 observations, exactly 4 committed records and one live
eviction. Total: 108 observations.

Complete native C and verified image-C calibration precede any Rust comparison.
All 30 UBus fields, decoded reply data/flags/order/TTLs and upstream sequence
are compared; transaction-ID and at most one-second cached-TTL normalization
match the initial gate. Missing rows and a single altered observation must be
rejected. All attempts and raw evidence remain in ignored private paths. All
network experiments run in `run_isolated.sh` on the build host; no router.

This unit covers NX and a single cross-type TXT record under pressure. It does
not establish mixed generic-RR ordering, stale or hash-bucket purge behavior.
