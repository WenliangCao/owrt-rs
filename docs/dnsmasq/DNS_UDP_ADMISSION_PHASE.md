# UDP query admission and forwarding capacity

The exact native C daemon completed 43 observed events from 40 input datagrams
in an isolated Linux namespace containing only loopback. It returned 32 packets:
six NOERROR, eight NOTIMP and 18 REFUSED. Eight input datagrams were deliberately
dropped; three accepted pending/coalesced datagrams had no immediate reply and
completed later. These protocol error replies are expected outcomes, not test
failures. Positive-local-response, changed-RCODE, truncated-count, table-full
and capacity-recovery calibrations passed.

The new `dns::udp_query` helper matches all 35 applicable C wire observations
byte for byte, including malformed questions that cannot be decoded as ordinary
DNS. Four focused Rust regressions and all-target clippy with warnings denied
pass. The daemon's public UDP entry now applies this check before local lookup,
and a `GroupFull` submission returns the exact capacity reply without cancelling
existing transactions. The paired real-daemon gate passes all 43 events with the
same input/configuration as C; the pure helper alone does not establish this.

The source contract is `forward.c::receive_query`, `forward_query`,
`rfc1035.c::extract_request/setup_reply`, `domain-match.c::make_local_answer`
and `edns0.c::add_pseudoheader` in the pinned image-matching source:

| Input/boundary | Actual C behavior |
| --- | --- |
| Short header, QR, receive beyond configured EDNS maximum | Drop |
| Non-QUERY opcode with skippable questions | NOTIMP; preserve opcode/RD/CD/Z, clear AA/TC/AD, set QR/RA |
| Failed request extraction with skippable questions | REFUSED; EDE 24 when a usable OPT exists |
| Invalid pointer/bitstring/name expansion but structurally skippable question | Echo original question bytes in the error reply |
| Unskippable name or truncated question fields | Drop |
| OPT discovery | UDP discovers it before extraction failure; malformed later RRs can discard it |
| TKEY question remaining in error reply | Suppress new OPT through signed-message detection |
| Error OPT | Advertise configured maximum; clear DO/version/extended RCODE |
| Full forwarding table | REFUSED, EDE unset; an ordinary OPT becomes empty |
| OPT output capacity | Empty OPT needs 15 spare bytes; EDE 24 needs 17 |

The capacity fixture holds two distinct upstream queries, rejects unrelated
requests, coalesces a duplicate without another upstream send, then completes
an unrelated pending request. A new query succeeds immediately after the first
release. The original and coalesced recipients then receive their replies and
another new query succeeds. C's observed FD count is 11 at readiness, 12 with
the table full, and 11 after release; termination exits zero and the process is
reaped. No throughput or resource improvement is claimed.

API: call `inspect(query, configured_edns_max)` before local lookup; continue,
drop or send its reply according to `Admission`. On an established forwarding
capacity failure, `table_full(query, configured_edns_max)` constructs the error
without touching pending state. A recvmsg caller must also discard `MSG_TRUNC`.
Both helpers use the configured receive maximum, not the larger scratch-buffer
allocation. TCP keeps its existing distinct OPT-discovery ordering.

Reproduction uses `dns_udp_admission_diff.py` through `run_isolated.sh` and the
strictly identified C ELF. C/Rust runs use identical configuration contents,
the same controlled upstream port, raw client packets and capacity. The helper
comparison reuses the independently captured C trace. Upstream IDs are
normalized only in upstream semantic observations; client replies are compared
as raw bytes, including IDs, flags and records.

Raw plans, configuration, packets, logs and results are in ignored
`private/dnsmasq-rewrite/udp-admission-20261001/`: `c-baseline-01/`,
`c-baseline-02/` and `helper-diff-01/`. The native C ELF SHA-256 remains
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
This host functional evidence does not establish target ABI, router performance
or production acceptance.

The paired native Rust ELF is
`3f77c3a4d1279c7fb342fc2281fb2dcf33d3f43d3695c3d943d83d24190dee9b`.
C FD observations remain 11 → 12 → 11; Rust observes 6 → 8 → 6, and both
processes exit zero. These are functional/resource observations, not a measured
throughput improvement. Duplicate-recipient exhaustion and immediate upstream
send failure require their own exact C error-envelope observations before
being mapped to the ordinary table-full reply.
