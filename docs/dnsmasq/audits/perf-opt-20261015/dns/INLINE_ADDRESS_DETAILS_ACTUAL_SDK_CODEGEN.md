# Actual bare1df SDK data-flow check

Already-downloaded immutable G and1df ELF/map/build identities were rehashed
locally. This examines their own executable PT_LOAD bytes and GNU input ranges;
no remote access, build or measurement occurred. The comparison includes1df's
inherited6ab changes and is not an isolated inline-address performance result.

The actual SDK matches the previously inspected mechanism. The fresh writer
uses positive address tags3/4; name inspection at0xe7d04 compares against2 and
branches at0xe7d08 before loading Record at0xe7d0c and kind at0xe7d10. Valid
positive A/AAAA entries therefore skip those dependent reads; Other still uses
them. The content-block/slot reads remain. This establishes emitted data flow,
not A53 cache misses, sample attribution or the cost saved.

| Emitted range | G bytes | 1df bytes |
| --- | ---: | ---: |
| `answer_local_or_cached` | 3980 | 3808 |
| `answer_parsed_with_query_events` | 4508 | 3584 |
| `cached_address_is_unclaimed` | 528 | 528 |
| `answer_local_records` | 12132 | 11968 |
| `answer_fresh_address` | 1088 | 1148 |
| `answer_records_general` | 13364 | 13380 |
| `process_udp` | 4672 | 4660 |
| `wait_for_files` | 7304 | 7192 |
| `find_pseudoheader` | 1264 | 1264 |
| `query_dotted_name` | 704 | 704 |
| `names_for` | 380 | 380 |
| `single_fresh_address_id_with_hint` | inlined/not emitted | 384 |

Both entire SDK ELFs are2,145,051B. The local entry shrinks, while eligibility
is now a384B outlined function and the fresh writer/general record path grow.
Retain these tradeoffs; original native/owner/device windows decide performance.

[Exact artifact/code hashes and selected instructions](inline-address-details-actual-sdk-codegen.json).
