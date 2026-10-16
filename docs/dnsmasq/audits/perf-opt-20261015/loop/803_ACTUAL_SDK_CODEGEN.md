# Actual G/803 SDK code ranges

The already-built and downloaded exact SDK ELF/map/build triplets were
rehashed locally. Executable ranges below come from their own GNU link maps
and file-backed executable PT_LOAD bytes. This is static investigation while
owner32/A53ten run elsewhere; no remote access or new measurement occurred.

| Emitted range | G bytes | 803 bytes | Delta |
| --- | ---: | ---: | ---: |
| `answer_local_or_cached` | 3980 | 3668 | -312 |
| `answer_parsed_with_query_events` | 4508 | 3700 | -808 |
| `cached_address_is_unclaimed` | 528 | 392 | -136 |
| `answer_local_records` | 12132 | 11436 | -696 |
| `answer_fresh_address` | 1088 | 1132 | +44 |
| `answer_records_general` | 13364 | 12812 | -552 |
| `process_udp` | 4672 | 4652 | -20 |
| `wait_for_files` | 7304 | 6752 | -552 |
| `find_pseudoheader` | 1264 | 1064 | -200 |
| `query_dotted_name` | 704 | 680 | -24 |
| `names_for` | 380 | 356 | -24 |

The shared local entry shrinks808B, its ownership helper136B, and poll setup552B.
The fresh-address writer grows44B; smaller total ELF does not mean every hot
range shrinks. These ranges can contain inlined code; do not sum them as a
measured dynamic working set or infer fewer I-cache misses. Whole actual SDK
ELF shrinks98,304B (2,145,051→2,046,747). Original performance thresholds still
decide whether the compiler experiment helps. The frozen candidate and all
measurement windows remain unchanged.

[Exact artifact, code-byte and disassembly hashes](803-actual-sdk-codegen.json).
