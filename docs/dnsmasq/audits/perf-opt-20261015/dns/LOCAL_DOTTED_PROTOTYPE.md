# Query-local dotted-name prototype

`c627927d` is an independent prototype based on frozen F source `3a3d8e3e`. It has not been added to F. All work in this report is local to the Mac: library tests, allocation counters and binary inspection. No CPU timing or Oracle workload ran.

`LocalAnswerer::answer_parsed_with_query_events` currently obtains a lower-case dotted byte name for local and lease lookup. That representation differs from `Name::dnsmasq_bytes`: a literal dot inside a wire label is rejected, other binary bytes are retained, and the maximum output is 253 bytes. The existing owned `wire_to_dotted` API has other callers in forward rules, query policy, domain-existence checks and CNAME traversal; this prototype leaves it unchanged.

The private query helper writes to a checked 253-byte local buffer and returns its initialized length. When leases are present, conversion still precedes the existing expiry traversal and the original query is retained for the later lookup. Without leases, conversion remains after the cached-CNAME short circuit. The lease expiry loop receives a borrowed slice; the 100-hop bound, TYPE_CNAME stop, sticky removal and PTR/ANY reverse expiry conditions are unchanged. Hosts/cache data structures, key hashing, lookup-return types and configuration state are unchanged.

## Local validation

The Mac library suite passed 715 tests with 8 ignored. The new 515-case codec comparison covers every binary byte at label lengths 1 and 63, mixed case, root, literal-dot rejection and the maximum 253-byte dotted name. A reused nonzero buffer verifies that unused bytes cannot become part of the result. Existing expiry, CNAME, raw-record and local-answer tests still pass.

The unchanged ten-scene public-answer probe completed 8,000 operations per side/scene, with matching answer-length checksums and zero final live requested bytes. These are allocation counts, not performance measurements.

| Scene | F allocations/query | Prototype | F requested bytes/query | Prototype |
|---|---:|---:|---:|---:|
| hit | 4 | 3 | 245 | 224 |
| hit-upper | 5 | 4 | 268 | 247 |
| hit-leases | 4 | 3 | 245 | 224 |
| miss | 2 | 1 | 53 | 32 |
| miss-leases | 2 | 1 | 53 | 32 |
| host | 8 | 7 | 499.6 | 478.6 |
| rrset | 5 | 4 | 846.6 | 825.6 |
| cname | 10 | 9 | 544 | 521 |
| cname-leases | 11 | 9 | 565 | 521 |
| cname-config | 18 | 18 | 1013.6 | 1013.6 |

The cached-CNAME paths can invoke local answering at the alias and terminal; they therefore remove a different number/size of conversions than a simple hit. Configured-CNAME traversal still uses its existing owned cursor and shows no allocation change.

## Concrete cost to check later

The uninstrumented Mac arm64 `answer_parsed_with_query_events` prologue reserves 896 bytes in F and 1,136 bytes in the prototype: +240 bytes. The callee-save register groups match, but this does not prove equal dynamic spills. Explicit vector stores still initialize the 253-byte buffer. The function contains 5,173 versus 5,034 static instructions in these particular binaries; that is not a CPU-cost result and does not predict SDK layout.

The avoided allocator/free work may or may not outweigh the larger frame and stores. Keep this prototype separate until F finishes its current acceptance work and a new fixed native/SDK screen can check ordinary hits, lease-present hits, cached/configured CNAME, long/binary names, raw records and localised address controls. Do not combine it with the independent lookup-result prototype before measuring each.

Full local commands, binary/source digests, count rows and prologues: [prototype receipt](local-dotted-prototype.json). Native artifacts and complete assembly remain under the private worktree directory.
