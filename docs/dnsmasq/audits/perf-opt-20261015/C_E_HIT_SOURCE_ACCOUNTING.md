# Exact C/E hit-path source accounting, before PMU attribution

This is source evidence for the newly requested direct C/E comparison, not a
cost ranking. Fresh paired device data confirms UDP CPU 84→146 µs/query and
TCP CPU 116→168 for exact C `097a9e21…` versus E `8b8082b9…`. No elapsed CPU
share is inferred from the code below. The pending syscall/PMU captures decide
which difference is material.

The matching OpenWrt C source files are hash-bound: `forward.c`
`ac05784d4233ed10bd166da5fe91e464afecf2883d3c2a0063305d3e81692f95`,
`dnsmasq.c` `d4bb7cde522376200a0293427b0812625ebc457f10dc9d3e2bef243ccba8ccd1`,
`rfc1035.c` `231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222`,
`cache.c` `51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c`.
Small original snippets remain private. E is frozen source `4f869c88`; no new
product patch is included in this note.

| Boundary | Exact C source | E source and concrete question |
| --- | --- | --- |
| UDP read | `check_dns_listeners` calls `receive_query` once and returns; `receive_query` makes one `recvmsg` | `SinglePoll::step` loops `step_udp` to a 16-packet budget; a quiet single-packet wake can make one trailing EAGAIN receive. Verify real counts before assigning cost. |
| Receive buffer | Global packet buffer, recv capacity configured EDNS maximum, then clears the unused tail | Persistent 65,535-byte owner buffer; initialized ancillary/address storage, cmsg parse and size/admission checks. Verify syscall parameters and avoid calling a larger buffer a copied payload. |
| Initial name validation | `extract_request` / later `answer_request` use the global name buffer | `udp_query::inspect` calls owned `wire::Question::parse` only to test `is_err`, dropping the name; `answer_udp_prepared_with_local` later parses another owned question. This is a concrete repeated allocation/parse, but its cost is not yet measured. |
| Pseudoheader | `receive_query` and answer/EDNS logic inspect the packet as required | `query_metadata`, local lookup and cache answering can each inspect OPT. Their malformed/signed/transport policies differ; sharing results requires proving identical input and interpretation. |
| Answer selection | `answer_request` combines configured records and dynamic cache, using a shared writer cursor | Local and cache components share a parsed question and query-local missing/singleton cache hint. Earlier instrumentation proved one initial name-index lookup per ordinary hit; do not claim the old duplicate lookup remains. |
| Cached name lookup | Pointer-seeded C bucket chain and in-place RR iteration/LRU mutation | FNV shard selection then randomized HashMap and slot/record indirection. Earlier exact SDK review found FNV tiny and probe samples concentrated in the first SIMD compare, not demonstrated long probe chains. Await direct C/E user-instruction attribution. |
| Reply | C writes into its packet buffer and sends the completed reply | Owned reply vectors and bounded writer, then `sendmsg`; earlier UDP input borrowing already removed the unconditional receive-packet copy. Enumerate remaining allocations using the real dynamic-cache hit fixture. |
| Time | Main loop obtains `dnsmasq_time` after poll and passes it down | Owner deadlines and daemon wall clock are read at several boundaries. Many clock reads can use vDSO; syscall absence cannot establish zero time-read work. |
| TCP | Keep-in-foreground C still forks; queries execute in children | E runs per-client state machines in the single owner. All C child work, close/reap and common fixed capture drain must be included. Parent-only counters are invalid for this comparison. |

None of these rows justifies changing validation precedence, buffered-work
fairness, CNAME/expiry/LRU behavior or error handling. Existing rejected batching
and insertion-key experiments remain evidence, not shortcuts to repeat. A
candidate should remove the largest measured unnecessary work, then receive
reproducer/regression coverage, mechanism screening, complete correctness and
fresh E/candidate device pairs.
