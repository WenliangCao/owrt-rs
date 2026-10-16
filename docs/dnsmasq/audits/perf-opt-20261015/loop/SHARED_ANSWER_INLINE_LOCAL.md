# Inlining the shared answer: local-only experiment

Source `a7b5fa1a` adds only `#[inline(always)]` to 9e's shared local/cache
answer entry. The hypothesis was that fixed UDP/TCP callers could specialize
transport branches and avoid a shared call boundary. No API, function body,
compiler flag, section attribute or test changes are included. All 729 local
release library tests pass (8 ignored); the final Linux musl daemon links.

The result does not establish the intended saving. The original 3848-byte
shared emitted body disappears, but the compiler now emits a 884-byte local
lookup wrapper and a 1620-byte cache-answer wrapper. The prepared UDP entry
calls these two wrappers where it formerly called the shared answer. Its own
code grows2484→3044B and frame688→816B. The outer process_udp4660B and
step_tcp_clients7596B remain unchanged. Nested frame costs must not be
compared using only the removed shared range.

The local whole ELF grows5024648→5027192B (+2544). This is neither the SDK
shipping size nor a runtime result. The source stays unselected: moving one
inlining boundary caused other outlining decisions, with no instruction,
cycle or A53 improvement established. It is not combined with frozen c95.
[Exact artifacts, tests, calls and ranges](shared-answer-inline-local.json).
