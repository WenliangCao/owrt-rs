# R131 Oracle correctness supplement

R131's frozen release ELF remains `c5bcf6e7c6f2ed565140e183ba3aa97c1ef60274bbde8398771ac13680da839a`.
The new commits `344e4ac` and `18df115` only extend tests; the production
portion of `client.rs` is byte-identical to source `4e45d2e`. No replacement
release ELF was introduced for these checks.

| Check | Result |
| --- | --- |
| Target musl unit tests | 53 passed, 0 failed |
| Native Oracle unit tests | 53 passed, 0 failed |
| Existing root/non-root functionality, ACL, fuzz, limits, recovery gates | Six gates, all exit 0 |
| Object events, events, monitor, release, UTF-8, monitor lookup, method ACL | C/R124/R131 transcripts byte-equal |
| Six FD boundary cases | C/R124/R131 byte-equal; witnesses and FD return-to-baseline pass |

The new socket tests force a direct short write inside frame two or frame
three, followed by another queued frame. They check the queue head, partial
offset, exact final bytes, and independence from reused batch storage. Both
tests also pass with the **original R124 helper** substituted into an isolated
test copy. This is added regression coverage, **not evidence that R124 had a
short-write bug**.

The exact-ELF `strace` check confirms the proposed mechanism:

| Fixture, 120 events including warmup | R124 event sendmsg calls | R131 event sendmsg calls | Frames, both |
| --- | ---: | ---: | ---: |
| One handler | 120 | 120 | 120 |
| Eight handlers on one connection | 960 | 240 | 960 |

For every eight-handler event, R131 sends one frame directly, then seven in
one call. All recorded calls are complete writes without ancillary data;
the exact-image caller validates payloads and removes the handlers. Trace
times and CPU readings are excluded from performance conclusions.

Two preliminary harness failures are retained: the legacy normal event caller
does not implement `exec-cpu-as`, and Oracle denied unprivileged ptrace.
The subsequent privileged run passed; the final run additionally checks all
six exact-image library identities before starting.

Raw evidence and test ELF are retained in
`private/r131-event-batch/correctness/correctness-01/`; the archive SHA-256 is
`aa55d3c27e1a956ca974c31c3de7cbcf755e673a205a689900529f9a4feee107`.
The [derived result](r131-correctness-supplement.json) records binary, helper,
runner, library, log and trace identities. The [mechanism tool](../../tools/r131_event_syscalls.py)
is Oracle-only.

These checks did not access the physical router. Router correctness gates are
separate, and the combined recovery gate uses the existing R95 dependency
bundle; neither is a complete final nine-component performance claim.
