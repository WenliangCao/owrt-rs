# TCP listener survival during accept failure

The Rust TCP listener now survives failed `accept` calls. Previously any error
other than `WouldBlock` or `Interrupted` exited its worker, eventually closing
the listening socket. The actual FD-exhaustion gate recorded this with EMFILE:
the released descriptor then let an unrelated UDP upstream socket allocation
succeed. See `DNS_START_FAILURE_PHASE.md` for the retained failing evidence.

The pinned `dnsmasq.c::do_tcp_connection`, lines 2024-2027, retries EINTR and
returns to the parent event loop on any other accept error. It does not close
the listener. Rust now likewise retries EINTR immediately and preserves its
listener after all other errors. Its existing nonblocking polling loop sleeps
20 ms before retrying, including under persistent descriptor pressure. This
adds no descriptors, threads or retained error objects and does not allocate a
TCP permit for a failed accept. Shutdown is checked again at the next loop
iteration. The delay bounds this retry path; it is not a C/Rust CPU benchmark.

The change is isolated from TCP cache snapshots, parent writeback and slot
admission. At the tested `0b913b4` baseline, one separate source difference
remains: Rust accepts a connection
before checking `tcp_active`, then closes it when at capacity. C's listener
polling and dispatch check for a free slot first (`dnsmasq.c:1900-1915` and
`1989-2003`), leaving excess connections queued. This fix does not establish
TCP pressure or complete daemon equivalence.

## Validation

On the isolated source based on `630addb`, Rust 1.98.1 host checks pass:

- Main binary unit tests: 6 passed, zero failed or ignored.
- Main binary Clippy with warnings denied.
- Main source `rustfmt --check` and `git diff --check`.

The committed `0b913b4` source was then built with native Linux aarch64 Rust
1.98.1. ELF SHA-256 is
`1238d66481bdd4cb62fe6716fe408fc06fa3f099209b04ea6dfbf19969da633f`.
Exact native C remains
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.

`dns_start_failure_diff.py` now passes all seven profiles and **61/61 ordered
observations** in `paired-01`, with no fixture or coverage failures. Both
FD-full cases observe six UDP socket EMFILE failures, preserving the original
zero-headroom boundary; there is no poll EINVAL or shutdown failure. The
`negative-01` calibration changes one initial forwarding counter and returns
exit 1 with exactly one difference and 60 matching observations. Earlier
failing records in `DNS_START_FAILURE_PHASE.md` remain historical evidence.

The new `dns_tcp_accept_failure_diff.py` runs complete C then Rust schedules in
normal foreground `-k` mode. C debug `-d` does not fork and would not exercise
its active TCP gauge. The new gate:

- Queues a real TCP request while descriptor headroom is zero, requires actual
  accept EMFILE, and verifies no premature reply or disconnect.
- Keeps the exact parent listening FD and socket inode across pressure and
  recovery, while parent UDP DNS and all 30 UBus metric fields remain usable.
- Restores the original descriptor limit, completes the queued request and a
  fresh connection, and observes active connections `0 -> 1 -> 2 -> 1 -> 0`.
- Checks parent descriptors return to their original identities, thread count
  returns to baseline, no child process remains, and SIGTERM exits normally.

`tcp-accept-paired-01` passes **17/17 observations**, with 31 auxiliary checks
per side and no failures. `tcp-accept-negative-01` changes only the recovered
listener comparison: 16 matches, one detected difference, exit 1 and no
fixture/coverage failures. The comparator separately rejects a missing row.
The tool SHA-256 for both runs is
`a08cfe8c247d7dcc978f0cf579a6a9631457c86dc311ff3834159ceeb6e96e54`.

Resource observations in the paired run are parent-process samples, not peak
or cost comparisons:

| Sample | Exact C | Rust |
| --- | ---: | ---: |
| Initial / pressure parent FDs | 15 / 15 | 7 / 7 |
| Two active / closed parent FDs | 17 / 15 | 9 / 7 |
| Initial / active / closed parent threads | 1 / 1 / 1 | 3 / 5 / 3 |
| Initial / active / closed child processes | 0 / 2 / 0 | 0 / 0 / 0 |
| Observed accept EMFILE before restoring limit | 1,659 | 6 |

The retry counts are diagnostic for this short straced fixture, not throughput,
CPU or latency evidence. Each process uses its own zero-headroom limit (C 15,
Rust 7); both limits are restored before recovery. The C child-process memory
and descriptor costs are outside these parent samples.

Private raw configurations, wire bytes, UBus payloads, resource snapshots,
syscall traces and results are under
`/home/ubuntu/dns-resume-fd-20261001/private/` in the four directories above.
No target artifact, complete TCP pressure equivalence, performance gain or
physical-router acceptance follows from these bounded gates.
