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
admission. One separate source difference remains: Rust accepts a connection
before checking `tcp_active`, then closes it when at capacity. C's listener
polling and dispatch check for a free slot first (`dnsmasq.c:1900-1915` and
`1989-2003`), leaving excess connections queued. This fix does not establish
TCP pressure or complete daemon equivalence.

## Validation

On the isolated source based on `630addb`, Rust 1.98.1 host checks pass:

- Main binary unit tests: 6 passed, zero failed or ignored.
- Main binary Clippy with warnings denied.
- Main source `rustfmt --check` and `git diff --check`.

These existing host checks do not exercise Linux EMFILE recovery. The actual
Linux gate remains required: rerun `dns_start_failure_diff.py` in a fresh
loopback-only namespace and retain the unchanged zero-FD-headroom boundary.
Every FD-full query must still observe UDP `socket` EMFILE, all reply/counter
observations must match exact C, recovery must work after restoring the limit,
and no poll EINVAL or shutdown failure may be hidden by changing the limit.
The earlier baseline contains seven profiles and 61 ordered observations.

A dedicated TCP recovery check should retain the original listening socket
identity across pressure, observe real accept EMFILE, restore the descriptor
limit, complete a DNS query over the same listener, then verify active
connections and resources return to their expected state. Use normal foreground
`-k` mode if comparing C's active TCP gauge: C debug `-d` does not fork and its
gauge increments only on the normal parent path. No Linux gate result, target
artifact, performance gain or physical-router acceptance is claimed here.
