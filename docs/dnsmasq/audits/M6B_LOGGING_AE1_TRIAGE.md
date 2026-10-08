# M6b same-A logging failures: caller selection and runnable logs

This is a source/raw triage, not a fresh passing gate. The failed same-A run
uses source `ae1cdba6bd03cf4e28b566c31f610a31020824de` and ELF
`e29007279f74165ffd08afc1d590fe6974db4be0624aa0bfe69aecdc5e827695`.
The original four failed cases remain in
`private/dnsmasq-rewrite/evidence/M6B/logging-ae1-failed-01/`; its derived
`readonly-triage.json` lists the input file identities. Full-metadata archive
qualification is separate and remains the root controller's responsibility.

| Failed case | Actual evidence | Classification and correction |
| --- | --- | --- |
| `startup-fault-error-pipe` | Old tracer injected EMFILE into Rust's first pipe; Rust then successfully daemonized and served DNS. C's selected second pipe failed with exit 5 and `cannot create pipe`. | Fixture selected Rust's optional signal wake pipe, not the startup error channel. Select by daemonization caller, then fresh-run both sides with the unchanged exit/errno expectations. |
| `startup-fault-error-pipe-flags` | Old Rust trace injected EIO into fd 4 `F_SETFL`; service then started. C fd 9 error writer failed with exit 5. | Same incorrect pipe selection. Bind the actual selected pipe's returned writer and inject its `F_SETFL`, preserving exit 5. |
| `startup-error-frame-interrupt` | C injected EINTR into fd 9 `writev` in the second child and reported the expected missing-log error. Rust's fault receipt has `injected=false`, with no selected syscall reached, although the original missing-log error is present. | Old selector retained the signal writer and never matched the real error-frame writer. Bind the selected error writer across both forks, then inject the same frame write with unchanged exit 3 and child depth 2. |
| `query-stale-producers` | Both sides captured four upstream requests: two initial answers plus UDP/TCP stale refresh requests with no replies. Both served the correct stale TTL-zero answers. C logged `UDP 106 forwarded stale-udp.forward.test to 127.0.0.2#15957`; Rust logged neither this record nor another equivalent record. | Real ordinary producer/consumer scheduling bug. Emit submission-generated query events immediately after the background refresh, rather than waiting for an upstream response or expiry. |

## Exact startup channel caller

The exact reference `dnsmasq-2.93/src/dnsmasq.c:582–589` creates the signal
pipe, and `:593–611` performs `chdir("/")` before `safe_pipe(err_pipe, 0)` and
the first fork. `util.c:352–358` makes pipe/flag failures fatal with `EC_MISC`.
Rust's same-A `main.rs:841` creates an optional signal wake pipe before
`StartupChannel::begin` at `main.rs:1198`.
`components/dnsmasq/src/startup/daemonize.rs` then performs the same successful
root-directory change, creates its private pipe, sets the writer nonblocking,
and forks twice. The old Rust ordinal of 1 became false when signal wakeup
was implemented.

Tool commit `e64e4525` replaces ordinal selection on both sides with the actual
successful `chdir("/")` → pipe → first-fork interval. It records that interval,
pipe flags, and returned reader/writer in `fault.json`. No failure result,
error spelling, errno, or followed-child depth is relaxed. Local execution
passed 10 tests; two Linux-only network controls were skipped on macOS.
Actual AArch64 ptrace and mirror qualification must be freshly executed.

## Stale refresh log is runnable when submitted

C `forward.c:2004–2016` sends the stale answer first, clears client source from
the refresh context, and forwards without a second client reply. The upstream
submission logs `F_SERVER | F_FORWARD` immediately at `:555–557`; it does not
need a reply to produce that record.

Rust `main.rs` drains `daemon.take_query_events()` before sending the stale
answer, then calls `refresh_udp_prepared_on_listener` afterward. That function
calls `submit_upstream_with_metadata`; `dns/daemon.rs` collects the new
upstream Forwarded event when submission completes. The event remains queued
in the daemon after the original drain. The new readiness dispatch calls
`poll_udp_completions` only for ready upstream sockets or expired upstream
deadlines. This fixture deliberately sends no refresh reply and stops before
expiry, so no consumer runs in time. The successful-refresh case does receive
a reply and therefore drains the event, which explains its separate pass.

The proposed small patch is retained as
`logging-ae1-failed-01/stale-refresh-product.patch`. Root must apply it to the
common no-A and independent A versions and add/run the actor test. It drains
and emits refresh submission events within the same stale branch after
releasing the parent borrow. Send-before-refresh, background context without
client prefix, and no second client reply stay intact. The service test must
fresh-run the existing failed case and successful refresh-context case, and
reject removal or duplication of the forwarded record. No product file was
changed by this triage agent.
