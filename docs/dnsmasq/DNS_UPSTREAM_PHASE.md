# DNS upstream transport phase

This phase supplies an isolated UDP transport around `ForwardDispatcher`. It
is a development/integration boundary, not a replacement for the complete
dnsmasq event loop. It does not open TCP, select UCI server rules, run
`process_reply`, perform DNS rebind/address filtering, insert cache records or
send a client-visible response.

| C behaviour | Rust API | Contract |
| --- | --- | --- |
| `forward.c:forward_query()` sends to candidates and records random sockets | `UpstreamResolver::start_udp` | One nonblocking UDP socket is owned by one query/server pair. A failed candidate is skipped and later candidates are attempted; failed sends never become table socket references. |
| `forward.c:reply_query()` validates ID/question/socket/source before processing | `poll` → `ForwardDispatcher::accept_reply` | Spoofed source, wrong ID/question and malformed packets are discarded. A valid response is returned as `UncheckedReply`, retaining upstream ID/case and original recipients. |
| `forward.c:915-925` logs an ordinary UDP TC reply; `forward.c:2203-2264` adds TCP only inside the `HAVE_DNSSEC` validation path | `udp_reply_is_truncated` and `UncheckedReply::truncated` | The exact `nodhcpv6` recipe does not define `HAVE_DNSSEC`, so a matched TC reply completes once and is delivered with TC set. The classifier runs after authentication and does not mutate forwarding state; a DNSSEC-enabled caller still needs a separate TCP transport. |
| `forward.c:process_reply()` REFUSED/SERVFAIL branches | `complete_reply` through `receive_ready` | `Wait` keeps all-server sockets open and continues polling without resending. `Retry` uses `plan_after_error`; a receive timeout is an expiry event, never a synthetic SERVFAIL. |
| `forward.c:fast_retry()` | `tick` | Fast retry is driven only by the configured fast-retry interval and `ForwardTable`; each attempt must send before its delay is doubled. |
| `free_rfds`/`free_frec` cleanup | `cancel`, `clear`, terminal event handling | Every transaction deadline, cancellation, send failure, poll error and successful delivery releases owned sockets and consumes dispatcher release records. |

The poll implementation takes one fixed deadline per transaction and polls all
owned sockets together. It limits receives per ready socket so a continuously
chatty upstream cannot starve the containing event loop. `resolve_udp` is only
a bounded convenience wrapper for an otherwise idle transport; asynchronous
callers should use `start_udp`, `poll`, `tick` and `cancel`.

`UncheckedReply` is deliberately named: callers must apply the remaining C
`process_reply` checks and client EDNS envelope before delivery. TCP upstream
fallback is not represented by this UDP type. For the exact OpenWrt base
variant, that is an explicit source-backed boundary rather than an omitted
ordinary-query retry: the recipe emits `-DNO_DHCP6` and does not enable
`-DHAVE_DNSSEC`, while C's `tcp_from_udp()` is compiled only under
`#ifdef HAVE_DNSSEC`. The classifier and loopback regression below preserve
the TC packet and prove that no UDP resend or transaction leak is introduced.

## Isolated evidence

`dns::upstream::tests` covers nine loopback cases: source spoof rejection,
failed-first-server fallback, all-server REFUSED waiting without a resend,
bounded timeout cleanup, duplicate coalescing/cancellation, explicit fast
retry/cancellation, and matched TC delivery/classification (including short
header rejection). The tests use only loopback UDP sockets and deterministic
random IDs. They passed 9/9 in the current crate run. The C state differential
and EDNS envelope evidence remain separate in `DNS_FORWARD_SERVICE_PHASE.md`;
this transport evidence does not claim complete daemon equivalence or
production acceptance.

The repeatable evidence wrapper is
`tools/dnsmasq/dns_upstream_probe.py`. For example:

```sh
PATH="$HOME/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin:$PATH" \
  python3 tools/dnsmasq/dns_upstream_probe.py \
  --out private/dnsmasq-rs/upstream/probe-<unique-id>
```

It stores stdout, stderr and a JSON summary below ignored `private/` and
refuses an output path outside that directory.
