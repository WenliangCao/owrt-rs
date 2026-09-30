# DNS upstream forwarding service phase

This phase adds a socket-independent dispatcher. `dns/upstream.rs` adds the
separate nonblocking UDP ownership boundary described in
`DNS_UPSTREAM_PHASE.md`; neither is a daemon, resolver configuration loader,
or cache/process-reply implementation.
The transport/event loop owns sockets, source/interface checks, server-rule
selection, EDNS option decoration, reply filtering, and cache insertion.

| C reference | Invariant | Rust boundary | Evidence |
| --- | --- | --- | --- |
| `forward.c:receive_query()`; `edns0.c:find_pseudoheader()` | The last OPT supplies the client UDP limit; it is clamped to the configured packet maximum and never below 512. DO and AD/CD become forwarding flags. | `forward_service::prepare_query` and `QueryMetadata` | `prepare_adds_opt_and_clamps_existing_opt` |
| `edns0.c:add_pseudoheader()` | Unsigned queries advertise the configured upstream UDP size. Empty OPT insertion needs 11 bytes plus four reserved bytes. If only 11–14 bytes fit, C returns the original length/arcount, while retaining any writes over an existing opaque tail. Signed TKEY/TSIG traffic is unchanged. | `prepare_query` | Exact 1,217-case extraction oracle and `prepare_preserves_c_tight_envelope_opt_boundary` |
| `forward.c:forward_query()` lookup path | New queries create one `ForwardTable` entry; retries and duplicate clients use the existing upstream ID/case packet. A duplicate arriving within two seconds is coalesced without another send. | `ForwardDispatcher::submit` | `dispatcher_coalesces_and_matches_reply`; existing `forward_tests` cover duplicate identity/case |
| `forward.c:forward_query()` server loop | Server order/all-server policy is planned by `ServerGroup`; the caller records successful sends and socket ownership. | `submit`, `note_sent`, `SendPlan` | `dispatcher_coalesces_and_matches_reply`; `forward_tests` server plan cases |
| `forward.c:reply_query()` | A response must match upstream ID, question, source endpoint, selected group and expected socket before processing. | `accept_reply` → `MatchedReply` | `dispatcher_coalesces_and_matches_reply`; `forward_tests` spoof/name/class checks |
| `forward.c:fast_retry()` | Retry scheduling is read-only until the caller sends; exponential delay changes only after `retry_finished`. | `plan_retries`, `retry_finished` | forwarding retry schedule tests in `forward_tests`; service-level retry remains transport-owned |

## Current boundary

`ForwardDispatcher` does not open UDP/TCP sockets and does not claim complete
upstream parity. It does not yet implement `add_edns0_config()` option
decoration (client subnet, MAC, source address, or Umbrella), signed reply
filtering, `process_reply()`/rebind checks, cache insertion/negative SOA, TCP
fallback, domain-aware upstream selection, or OpenWrt reload/ubus integration.
Those are separate contracts and must be wired by a caller after their C
behaviour is audited.

The dispatcher accepts a selected `ServerGroup`; it never falls back to a
default resolver or silently sends a query when no group is configured. The
UDP transport returns raw `UncheckedReply` values and leaves client delivery
to a caller that has completed `process_reply` policy.

The separate UDP transport boundary is documented in
`DNS_UPSTREAM_PHASE.md`. It returns authenticated-but-unprocessed upstream
packets and is intentionally not wired into the local-only development
binary.

## Reproducible EDNS boundary evidence

`tools/dnsmasq/dns_forward_service_diff.py --rustc <rustc> --count 1000`
extracts the exact source functions after checking their SHA-256 identities,
then compares C `add_pseudoheader(..., optno=0)` with Rust
`prepare_query`. The 2026-09-30 run used seed 293 and **1,007 cases with zero
mismatches**, including no-OPT insertion, existing/multiple sections, signed
TKEY and trailing bytes. That corpus did not position records at the tight
11-to-14-byte output boundary; its passing result did not cover that branch.
Generated C/Rust binaries,
inputs and outputs are ignored under
`private/dnsmasq-rs/forward-service/differential/`.

The 2026-10-01 extension adds 210 cases across five output sizes, 10–16 bytes
of available space, and opaque tails of 0/1/4/10/11/17 bytes. The pinned C
function exposed 100 mismatches before the fix. Rust had transmitted newly
appended OPT bytes even though C returned its original `plen`. The corrected
code preserves both C's returned length and any overwrite of bytes already
inside that original length; it does not simply delete every trailing byte.
The prior unit expectation was also incorrect and has been replaced with
independent returned-length/arcount/tail checks. The C driver now uses aligned
header storage and rejects missing output rows before comparing results.

`private/dnsmasq-rewrite/forward-opt-boundary-20261001/before-fix/` retains the
100 failures; `fixed/` has **1,217 cases and zero mismatches**. All six focused
forward-service tests pass. This closes the `optno=0` boundary only, not every
EDNS decoration or malformed-query policy.
