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
| `edns0.c:add_pseudoheader()` | Unsigned queries advertise the configured upstream UDP size. If no OPT exists, an empty OPT is appended only when the output envelope fits; C's tight `p+11`/`p+4` boundary can leave an uncounted trailing OPT and is retained. Signed TKEY/TSIG traffic is left byte-for-byte unchanged. | `prepare_query` | `signed_tkey_is_not_decorated`; `prepare_preserves_c_tight_envelope_opt_boundary`; malformed/truncated input is rejected before table state |
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
TKEY, trailing bytes, and the tight output envelope. Generated C/Rust binaries,
inputs and outputs are ignored under
`private/dnsmasq-rs/forward-service/differential/`.
