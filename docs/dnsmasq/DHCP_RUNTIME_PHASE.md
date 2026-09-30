# DHCPv4 runtime boundary

This phase joins the admitted `dhcp::service::Dispatch` to the already
reviewed state and wire layers. It does not discover interfaces, open sockets,
perform relay forwarding, or silently turn unsupported PXE/LEASEQUERY routes
into local DHCP replies.

| C source | Boundary | Rust | Evidence |
|---|---|---|---|
| `dhcp.c:130-177,248-373` | `recvmsg` admission has already bounded the datagram and captured interface/pktinfo; `Dispatch` retains kind and relay metadata | `dhcp::runtime::process` emits `Admitted` | Runtime tests inspect local, relay and all-ones relay-source metadata |
| `rfc2131.c:75-1830` | Context/tag/lease selection is caller-owned; state side effects commit before transmission | `OutcomeProvider` → `Outcome`, followed by `StateCommitted` | Provider callback tests verify no callback for unsupported routes and commit survives send failure |
| `rfc2131.c:138-151,2050-2129` | Reply buffer follows option-57 capacity and bounded header/option construction | `build_outcome` into caller-owned buffer; `Built` event | Small-buffer test returns `ReplyError::BufferTooSmall` without sending |
| `dhcp.c:397-500` | Local replies select client port 68, broadcast for broadcast flag/invalid hardware, otherwise peer/`ciaddr`/`yiaddr`; unconfigured `yiaddr` needs ARP and an interface route; relay send needs a distinct server port | `destination` models complete local routes with interface/ARP metadata; relay/PXE/LEASEQUERY are explicit `Unsupported` | Broadcast OFFER and renewal peer/client tests; relay and relay-source tests reject before state |
| `dhcp.c:530-550` | Lease/name/DNS cleanup is independent of UDP send success | `StateCommitted` and `Cleanup` events; `RuntimeFailure::committed` | Mock send failure preserves committed ownership and records no rollback |

The runtime entry point is:

```rust
process(dispatch, peer, outcome_provider, datagram_sender, options, buffer)
```

On Linux 64-bit, `net::DatagramSocket` implements the sender trait as an
explicit unsupported-route adapter until pktinfo interface selection,
broadcast permission and ARP-cache injection are exposed together. Library
tests use a recorder/failure sender and never bind a socket. The caller owns
buffer sizing and supplies the selected options; the runtime sends exactly the
`ReplyEncoding::len` prefix to a complete `Destination` route.

Relay, relay-source, PXE, DHCPLEASEQUERY and unknown message kinds return an
explicit `RuntimeError::Unsupported` before invoking the state provider. This
is a deliberate integration gate until their destination and wire contracts
are implemented. `RuntimeReport` and `RuntimeFailure` retain the owned
`Outcome` after the provider returns, so removed leases and lost-name
notifications can reach cleanup sinks even when build or send fails. A
provider-returned outcome is considered committed before wire build;
buffer/build/send failures therefore report `committed = true` and must not
attempt a lease rollback.
