# DHCPv4 runtime boundary

This phase joins the admitted `dhcp::service::Dispatch` to the already
reviewed state and wire layers. It does not discover interfaces, open sockets,
perform relay forwarding, or silently turn unsupported PXE/LEASEQUERY routes
into local DHCP replies.

| C source | Boundary | Rust | Evidence |
|---|---|---|---|
| `dhcp.c:130-177,248-373` | `recvmsg` admission has already bounded the datagram and captured interface/pktinfo; the IP-header destination is distinct from the local interface address | `dhcp::service::Received` retains peer, destination, `local_address` (`ipi_spec_dst`) and interface; `dhcp::runtime::process` emits `Admitted` | pktinfo parser test and runtime tests inspect local, relay and all-ones relay-source metadata |
| `rfc2131.c:75-1830` | Context/tag/lease selection is caller-owned; state side effects commit before transmission | `OutcomeProvider` → `Outcome`, followed by `StateCommitted` | Provider callback tests verify no callback for unsupported routes and commit survives send failure |
| `rfc2131.c:138-151,2050-2129` | Reply buffer follows option-57 capacity and bounded header/option construction | `build_outcome` into caller-owned buffer; `Built` event | Small-buffer test returns `ReplyError::BufferTooSmall` without sending |
| `dhcp.c:397-500` | Local replies select client port 68, broadcast for broadcast flag/invalid hardware, otherwise peer/`ciaddr`/`yiaddr`; unconfigured `yiaddr` needs ARP and an interface route; relay send needs a distinct server port | `destination` models local routes with interface/ARP metadata; Linux `DatagramSocket` can send broadcast replies with `IP_PKTINFO` interface selection and ordinary client/peer replies; ARP and relay/PXE/LEASEQUERY remain explicit `Unsupported` | Broadcast OFFER and renewal peer/client tests; pktinfo parser/target check; relay and relay-source tests reject before state |
| `dhcp.c:530-550` | Lease/name/DNS cleanup is independent of UDP send success | `StateCommitted` and `Cleanup` events; `RuntimeFailure::committed` | Mock send failure preserves committed ownership and records no rollback |

The public destination boundary also checks that the caller-supplied completed
wire buffer contains the full `chaddr` slice before preparing ARP metadata. A
short synthetic buffer now returns `BufferTooSmall` instead of indexing past
the packet; the real C path always supplies the fixed BOOTP header first.

The runtime entry point is:

```rust
process(dispatch, peer, outcome_provider, datagram_sender, options, buffer)
```

`runtime::StateProvider` is the local state adapter used when the caller has a
configured `LeaseStore` and address ranges. It maps BOOTP, DISCOVER, REQUEST,
DECLINE, RELEASE and INFORM to the existing state functions, applies pktinfo
interface/unicast metadata to `Environment`, and derives option 12 hostnames
so `LeaseStore::set_hostname` marks DNS/name changes before reply transmission.
The provider deliberately leaves FQDN/domain policy, leasefile persistence and
DNS publication to the caller; `Outcome::lost_names` and `LeaseStore::changes`
are the handoff evidence. `service::SocketListener::process_once_local` then
owns the isolated nonblocking AF_INET socket and feeds an admitted datagram
through this runtime path.

On Linux 64-bit, `net::DatagramSocket` implements ordinary client/peer sends
and broadcast sends with `SO_BROADCAST` plus IPv4 `IP_PKTINFO` interface
selection. Unconfigured `yiaddr` routes still return an explicit unsupported
error until ARP-cache injection is available; relay/PXE/LEASEQUERY remain
unsupported. Library tests use a recorder/failure sender and never bind a
socket. The caller owns buffer sizing and supplies the selected options; the
runtime sends exactly the `ReplyEncoding::len` prefix to a complete
`Destination` route.

Relay, relay-source, PXE, DHCPLEASEQUERY and unknown message kinds return an
explicit `RuntimeError::Unsupported` before invoking the state provider. This
is a deliberate integration gate until their destination and wire contracts
are implemented. `RuntimeReport` and `RuntimeFailure` retain the owned
`Outcome` after the provider returns, so removed leases and lost-name
notifications can reach cleanup sinks even when build or send fails. A
provider-returned outcome is considered committed before wire build;
buffer/build/send failures therefore report `committed = true` and must not
attempt a lease rollback.

## Local destination differential (2026-09-30)

`tools/dnsmasq/dhcp_destination_diff.py` extracts the local `ciaddr` branch and
the Linux flags/hardware/ARP branch from the matching `dhcp.c:415-476` (SHA256
`600dc068b0516d7edebcde9b02ae2091a278fc154551106823ddc388170d7001`). The
generated C oracle runs with address/undefined-behaviour sanitizers. Its ioctl
stub records ARP metadata without opening sockets or changing the host network.
Both implementations receive the same completed BOOTP header and peer. The
comparison retains destination address/port, ARP hardware type and address;
there are no randomized or reordered fields to normalize at this boundary.

The harness first calibrates success/failure counts, missing/extra output
detection, and seven manually checked C branch results. Its 3,648 cases vary
INFORM/ACK, `ciaddr`, `yiaddr`, source address/port, broadcast flag, hardware
type and lengths 0/1/6/14/15/16 within the admission contract. Before the fix,
672 comparisons failed; after the fix, **3,648 passed, zero failed**. Raw
inputs, generated C, executables and all outputs remain ignored under
`private/dnsmasq-rewrite/dhcp-destination-20260930/{before,after}/`.

Two runtime differences were fixed and retained as focused regressions:

- INFORM may trust a peer address different from `ciaddr`, but zero source
  addresses or source ports still fall back to `ciaddr:68` in C. Rust now
  preserves that condition. IPv6 synthetic peers also fall back; real IPv6
  ingress is already rejected by the DHCPv4 service boundary.
- With no `ciaddr` and valid hardware, the Linux C branch chooses `yiaddr`
  and ARP metadata even when the supplied `yiaddr` is zero. The route selector
  no longer invents a broadcast fallback for that header; state selection
  remains responsible for choosing the offered address.

The affected DHCP library regression passed 66 tests. This is a socket-free
destination/ARP-metadata comparison; it does not validate interface ancillary
data, actual ARP injection, sends, alternate ports, relay/PXE, or the complete
listener/lease lifecycle, and carries no performance claim.
