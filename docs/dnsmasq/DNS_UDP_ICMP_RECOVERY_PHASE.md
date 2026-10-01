# UDP ICMP refusal and retry: observed recovery, receive-error gap remains

The closed-upstream-port service experiment completed with **52 behavioral
checks passing and no C/Rust trace differences**, but it did **not** trigger
the application's receive-error branch. The tool deliberately exits **2** and
records that coverage gap. Kernel ICMP traffic is not evidence that a UDP
application received POLLERR or a failing recvfrom.

This report describes the original `2415216` experiment. The later
[receive-error repair](DNS_UDP_RECEIVE_ERROR_PHASE.md) adds controlled I/O
coverage and repeats the actual-service gate; real errno delivery remains
uncovered in that recheck too.

No product source was changed. In particular, this work does not modify
`upstream.rs`, enable socket error options, connect the daemon's UDP sockets,
inject syscall faults, or access a router/production network.

## Identity and isolation

The actual C daemon is the audited native 2.93 reference, ELF SHA256
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Rust is the frozen product **2415216**, SHA256
`1334f0dfbd9af3a38279a0fb69199be8193f7b5a3e710787a48fb33b37d786be`.
That Rust snapshot has the original receive-error cancellation behavior. It
also predates the later forwarding-lifetime repair, so this experiment stays
well inside its 40-second timeout and makes no claim about that later boundary.

Both run on the same Linux `6.17.0-1020-oracle` build-host kernel, in fresh
network/mount/PID isolation containing only loopback. The client side uses IPv4;
the upstream side is tested separately over IPv4 and IPv6. Both sides use the
same configuration, fixed query, zero dynamic cache capacity and disabled case
randomization. No DHCP listener is configured.

The passive AF_PACKET observer only receives standard loopback traffic; it
does not transmit raw packets. Strace attaches only to the task-owned daemon
and its threads. The raw IP packets, process FD maps, configuration, syscall
logs and random IDs/ports remain in ignored/private.

## What actually happened

The controlled upstream port initially has no bound receiver. The harness
sends one ordinary DNS query, records its outgoing upstream ID/source port,
and observes the kernel's matching port-unreachable ICMP message. It waits for
an error-processing opportunity and verifies that no premature client answer
arrives. It then opens the controlled upstream socket and retransmits the
same query from the same client socket and ID.

For C and Rust, over both upstream families:

- The upstream socket remains present after the ICMP observation.
- The retry reuses the original upstream ID and source port.
- Exactly two upstream queries are observed: the initial query and the manual
  retry. The controlled successful reply reaches the client with the original
  client ID, expected flags, address and TTL, without a second client reply.
- The transaction's upstream socket is released on completion. Each daemon
  exits normally and is reaped.

The raw syscall clocks place the first upstream send to the final client reply
attempt within approximately 0.3 seconds for these runs. This only establishes
that the 40-second snapshot difference was not exercised. The interval includes
the harness's deliberate wait and strace overhead; it is not a latency or
performance comparison.

| Daemon / upstream family | Sampled FD count: ready → pending → complete | Sampled threads | Child processes |
| --- | --- | ---: | ---: |
| C / IPv4 | 11 → 12 → 11 | 1 | 0 |
| C / IPv6 | 11 → 12 → 11 | 1 | 0 |
| Rust / IPv4 | 6 → 7 → 6 | 3 | 0 |
| Rust / IPv6 | 6 → 7 → 6 | 3 | 0 |

These are point-in-time resource observations, not peaks, exclusive memory,
long-run growth or target-router cost measurements.

## Why the targeted error branch was not covered

The namespace first calibrates ordinary harness UDP sockets independently of
the daemons. Unconnected IPv4/IPv6 sockets report no poll error and EAGAIN on
recvfrom after sending to the closed loopback port. Connected control sockets
in that same namespace do produce POLLERR and ECONNREFUSED. These controls prove
that kernel error delivery works for the connected case; they are **not** a
connected substitute for the real service sockets.

Source inspection and actual strace agree that the tested daemon paths use
bind plus sendto, without connect or IP_RECVERR/IPV6_RECVERR. Passive capture
confirms the ICMP messages, but all four actual upstream FD traces contain
**zero returned poll-error events and zero non-benign receive errors**. The
checker distinguishes requested poll flags from returned `revents`; merely
asking poll to watch POLLERR is not counted as receiving it.

The retained source-level discrepancy is therefore still unexercised:

- Exact C `forward.c::reply_query` performs recvfrom and returns before frec
  lookup when the length is below a DNS header, including an error return.
  It does not cancel that query there. Its listener dispatcher checks POLLIN.
- The frozen Rust `UpstreamResolver::receive_ready` calls `fail` on a standalone
  POLLERR/POLLHUP or a non-benign recv_from error. `fail` cancels the query and
  releases its sockets and recipients.

This is not an observed closed-port functional regression. A later change
needs a separately labeled receive-error test or a deterministic I/O-boundary
unit test. Recoverable receive errors, stale/invalid owned FDs and shutdown
must remain distinct. Simply ignoring a persistent poll error could create a
busy loop; changing connect/error-delivery options solely to make a fixture
fail would no longer test the deployed socket contract.

## Calibration, evidence and reproduction

`gate-01` retained the initial 40-check diagnostic. Its capture/recovery result
was the same, with the target branch uncovered. `gate-02` adds explicit
controlled-answer/source-port/no-extra-reply checks so both implementations
returning no answer cannot pass merely by agreeing. All **52** checks pass.
Separate comparator calibration accepts the actual C trace, rejects a changed
upstream-ID relationship and a missing client reply, and rejects a shortened
family list. IPv4/IPv6 normalized C/Rust traces both match.

Evidence is in ignored
`private/dnsmasq-rewrite/udp-icmp-recovery-20261001/`, including both rounds,
the frozen Rust source excerpt, strace logs and raw packet captures. The source
contract remains **uncovered**, not waived or marked as passed.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dns_udp_icmp_recovery.py \
  --c "$EXACT_C_DAEMON" \
  --rust "$FROZEN_RUST_DAEMON" \
  --rust-sha256 "$FROZEN_RUST_SHA256" \
  --rust-revision 2415216 \
  --out private/udp-icmp-recovery
```

Exit 0 requires that the target error path was actually observed; exit 1 reports
behavioral/harness failure; exit 2 records successful ordinary recovery with
the receive-error coverage gap still present. No production acceptance or
performance conclusion follows from this experiment.
