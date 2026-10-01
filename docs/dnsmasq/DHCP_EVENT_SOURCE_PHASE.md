# DHCP ACK/RELEASE source notification adapter

The local provider now exposes a borrowed `with_event_sink` adapter for one
listener operation. Ordinary ACK, INFORM ACK and RELEASE callbacks originate
at their state-machine `rfc2131.c log_packet` counterparts, before reply
construction and sending. They are not reconstructed from post-send events.
The caller's notification failure cannot roll back the DHCP transaction.

The runtime passes the interface-name snapshot captured before state/probing.
The provider preserves `extended_hwaddr` / `print_mac` behavior, including
client-ID fallback, EUI64/IEEE1394 handling and the `<null>` empty-hardware text.
`quiet-dhcp` suppresses clean notifications unless `log-dhcp` is enabled; an
unknown RELEASE retains its error notification. RELEASE never borrows a name
from the deleted lease. INFORM's by-address lease-name fallback is separate
from the name of a lease already found by client identity.

Write points match `rfc2131.c:1282–1283,1738–1739,1784–1785`:

- RELEASE: after a valid matching lease is pruned, or after unknown-lease
  classification, and after its counter increment.
- Ordinary ACK: after identity/name/expiry/interface state is committed and
  its ACK counter incremented.
- INFORM ACK: after its counter increment, before lease-interface update.

`LocalProvider` passes the synchronous callback to `StateProvider`; its
file/DNS maintenance follows `StateProvider::resolve`. The borrowed adapter
forwards the existing boot, option and name methods. Its sink does not acquire
the provider again. Main's event/provider/parent lock integration and real
ubusd delivery are separately owned and tested by the UBus integration stage.

`dhcp_events_diff.py` links unchanged exact C rfc2131 objects with a linker
wrapper around `ubus_event_bcast`, recording the actual `log_packet` arguments.
The wrapper observes notification intent, not subscriber/broker delivery. The
Rust observer uses the real `LocalProvider` and borrowed adapter with the same
configuration and request bytes, in an isolated namespace whose only interface
is loopback. A synthetic address is assigned only to that private loopback.
All expiry times stay live in this corpus; this field/order gate does not
compare wire TTLs or infer lease-expiry equivalence from event equality.

Ignored evidence is under `private/dnsmasq-rewrite/boot-config-20261001/`:

- `events-c-baseline-01`: 9 source scenarios, 41 packet steps, 23 C events.
- `events-pair-01`: **41/41** ordered per-packet event lists match, including
  no-event cases; no unexecuted steps.
- `events-calibration-01`: remove one ACK event, **40 matches / 1 difference**,
  exit 1.
- `events-unit-01.log`: **109** related unit tests pass.
- `events-source-order-unit.log`: the source callback is observed before the
  sender is entered; an injected send failure does not repeat/undo it.
- `events-musl-clippy.log`: Linux-musl library clippy, warnings denied.
- `events-freeze-01`: source archive/manifest, observer ELF and successful build.

The C observer ELF SHA-256 is
`664e15b1f60b598d70a25dce2e17816c22ee66b2b2667b04c73232a5a9c96286`;
the Linux Rust observer is
`b18d44998f6a7d830e09c63e0fab2497ec1d62006ac801fdb04d28332065af01`.
Frozen source-manifest SHA-256:
`c44c93b604ca38eb8ec739d78a7c7de59af2ee3924fc45f0c1592d1dc311332d`.
The later source-order assertion is a test-only addition after that freeze.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dhcp_events_diff.py \
  --reference-build "$EXACT_C_BUILD" \
  --rust "$FROZEN_RUST_OBSERVER" --output private/dhcp-events-rerun
```

This stage does not close the previously missing ACK/INFORM `host_from_dns`
reverse-static-host lookup. That needs its own C baseline and shared DNS hook;
it must not use dynamic DHCP names or a system resolver as a substitute.
A stronger file/DNS-maintenance order observer is also pending; external ubusd
arrival order is not used as proof of source order. No whole-daemon, resource,
performance or physical-router acceptance claim follows from these passes.
