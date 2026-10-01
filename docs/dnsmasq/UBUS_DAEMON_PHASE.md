# Real daemon UBus integration: one remaining TCP cache gate

The actual Rust daemon now consumes `enable-ubus`, publishes metrics from its
running engines, applies UDP DNS subscriber replies, and sends DHCP ACK/RELEASE
notifications at their source event. The frozen real C/Rust service schedule
has **69 paired observations: 68 match, 1 fails**. The remaining failure is the
previously absent TCP child-to-parent cache writeback; UBus does not fabricate
an insertion to hide it. This is a development service phase, not complete
dnsmasq replacement or deployment acceptance.

## Ownership and event ordering

The foreground runner serializes parent events with one mutex. Lock order is
`event -> DHCP provider -> DNS parent`; socket receive waits happen outside
that gate. UBus connection state and the actual local/stale UDP send counters
belong to the event owner. The TCP active gauge counts the same real slots used
for TCP admission, with a permit released when the session exits; the previous
atomic slot owner was replaced, not copied into a second metric.

Cache insertion/live-free counters are read from `DnsDaemon`'s cache owner;
forwarded/unanswered counters come from its forwarding owner; lease operation
and DHCP message counters come from `LocalProvider`. No snapshot consumes or
resets these counters. SIGHUP resets only the cache owner's two counters while
preserving the other windows. Disabled engines naturally contribute zero;
auth, DNSSEC, DHCPv6 allocation and leasequery paths are excluded or rejected
by this implementation. IPv4 restoration of `0.0.0.0` can still contribute to
the IPv6 prune slot, which is copied from its real lease owner.

Before DNS processing, the runner captures the provider snapshot, then locks
the DNS parent. The record callback receives current DNS counters at the common
admitted-reply stage, before the reply's cache transaction commits. It performs
UBus replacement and static alias processing in one ordered scan. The
controller answers metrics requests queued during the synchronous notification
before returning a replacement. No callback reacquires the provider lock.
TCP receives no UBus doctor callback.

For the real queued-call case, both C and Rust report:

| Snapshot | Cache inserted | Queries forwarded | Local answered |
| --- | ---: | ---: | ---: |
| Before DNS query | 6 | 7 | 3 |
| Metrics requested inside subscriber callback | 6 | 8 | 3 |
| After DNS reply | 7 | 8 | 3 |

DHCP uses `LocalProvider::with_event_sink` and the source-stage ACK/RELEASE
producer, before lease maintenance and socket sending. The main sink calls
UBus directly; it does not infer events from a successful send or lease diff.
Quiet/log/error decisions are supplied by the producer. Notification delivery
failure drops the UBus connection without undoing DHCP state or suppressing a
valid reply. External arrival order through ubusd is not asserted to prove
the internal pre-send ordering.

Initial object-registration failure exits with C's miscellaneous-error status
5. An absent bus permits normal service startup and is retried. Registration
failure during retry disables only UBus; transport failure discards connection
IDs and retries using fresh objects. The main loop also services UBus with
`port=0` and no DHCP traffic. The empty-name safety boundary from
[UBUS_CONFIG_PHASE.md](UBUS_CONFIG_PHASE.md) remains explicit.

## Real service corpus and remaining failure

`ubus_daemon_diff.py` completes the entire exact C schedule before the Rust
schedule. Both consume the same semantic configuration and DNS/DHCP inputs.
All 30 metric fields, widths and order are checked against C, alongside object
signatures, typed notifications and DNS responses. There is no standalone
counter fixture and no test-only production CLI.

The 69 observations cover local answers; forwarded/cache answers; HUP windows;
A/AAAA, unchanged/invalid/wrong-family/silent doctor responses; UBus-before-alias
ordering; rewritten cache hits without repeated notifications; queued metrics;
TCP active/local/upstream/closed states and absence of TCP DNS notifications;
normal, quiet and quiet-with-log DHCP ACK/RELEASE fields and counters; restored
leases with `port=0`; stale replies and background refresh; live cache pressure;
no-upstream refusal; and normal DNS service while UBus starts late. Additional
checks verify reconnect, fresh Rust DNS object types, resumed rewriting, clean
daemon exits and disappearance of process resources.

The sole mismatching observation is `tcp-closed`: after one successful TCP
upstream answer, C's parent cache has 8 insertions while Rust has 7. All other
fields match, including forwarded=8 and active TCP=0. The TCP engine has not
yet sent that cache transaction back to the parent; the reported Rust counter
truthfully reflects its actual cache. This gate remains red until the real
TCP cache ownership/transfer implementation and paired test close it.

C's separate restart defect is recorded explicitly: its DNS object's stale
type makes ordinary lookup return no DATA after ubusd restarts. Rust registers
both objects/types afresh and its subscriber can rewrite again. This reference
defect is not copied and is not counted as a paired equivalence success.
The older standalone doctor receive-buffer lifetime difference remains in
[UBUS_DOCTOR_PHASE.md](UBUS_DOCTOR_PHASE.md); this service corpus does not waive
or reclassify that separate 473/474 gate.

The negative calibration alters the C-observed initial cache-insertion
expectation. It adds a second failure: **67/69 paired observations match**.
Both positive and negative service runs exit 1 while the TCP gap remains.
Helper checks include repeated readiness samples; their raw totals are kept
in the report but do not enlarge the frozen 69-observation denominator.

The DNS hook unit test verifies two real admitted upstream transactions expose
cache counts 0 then 1, apply UBus before aliases, commit two records, and retain
forwarding counts after cache reload. The relevant daemon suite passes
**35 tests**, with **3 ignored external-oracle drivers not counted as passes**.
Six runner tests pass. The native Linux runner passes Rust 1.98.1 clippy with
warnings denied. These checks do not establish pressure, ACL, resource-exhaustion
or performance acceptance.

## Evidence and reproduction

All tests run only on the build host under the private loopback network,
mount and PID namespace wrapper. No physical router was accessed. Raw results,
configurations, packets, ELF files, hashes and failures remain ignored under
`private/dnsmasq-rewrite/ubus-lifecycle-20261001/`. The initial 56-observation
run and expanded runs are retained, including the build attempt that copied a
temporary test binary source without its included probe. Final builds name
the real `dnsmasq-rs` binary explicitly.

```sh
cargo +1.98.1 build --manifest-path components/dnsmasq/Cargo.toml --bin dnsmasq-rs
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/ubus_daemon_diff.py \
  --reference-build "$EXACT_C_BUILD" \
  --c-sha256 bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431 \
  --rust-binary components/dnsmasq/target/debug/dnsmasq-rs \
  --out private/ubus-product
```

Use a fresh output directory and `--inject-error` for the negative calibration.
