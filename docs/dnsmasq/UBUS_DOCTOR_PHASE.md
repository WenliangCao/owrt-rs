# Synchronous ubus DNS doctor boundary

This phase adds a synchronous library/controller hook. It does **not** connect
the product DNS daemon, publish invented metrics, enable the CLI, or establish
complete C equivalence. The exact C/Rust hook corpus retains **473 passes and
1 explicit reference-defect difference out of 474 checks**. That nonzero gate
is intentional and remains visible.

## API, ownership and failure handling

`Connection::notify_with_data_until` sends one notification and streams matching
DATA fields to a nonblocking callback. It follows the pinned libubus sequence:
first wait for ubusd's object-peer STATUS containing its subscriber-object IDs,
then accept DATA and completion STATUS only for that sequence and still-pending
peer. There are at most 16 subscriber slots, matching `UBUS_MAX_NOTIFY_PEERS`.
Repeated DATA is delivered in arrival order. Completed-peer and old-sequence
replies are discarded, including late replies from a previous timeout.
Subscriber status codes complete that peer but do not become the notification's
overall result, matching `libubus-req.c`.

One absolute deadline covers the send, all frame bytes and all responses. A
clean deadline returns `Ok(false)` and preserves the framed connection.
Unrelated invokes and subscription-state messages stay queued in order for the
owner to drain after return. A supplied cancellation callback applies during
this call, takes precedence over an existing connection callback, and is then
restored. Cancellation, EOF, malformed framing, partial-frame deadline and
queue-limit errors shut down the transport and release queued/read-ahead FDs;
the owner must drop that connection.

`UbusService::doctor_dns(&DnsResult, Option<fn() -> bool>, &Metrics)` uses a 100 ms
deadline. If the DNS object has no subscribers it returns `None` immediately.
Otherwise it returns a same-family `Some(address)` only after processing an
applicable string address. `Some` includes an unchanged address: the DNS caller
must still clear AA, as the C code does. Clean timeout keeps any applicable
response received before the deadline. The method neither changes DNS bytes nor
inserts cache entries.

The [later queued-call phase](UBUS_LIFECYCLE_PHASE.md) establishes that the C
library drains deferred invokes before returning the notification result.
The controller now does the same with a caller-supplied pre-hook metrics
snapshot; draining only after returning to the DNS owner is too late.

The future ParentDns owner must:

- Drain `process_one` before the hook so subscription state is current. The
  hook drains queued invokes and subscription changes before returning.
  Obtain real metrics before acquiring the DNS parent lock; never acquire
  the provider lock from inside the hook while holding the parent lock.
- Call the hook at the exact UDP `process_reply`/`do_doctor` stage after the
  existing upstream response validation. Apply address/flag/cache effects at
  that source-defined stage. Never call it on the TCP path: the C child drops
  ubus before processing TCP requests.
- On a transport error, retain the original successful DNS answer, address and
  AA; log the ubus failure, drop the service and reconnect from fresh IDs. Do not
  discard the DNS answer or increment DNS-failure metrics merely because ubus
  failed. Optional diagnostic counters must not invent new C metrics fields.
- Treat an ordinary 100 ms completion timeout as the C notification outcome,
  not a transport disconnect. A timeout can still yield a valid address.

There is a separate flags detail for integration review: the ubus rewrite clears
AA but does not set `do_doctor`'s `done` variable. C's caller clears `cache_secure`
only when that return value is nonzero; the ordinary NAT-doctor branch sets it.
This hook does not silently assume AD/secure-bit behavior from its address return.

## Response policy and byte ownership

The controller validates fields against the actual libubox rules before selecting
an address: padded attribute boundaries, extended-name header and terminal NUL,
known type IDs, exact integer widths, string terminal NUL, and the C double
minimum length. Parsing stops at a malformed preceding field, even when that
field has an unrelated name. The first matching string `address` within one
DATA message wins; validation errors after that match do not erase the retained
slot because C's callback ignores the parser return code. Non-string address
fields are not applicable.

Across DATA messages, the last applicable string wins. Invalid text or another
address family cancels a preceding valid value. DATA without an applicable
string leaves the owned selection unchanged. The selection is an `IpAddr`, not
a pointer into the transport's mutable receive buffer. No unbounded response
vector is collected.

## Explicit pending-work limit

While the owner is synchronously waiting, unrelated queued work is capped at
128 messages and 1 MiB of blob storage. One incoming frame can additionally
occupy the transport's existing bounded receive storage. Exceeding either
pending-work cap returns `OutOfMemory` and shuts down the transport; legitimate
queued calls are not silently dropped while claiming success.

This cap is a deliberate resource-failure boundary. The original C libubus does
not impose the same pending-work limit, so extreme-pressure behavior is **not
claimed C-equivalent**, nor used as a performance improvement. Full daemon
pressure and caller recovery acceptance remain open.

Linux socket-pair tests measured the queue at **128 messages / 3,072 blob bytes /
128 passed FDs**, and separately **1 message / 600,028 blob bytes / 1 passed FD**
before the next message exceeded the byte cap. All retained passed FDs were
closed on failure. These are pending-queue measurements, not whole-process
memory or FD peaks. Other tests cover interleaved Invoke/SubscribeState ordering,
multiple DATA, stale sequences, partial-frame cancellation/deadlines, EOF and
descriptor release. The existing 59 library regressions remain part of the
shared-library gate; no existing request/notify API changes semantics.

The final Linux shared-library suite passes **64/64** (59 existing plus five
notification tests). The final interleaved subscription-state assertion also
passes its focused rerun. Four controller policy tests pass on macOS; the same
four plus the existing metrics test pass on Linux. These successes do not
remove the separate one-case C behavior difference below.

## Exact C observations and remaining difference

`ubus_doctor_diff.py` completes 36 real C daemon scenarios first, then gives the
same subscriber behavior to the standalone Rust controller fixture. Expected
address/AA results come from C packets, not Rust. It covers no subscribers,
immediate/delayed/silent/disconnecting subscribers, A/AAAA/same-address/invalid
and wrong-family values, error STATUS, duplicate fields, repeated DATA, a peer
that never completes, malformed field boundaries/types/terminators, and multiple
subscribers. Additional Rust lifecycle checks cover late responses across three
successive notifications, cancellation/reconnection and stable controller FDs.

`doctor-01` retains **473/474**, exit 1. The one difference is the case where a
valid string-address DATA is followed by an address field of a different type.
Rust retains its previously parsed value; C loses the rewrite. The negative
control deliberately changes one other real expected address and reports
**472 passes / 2 failures**, exit 1. Thus the harness both preserves the known
difference and rejects an additional wrong answer; it never rewrites the
expected result to make the gate green.

The separate `--reference-lifetime` C/C diagnostic keeps the DNS query bytes,
configuration, first valid response and dependencies identical, and varies only
the later irrelevant DATA payload. Empty DATA and a short note preserve C's
rewrite, while a longer note and a non-string address field lose it. This matches
the source's retained blob-string pointer outliving the callback while later
DATA reuses receive storage. Its 35 checks confirm the reference defect; they
are not extra compatibility passes and do not change the 474-check denominator.
The Rust implementation deliberately keeps its owned parsed value rather than
reproducing receive-buffer lifetime errors.

Original C is not patched, and the discrepancy is not waived as overall
functional equivalence. No performance claim, package acceptance or production
acceptance follows from this phase. Product wiring, metrics increment/reload
snapshots, ACL, full pressure recovery and DNS proxy/AD/cache integration remain
open. The complete metrics write/reset source map is
[METRICS_SOURCE_MAP.md](METRICS_SOURCE_MAP.md).

## Evidence and reproduction

Raw results, C/Rust payloads, failures, binaries and source identities are in
ignored `private/dnsmasq-rewrite/ubus-20261001/`: `doctor-01`, `doctor-negative`,
`doctor-c-lifetime`, `doctor-ubus-unit.log` and `doctor-controller-unit.log`.
Initial macOS socket/SCM_RIGHTS deadline tests were invalid for this Linux-only
FFI and failed; the Linux tests are explicitly gated and executed on the build
host. They are not reported as macOS transport passes. Pure controller policy
tests run on both hosts.

Build the standalone fixture as documented in
[UBUS_CONTRACT_PHASE.md](UBUS_CONTRACT_PHASE.md), with the updated library and
Rust 1.98.1, then run in a new isolated directory:

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/ubus_doctor_diff.py \
  --reference-build "$EXACT_C_BUILD" \
  --c-sha256 bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431 \
  --probe private/ubus-service-probe \
  --out private/ubus-doctor
```

Use separate output directories with `--inject-error` for the negative control
or `--reference-lifetime` for the C/C diagnostic. The expected main-gate exit
remains nonzero while the documented reference difference exists.
