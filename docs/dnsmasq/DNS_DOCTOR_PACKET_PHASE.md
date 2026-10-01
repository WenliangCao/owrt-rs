# DNS doctor packet primitive and exact C boundary

This phase implements `dns::doctor::apply`; it does not wire main/Daemon,
enable alias/ubus CLI options, or declare complete C equivalence. The packet
gate is **36 matched / 2 explicit safe-boundary differences / 38 total** and
retains its nonzero exit. Those differences are not normalized away.

## Source contract and API

The unchanged patched reference is `rfc1035.c:512-591` (`do_doctor`), called
from `forward.c:806` before bogus-address policy and `extract_addresses`.
The reference `rfc1035.c` SHA256 is
`231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222`.

```rust
doctor::apply(packet, aliases, notify) -> DoctorOutcome
```

The packet is borrowed mutably; its length never changes. `aliases` contains
already-validated IPv4 `Alias { from, end, to, mask }` values in evaluation
order. C prepends aliases in `option.c:4875-4907`, so later configuration
declarations come first. The mask is an arbitrary IPv4 bit mask, not necessarily
a CIDR prefix. A zero end uses masked-network matching; a nonzero end uses the
inclusive range. A matching rule preserves unmasked address bits and replaces
masked bits, then stops. Even a no-op match clears AA and invalidates cache
security, matching C.

The optional borrowed callback receives dnsmasq-escaped **name bytes**, raw u32
TTL and an owned `IpAddr`, returning `Option<IpAddr>`. Binary owner labels,
case and dnsmasq's internal escaping survive; no UTF-8 replacement occurs.
Wrong-family replacements are ignored. A successful same-family callback clears
AA even when the replacement equals the original address. TTL and other flags
are untouched by this primitive.

For each IN A/AAAA record, ubus callback rewriting occurs **before** static
IPv4 alias matching. The alias therefore sees the replacement address. AAAA
has no static-alias stage. Non-IN records and other types do not notify.
Answer records are visited in order, Authority is skipped with C's skipping
semantics, and Additional records follow in order. The RR owner is decoded,
not substituted with the original question name. A malformed later record can
stop traversal after earlier notifications and changes have already happened.

`DoctorOutcome` exposes completed static rewrites, ubus rewrites and notification
counts, `clear_cache_secure`, and an optional `stopped` wire error. The result is
not an atomic transaction: earlier effects remain in the packet on failure.
The owned callback return avoids borrowing mutable transport receive storage.
The separate cross-DATA lifetime defect and its retained gate are documented in
[UBUS_DOCTOR_PHASE.md](UBUS_DOCTOR_PHASE.md).

## Required integration position

| Stage | Required ownership/order |
| --- | --- |
| Authentication and ignore-address | Match the upstream transaction and perform the existing pre-completion ignore check first. |
| Envelope/local-domain handling | C normalizes EDNS/AD/RA and handles locally known NXDOMAIN before doctor. Eligibility requires QUERY opcode, NOERROR/NXDOMAIN, no TC, and the C bogus-validation/CD condition. This primitive does not reimplement that caller gate. |
| Doctor | Run once on the eligible common upstream response if aliases or subscribers exist. Pass the callback for UDP; pass `None` for TCP, whose C child dropped ubus. |
| Address policy and cache | Bogus wildcard, rebind/malformed-address handling and cache insertion must inspect the doctor output. Preserve the source's separate `cache_secure` decision. |
| Client delivery | Apply recipient envelope/ID/size work afterward. Do not notify once per merged client, or walk local/cached answers again. |

The current `process.rs` combines address-policy stages; its eventual owner must
place this hook before those stages rather than attach it to the final client
reply. No `process.rs`, main or Daemon change is part of this commit. Ubus transport
errors belong to the callback owner: log/drop/reconnect as specified by the
controller phase, return `None`, and allow the original address's static-alias
stage to continue. Do not turn an ubus failure into a lost DNS answer.

## Exact C differential and retained differences

`doctor_packet_driver.c` links unchanged exact `rfc1035.o` and the other audited
native reference objects. It replaces only the ubus transport dependency with a
deterministic callback fixture using the matching libubox. The actual C-generated
name/TTL/type/address payload is observed, and the specified single-DATA response
remains alive until C consumes it. This is not another ubusd transport test;
the real-bus controller gate remains separate.

Linker wrappers observe `log_query` and `inet_pton` while still calling their real
implementations, so completed static/ubus changes are counted without modifying
`do_doctor`. Rust receives the exact alias values/order parsed by C. This checks
the packet primitive and does not claim a Rust alias configuration parser.

The 38 cases include mixed Answer/Authority/Additional sections, compressed
owners, binary labels, unknown record types, non-IN records, all important u32
TTL boundaries, same/invalid/wrong-family callback results, callback-before-alias
ordering, overlapping aliases, first-match termination, inclusive ranges,
noncontiguous/zero masks, no-callback static handling, authority skipping,
extended RDATA, and partial malformed inputs.

Two deliberate differences remain visible:

1. C reads an A address using packet bounds even when its declared RDLEN is
   shorter than four bytes. With another RR following, it can notify using bytes
   from that RR and overwrite them. Rust checks both packet and declared RDATA
   bounds, stops without that notification, and preserves the following record.
2. After an earlier static rewrite, C's short-AAAA branch returns zero and loses
   its prior `done` state. Rust retains the completed static effect and
   `clear_cache_secure=true`, while reporting truncation. No earlier effects are
   rolled back.

The positive corpus is **36 pass / 2 differences**, exit 1. Negative calibration
changes one previously matching C return expectation and reports **35 pass /
3 differences**, exit 1. Original C output is retained unchanged. A nonzero gate
does not establish complete functional equivalence; these source defects are
not reproduced to make the comparator green.

Four unit tests pass on both macOS and Linux, including an additional bounded
4,096-input parser screen (lengths 0–255 with deterministic bytes), header/length
preservation, refusal to cross short RDATA, and retention of earlier effects.
That bounded screen is not an exhaustive fuzzing or safety proof.

## Cost and evidence limits

The packet is changed in place. Traversal is linear in visited records plus
name decompression work; each IPv4 address scans aliases until the first match,
as C does. This is not an algorithmic performance improvement claim. The current
implementation allocates decoded/escaped name storage per visited record; it
does not yet reuse C-style name scratch storage. No throughput, CPU, whole-process
memory or router performance result is claimed.

Raw inputs, alias configurations, exact event traces, packets, failures, build
logs, binaries and identities are in ignored
`private/dnsmasq-rewrite/doctor-packet-20261001/`. Reproduce on the Linux build host:

```sh
python3 tools/dnsmasq/doctor_packet_diff.py \
  --reference-build "$EXACT_C_BUILD" \
  --cargo "$PINNED_CARGO" \
  --out private/doctor-packet
```

Use `--inject-error` with a fresh directory for the negative control. The main
gate intentionally remains nonzero while the two safe-boundary differences are
retained. Real product reply placement, recipient coalescing, TCP/static-alias
integration, alias CLI semantics and cache/AD interaction still require their
own combined gate.
