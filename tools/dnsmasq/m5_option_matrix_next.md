# Option matrix next batch: source checklist

Status: planned, not executed, no option closed by this file. Reuse
`m5_option_matrix.py`; add probe adapters only. Runtime changes go to the root
agent. Exact-image C supplies expected observations. The current matrix's
`no-0x20-encode` and `listen-address` defaults must be removed from the relevant
profiles: retaining either would disable the behavior being tested.

Reference: matching dnsmasq 2.93 OpenWrt source already identified in the matrix
manifest. Line numbers below refer to that source. Raw results remain in
`private/dnsmasq-rewrite/evidence/M5/option-matrix/`.

## do-0x20-encode and no-0x20-encode

C: option.c:609–610; forward.c:268–320, 391–395, 1292, 1323–1340,
1457–1518, 3232–3276; rfc1035.c:extract_name. Rust consumers exist in
config/dns.rs and dns/forward.rs. No runtime gap identified in this source read.

- [ ] Compare absent/do/no/both flags in each order, repeat flags, and rejected
  unexpected arguments; compare syntax and actual startup diagnostic streams.
- [ ] For UDP, record raw outbound question casing. `do && !no` randomizes only
  the first 32 alphabetic characters; digit, hyphen and label separator positions
  do not consume bits. Check short and more-than-64-letter mixed-case names.
- [ ] Do not compare random bit patterns or random IDs exactly. Require C and
  Rust to obey the same enabled/disabled rules and collect 64 independent
  requests so a disabled RNG path cannot pass an enabled profile.
- [ ] Reply with exact echoed question; then with exactly one alphabetic case
  bit flipped. Enabled UDP must reject the second response and accept a later
  correctly cased one. Disabled UDP follows C's case-insensitive lookup.
- [ ] Compare exact client question bytes, including original mixed case.
  Coalesce two clients whose letter-case difference occurs after letter 32 and
  after letter 64; both receive their own original question case and ID.
- [ ] Exercise TCP separately; its forwarding path does not use the UDP frec
  encoding step. Record the observed C behavior rather than imposing UDP rules.
- [ ] Controls: force no outbound case changes in enabled mode; mutate restored
  client case; accept an incorrect-case response; delete an observation.

## fast-dns-retry

C: option.c:3552–3575; forward.c:472–489, 628–670, 3204;
dnsmasq.c:1103. Rust ScalarConfig/FastRetry and ForwardTable retry deadlines are
connected. Reuse the stimuli from `dns_retry_failure_diff.py`, not its native C
execution wrapper.

- [ ] Syntax/startup: absent, bare flag, `50`, `50,0`, `50,999`, `50,1000`,
  `50,1999`; reject `49`, nonnumeric fields and extra fields. Check exact output.
- [ ] Blackhole one upstream: first send then exponential retry intervals;
  timeout milliseconds truncate to seconds. Compare C-derived event counts and
  ordering; retain actual timestamps and use explicit bounded scheduler jitter.
- [ ] A successful reply cancels further retries; timeout stops retries.
  A subsecond timeout performs no timer retries after truncation to zero.
- [ ] Retry send failure does not leak a forward slot; recovered transport can
  answer later queries. Observe upstream selection under strict order and the
  normal selection mode, with the same source-derived fixture for each side.
- [ ] DNS local UDP/TCP queries remain responsive while a retry is pending.
- [ ] Controls: suppress a retry, leave retries active after success, mutate the
  interval sequence, omit a deadline observation.

Known common diagnostic gap from static read: Rust scalar errors currently say
`retry interval below 50 ms` / `bad integer`; C uses its generic `error`. Keep
these rows failing until the root agent fixes the shared diagnostic boundary.

## max-tcp-connections

C: option.c:5453–5462 (zero rejected); dnsmasq.c:1901–1915, 1994–2008,
1631–1650 (slot requires both child exit and pipe EOF). Rust's shared owner
already consumes max_tcp_connections. Reuse the schedule from
`dns_tcp_capacity_diff.py`; execute both daemons in the exact image with `-k`.

- [ ] Syntax/startup: one, two and zero; zero must fail rather than become an
  unlimited or disabled TCP service. Retain invalid-number diagnostics.
- [ ] Fill all slots with idle clients, then connect/send an additional client.
  The extra request waits in the kernel accept queue and receives no response
  until a slot is released; it is not reset or rejected prematurely.
- [ ] Close one client and observe queued-client admission and reply. Repeat
  through both listener addresses so the limit is global rather than per socket.
- [ ] Keep UDP queries successful during TCP saturation, repeat fill/drain, and
  check child/socket/PID cleanup on shutdown. Use UDP readiness so readiness
  itself does not temporarily consume a TCP slot.
- [ ] Controls: serve the excess client early, drop its eventual response,
  report per-listener capacity, retain a child after shutdown.

Known common diagnostic gap: Rust rejects zero with `max-tcp-connections must
be positive`; C uses generic `error`. This is not evidence of a runtime gap.

## local-service

C: option.c:3485–3492 and 6309–6321; network.c:271; forward.c:1685–1725,
2416–2450. Rust config finalization and ingress policy consumers already exist.

- [ ] Syntax/startup: absent, no argument, `net`, `host`, invalid value. Preserve
  exact diagnostic streams; Rust's static `bad local-service` differs from C's
  generic `error` and must remain visible until corrected.
- [ ] With no explicit interface/listen-address ACL, `net` admits only directly
  connected source subnets. Test local and routed non-local IPv4/IPv6 clients,
  each through UDP and TCP, using veths inside this family's private namespace.
- [ ] `host` creates loopback-only binding equivalent to C's interface=lo plus
  bind-interfaces; check both address families and non-loopback destination.
- [ ] Explicit interface, except-interface or listen-address configuration
  disables local-service restrictions; cover each override independently.
- [ ] Check source subnet boundaries and distinguish source admission from
  destination listener presence. Namespace route setup and interface deletion
  must be recorded and cleaned up without touching the host network.
- [ ] Controls: invert one admission decision, retain local-service despite an
  explicit ACL, delete one IPv6 or TCP observation.

This batch qualifies five options only after all their checked rows pass. Do not
include reverse-cache, max-ttl, EDNS identity mutation, dynamic-file or other
known functionality gaps merely to increase the matrix's option count.
