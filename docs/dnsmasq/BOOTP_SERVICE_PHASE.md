# Ordinary BOOTP address and lease service

The existing ordinary BOOTP path is connected through configuration,
`LocalProvider`, `StateProvider`, runtime reply construction and the main DHCP
listener. The broader service gate now matches exact C in **9 scenarios / 25
ordered events**, including packets, lease files and immediately visible DNS.
No main wiring change was needed for this slice.

The first paired run found two real differences: an empty DHCP parameter
request list in a BOOTP vendor area made Rust omit the default router and DNS
server options. C's BOOTP branch passes `req_options=NULL` to `do_options`, so
those options remain eligible. The runtime now applies that same BOOTP rule.
The before/after results are 23/25 and 25/25 matches respectively. A retained
runtime regression checks the actual reply builder/send path with empty PRL.

The service corpus covers:

- A configured static MAC/name, finite lease duration, broadcast and unicast
  same-MAC retry, empty PRL and preservation of a non-RFC1048 cookie.
- Unknown static MAC rejection and client-ID-only configuration not granting
  BOOTP address authorization.
- Tagless `bootp-dynamic`, repeated allocation lookup, multiple clients,
  lease-capacity refusal and subsequent same-MAC success.
- An already occupied fixed address and refusal to steal a shared configured
  address from a different MAC, while the original MAC remains serviceable.
- Startup restoration, conversion of a finite dynamic lease to BOOTP's
  infinite lifetime, retention of the restored name, and client hostname/FQDN
  data being ignored on BOOTP.
- Committed files and short/FQDN/PTR DNS observations immediately after the
  client receives a reply; release removes the committed name/address data.
- Missing hardware and disabled dynamic permission producing no response.

The initial source review suspected client-name handling, but the real paired
trace and `Packet::client_hostname_full` showed that BOOTP already returns
before that parsing. No redundant name-policy change was made. Replies are
exactly 300 bytes without DHCP message type/timer options; all returned bytes,
including cookie, header and vendor order, are compared directly. Only finite
lease-file expiry timestamps are normalized, after checking them against the
actual request/reply interval and the configured 900-second duration. DNS TTL,
flags, address selection and record order remain significant.

All C runs precede their Rust counterparts with identical configuration
contents and concrete input packets. The C baseline freezes each scenario's
event/reply count: 25 events yield 16 BOOTP replies and nine expected no-reply
events. A deliberately removed observed Rust reply produces 24 matches, one
mismatch and exit 1 on the same 25-event schedule. All 18 daemon processes in
the ordinary paired gate exit zero and are reaped. The test runs only in an
isolated loopback namespace and uses private lease files.

The `bootp` producer remains covered by the independently executed full-C
message-counter gate in [METRICS_DHCP_MESSAGE_PHASE.md](METRICS_DHCP_MESSAGE_PHASE.md).
The main executable does not yet publish that owner through a live ubus metrics
endpoint. This service gate does not manufacture a counter from packet counts
or claim that the publication gap is closed.

Tag predicates, `dhcp-boot` file/server-name/next-server configuration, PXE,
relay and leasequery remain explicitly staged capabilities. Unsupported
configuration still fails; it is not silently ignored. In particular, this
address/lease service result is not complete PXE or network-boot acceptance.

Evidence is in ignored `private/dnsmasq-rewrite/bootp-service-20261001/`:
`c-baseline-01/`, `pair-before-01/`, `pair-after-01/`, `calibration-01/` and
`freeze-after-01/`. The latter contains the exact source archive/manifest,
native Rust 1.98.1 build log and recovered ELF. Source-manifest SHA-256:
`9bd0c42f03e6fc6bb8721530146c3063d4bb94ebbe1e22590d5a41e7f6558d26`.
Rust ELF SHA-256:
`bc9b58eae28df654d11d22d4b0758bb551f2b696955e4e0b3280297e913c2f7f`.
C uses the audited native ELF
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
The 15 runtime regressions and Linux-musl all-target Clippy pass. No router,
performance improvement or production acceptance is claimed.
