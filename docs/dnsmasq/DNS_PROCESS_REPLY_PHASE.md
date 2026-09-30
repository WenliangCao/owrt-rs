# DNS upstream reply policy phase

This phase implements the bounded address decisions that happen after
`reply_query()` has authenticated the upstream source, ID, question and
socket. It does not claim the complete `forward.c::process_reply` contract.

| C source | Behaviour / invariant | Rust boundary |
|---|---|---|
| `forward.c:1241-1245` | `ignore-address` is checked before TC/opcode/error handling, but only when the low header RCODE is `NOERROR`. A match leaves the forwarding record and packet untouched. | `ignore_reply` predicate; the transport must call it before `complete_reply` |
| `forward.c:778-845`, `rfc1035.c:793-1081` | Rebind/bogus address handling runs only for QUERY, extended RCODE NOERROR/NXDOMAIN, and a non-TC reply. Rebind follows the queried IN A/AAAA owner through matching CNAMEs; ANY and unrelated owners/types are not rebind checks. | `process_reply`, `extract_address_policy` |
| `rfc1035.c:426-467` | Private IPv4/IPv6 ranges, including all `0.0.0.0/8` when localhost is banned, mapped IPv4, link-local, site-local, ULA and documentation ranges are blocked. | `is_allowed_address` |
| `rfc1035.c:1419-1479` | `bogus-nxdomain` and `ignore-address` scan every IN A/AAAA answer, independent of the question name/type. Bogus runs before rebind and clears sections with NXDOMAIN/AA clear. | `scan_bad_addresses` |
| `rfc1035.c:1068-1074` | Address reads require four/sixteen bytes remaining in the packet, not an exact RDLEN. Short RDLEN can consume bytes from the following record; oversized RDLEN is accepted. | bounded `packet_address` reads |
| `rfc1035.c:395-416` | Clearing sections restores the retained last OPT and `arcount=1`; an unsigned daemon-added OPT removed earlier is not restored. | section clear in `process_reply` preserves the last OPT |

`process_reply` is intentionally limited to the address-policy mutation. It
does not perform local NXDOMAIN conversion, cache/SOA insertion, DNSSEC
validation, RR filtering, doctor/UBus rewrites, EDE construction, TCP fallback,
or transaction retry/release. `ignore_reply` must run before the transport
marks a query complete; calling `process_reply` after completion cannot emulate
C's pending transaction boundary.

The exact-source differential tool is
`tools/dnsmasq/dns_process_diff.py`. It pins the reference `rfc1035.c` hash,
compiles the C `private_net`/`private_net6` functions with sanitizers, and
compares generated matching A/AAAA replies against the Rust policy path. Its
outputs belong under ignored `private/`; the tool reports its narrow scope and
does not treat that check as daemon or full `process_reply` equivalence.
