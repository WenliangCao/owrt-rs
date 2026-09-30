# DNS upstream reply policy phase

This phase isolates the address decisions in `forward.c::process_reply` and
`rfc1035.c::extract_addresses`. It runs only after the forwarding table has
authenticated the source, ID, question and socket. It does not choose another
server or commit cache entries.

| C source | Behaviour / invariant | Rust | Evidence |
|---|---|---|---|
| `forward.c:1241-1245`, `rfc1035.c:1419-1479` | `ignore-address` is checked over answer records before retry/delivery; a match abandons the reply without mutating it | `dns::process::process_reply`, `AddressPolicy::ignore_addresses` | `ignore_address_abandons_without_mutating_packet` |
| `forward.c:809-843`, `rfc1035.c:420-467,768-1120` | A/AAAA private, link-local, ULA, test-net and broadcast answers are blocked when `stop-dns-rebind` is enabled; localhost is controlled separately | `is_allowed_address`, `AddressPolicy::{stop_rebind,rebind_localhost_ok}` | IPv4 localhost/private and IPv6 policy unit coverage |
| `forward.c:811-821`, `rfc1035.c:1419-1499` | `bogus-nxdomain` address prefixes turn a successful answer into NXDOMAIN, clear sections and remove AA | `AddressPolicy::bogus_addresses` | `localhost_exception_and_bogus_prefix_follow_c_order` |
| `rfc1035.c:768-843` | Malformed A/AAAA RDATA is a SERVFAIL result after structural packet validation | `ProcessReport::malformed_address` | malformed-length regression |

The packet mutation is atomic with respect to structural parsing: `Message`
must parse first. On a policy block the question remains and answer,
authority, additional counts are cleared. `ignore-address` is intentionally
different and leaves the bytes untouched so the caller can retry or release
the forwarding record exactly once. Domain exceptions use canonical DNS wire
labels and are label bounded, matching `check_rebind`'s suffix ownership.

The current boundary has no UBus doctor callback, cache insertion, SOA negative
TTL extraction, DNSSEC validation or TCP fallback. Those remain separate gates;
this module must not be used to claim complete `process_reply` equivalence.
