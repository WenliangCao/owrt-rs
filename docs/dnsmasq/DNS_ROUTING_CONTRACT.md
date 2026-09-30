# DNS domain rule contract

This contract records the local answer routing that was checked against the
patched dnsmasq 2.93 source. It covers only the configured local boundary; it
does not imply that the Rust daemon has an upstream dispatcher.

| C source | Behavior and invariant | Rust implementation | Evidence |
|---|---|---|---|
| `domain-match.c:106-237,480-529` | Search the full name and then shorter right hand suffixes. Matching is ASCII case-insensitive. A `*example.test` rule is a character suffix; `*.example.test` keeps the leading dot and requires a label boundary. | `dns/local.rs::matches_domain`, `pattern_score`; `config/dns.rs::pattern` retains `wildcard_dot` | `routing-review/{wild,wild-dot,wild-specific}.conf`; 72 C/Rust semantic cases, zero mismatch |
| `domain-match.c:284-377,511-590` | At one suffix choose IPv6 literals, IPv4 literals, zero addresses, local-only, resolver and upstream in that order. If a requested family is absent, continue with the next shorter suffix. ANY receives only the highest applicable family tier. | `dns/local.rs::select_local_rules` | `fallback`, `families`, `v6zero`, `conflict`, `miss-parent-local`, `local-prio` fixtures; zero mismatch |
| `rfc1035.c:1730-1840`, `forward.c:346-358,592-625` | Configured/cache records are attempted before domain rules. A CNAME owns its alias and suppresses alias address records/rules; the target may be absent and still yields a CNAME-only response. | `LocalAnswerer::answer`, `add_cname_chain`; local rows gate rule selection | `answer.conf` CNAME matrix; local CNAME/address regression |
| `rfc1035.c:1302-1337`, `domain-match.c:is_local_answer` | Non-IN classes do not receive IN records, but local-only domain selection still returns NXDOMAIN or empty NOERROR, including ANY/CHAOS. | `LocalAnswerer::answer` separates `class_in` from local-only rule selection | `class-local` and `class-child`; 48 semantic cases, zero mismatch |

The exact C driver, configurations, query corpus, semantic result files and
object/source identities remain under ignored
`private/dnsmasq-rewrite/local-c-audit-20260930/`. The comparison preserves
ID, flags, question, section order, owner/type/class/TTL and decoded RDATA; it
does not compare compression pointer spelling.

DS/DNSKEY parent-domain routing is represented by the C contract
(`extract_request` marks `F_DS`, then `lookup_domain` strips the first label).
The current nodhcpv6/no-DNSSEC-validation local service does not synthesize
DNSSEC records or forward queries, so this remains an upstream dispatcher
responsibility and is not claimed as a completed daemon feature.
