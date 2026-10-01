# Static DNS alias configuration contract

`DnsConfig` now parses `alias` into `Vec<AliasConfig>`. The vector is already
**newest declaration first**, matching C's `daemon->doctors` chain. Its four
fields (`from`, `end`, `to`, `mask`) copy directly into `dns::doctor::Alias`.
The consumer must not reverse, deduplicate or normalize the rules again.

At the parser milestone, DNS-enabled runtime was explicitly gated by
`validate_ready`, while `finalize`/CLI `--test` could validate syntax. That guard
was removed after the [static alias service gate](DNS_ALIAS_SERVICE_PHASE.md)
connected and compared the real upstream consumer. As in C, a disabled DNS port
gives this DNS-only option no execution semantics; no extra `port=0` rejection
was added. This configuration phase alone does not establish service
integration or performance improvement.

| Exact C reference | Preserved behavior |
|---|---|
| `option.c:4871-4880` | Prepend each rule; default mask is all ones and default end is zero. Duplicate or overlapping rules remain distinct and preserve priority. |
| `option.c:4882-4891` | Split the first comma while preserving the encoded first field. Unhide the remaining text before splitting target/mask. Configuration-file quoting is therefore asymmetric: a quoted source address fails, whereas quoted target/mask can succeed, and a quoted comma in the tail becomes a separator. |
| `option.c:4893-4895` | Source, target and optional mask must be strict dotted IPv4 addresses. Missing fields, IPv6, shorthand/leading-zero addresses, prefix-length syntax and extra fields fail with exit 1. Masks need not be contiguous. |
| `option.c:4897-4901` | A written range must have valid endpoints, start ≤ end and equal masked networks. With the default all-ones mask only a one-address range satisfies that condition. |
| `rfc1035.c:549-567` | End zero selects masked-network matching; nonzero end selects the inclusive numeric range. Rewrite preserves original unmasked bits and target masked bits. The first match wins and stops; no cascade occurs. A match clears AA and marks static rewriting even if the address bytes stay unchanged. |

The parser retains source/target host bits and C's zero-end sentinel exactly.
An explicit zero-to-zero range with zero mask therefore retains the C masked
matching behavior; it is not converted into a distinct range enum. A
noncontiguous-mask range can include intervening addresses outside the endpoints'
masked network, because runtime range matching compares endpoints only.

## Evidence

`tools/dnsmasq/dns_alias_config_diff.py` links the matching native C objects and
calls their real `read_opts`. It prints every parsed doctor field in list order,
then runs complete single-A packets through actual `do_doctor`. The Rust probe
uses the typed configuration and existing doctor primitive; it does not supply
expected outputs. Both sides separately run `--test`; runtime readiness is a
separate Rust boundary check.

Generated configuration, source drivers, the tool's argument corpus, executables
and raw observations remain in ignored
`private/dnsmasq-rewrite/dns-alias-config-20261001/`:

- `c-baseline-01/`: **72 C cases**, **34 accepted / 38 rejected**, 22 address
  queries for each accepted case. These counts precede the Rust comparison.
- `diff-01/`, `diff-02/`: **72/72 matching state/CLI cases**, including **748
  doctor observations**. Rule fields/order, result address, rewrite status,
  complete header flags and unchanged TTL compare exactly. No sorting or
  reply-order normalization is used.
- `diff-02/`: all **33 accepted configurations containing aliases** also fail
  the explicit unconnected-consumer runtime guard; the empty configuration
  passes. These refusals are not counted as C runtime compatibility.
- `calibration-01/`: changing one parsed target address in decoded Rust output
  gives **71 matches / 1 failure**, exit 1. The original bytes remain intact.
  Independent C calibrations fix default all-ones masking, no-rule identity,
  newest-first selection, non-cascading rewrite, zero-end/zero-mask matching,
  unchanged TTL and total output count.

The corpus includes CLI long/short forms, repeated CLI options, main-file versus
CLI ordering, point/network/range boundaries, duplicate/overlapping rules,
arbitrary masks, empty/extra fields, whitespace/comments and quoted-field cases.
Configuration-DNS unit tests and library clippy passed. The parser milestone's
unit checked the unconnected guard; the current unit retains evaluation-order
checks and expects readiness after the service consumer was connected.

The C source hashes cover `option.c`, `rfc1035.c`, `dnsmasq.h`, `util.c` and the
validated target feature header. No listener or ubus connection was started,
and no physical router was accessed. Full Answer/Additional traversal and ubus
interaction remain in the existing doctor contract; this unit supplies its
validated rule sequence, not a new packet algorithm. The later service phase
preserves these parser/primitive observations and separately establishes its
consumer evidence. The tool defaults to expecting connected runtime readiness;
`--expect-runtime-alias-rejection` reproduces the old guard assertion against
the historical parser-only source.
