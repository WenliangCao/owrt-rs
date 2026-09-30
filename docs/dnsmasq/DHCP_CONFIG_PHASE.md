# DHCPv4 range configuration contract

The exact patched `option.c:3747–4005` and `config.h:51` define this parser
boundary. A driver linked to the verified native C objects calls real
`read_opts()` and prints the resulting context list; it opens no listener.
`tools/dnsmasq/dhcp_config_diff.py` compares that state against the Rust
`DhcpConfig` parser. Rust does not generate expected values.

The 2026-09-30 C-only baseline contained 90 inputs: 70 accepted and 20 rejected.
These counts were frozen before the final differential gate. Of those inputs,
84 belong to the implemented dynamic IPv4 range contract and match in acceptance
and every printed field (64 accepted, 20 rejected). Six C-supported forms remain
explicit Rust rejections and are separate checked boundaries, not equivalence
passes. Comparator calibration detects both a changed state value and a changed
accept/reject result. Six Rust regression tests pass.

| Exact C behavior | Rust change and regression scope |
| --- | --- |
| Reversed start/end addresses are swapped | Normalize instead of rejecting; preserve equal endpoints |
| Missing mask has no `CONTEXT_NETMASK`; runtime derives it | Represent as `None`, distinct from explicit `0.0.0.0`; remove invented `/24` |
| Optional fourth address is broadcast | Separate `broadcast: Option<Ipv4Addr>`; remove incorrect router field and value-based field counting |
| Optional fifth field is lease duration | Accept start/end/mask/broadcast/duration together |
| Explicit mask must place both endpoints on the same network | Compare masked addresses; do not invent a contiguity check absent from C |
| Default `DEFLEASE` is 3600 seconds | Fix previous 43200-second default |
| Explicit finite durations below 120 become 120 | Cover zero, one, 119, 120, 121 and minute boundaries |
| `s/m/h/d/w` accept both cases; a bare suffix parses as zero | Preserve C behavior and the 120-second floor |
| `infinite` is `u32::MAX`; an empty trailing field retains the default | Preserve `lease_time_explicit` / `CONTEXT_SETLEASE` separately |
| New contexts prepend to the linked list | Store ranges in C traversal order; compare ordered output |
| Quoted metacharacters remain hidden in this parser branch | Reject quoted numeric/address forms as C does |

`RangeConfig.netmask`, `broadcast`, `lease_time` and `lease_time_explicit` are
parsed state, not a substitute for serving-interface discovery or DHCP option
construction. This phase does not establish packet-level mask/broadcast/router
selection, lease persistence, or listener correctness.

The six known unsupported forms are `tag:`, `set:`, a legacy tag, `static`,
`proxy`, and `deprecated`. Their rejection is checked explicitly so a future
parser cannot silently discard their meaning. They remain functional coverage
gaps. DHCPv6 range syntax is rejected by both sides of this nodhcpv6 variant.
Finite durations that overflow C's signed `int` arithmetic have no defined C
arithmetic expectation here; Rust rejects them, and they are excluded from the
differential denominator. This phase makes no performance claim.

```sh
python3 tools/dnsmasq/dhcp_config_diff.py \
  --source "$REFERENCE_SOURCE" \
  --reference-build "$REFERENCE_BUILD" \
  --out private/dnsmasq-rewrite/dhcp-config-diff
cargo test --manifest-path components/dnsmasq/Cargo.toml --lib config::dhcp::tests
```

Both source and build copies of `option.c` are hash-pinned to
`bdcd4c532b66560fb2b197470fe7ebbfe387d4ab3cd5372932591ce260e30bed`.
The parent native reference audit is described in `REFERENCE_AUDIT.md`.
Ignored `private/dnsmasq-rewrite/dhcp-config-20260930/` retains the `c-only`,
`diff-01` and final `diff-02` runs, configuration inputs, both processes' stdout
and stderr, binaries, exit statuses and parser identity. `diff-02/result.json`
is the final state comparison. The tool reports `full_functional_equivalence:
false` even when its covered contract and unsupported-boundary checks pass.
