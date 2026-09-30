# DHCPv4 reply-wire phase

This phase adds a socket-independent wire boundary.  It consumes a selected
`dhcp::state::Outcome` and a caller-owned list of already selected options; it
does not choose interfaces, contexts, tags, destinations, or lease side
effects.  It is therefore reviewable and testable without binding a DHCP
socket.

| Exact C source | Behaviour / invariant | Rust implementation | Evidence |
|---|---|---|---|
| `rfc2131.c:2559-2566` (`clear_packet`) | Preserve the fixed BOOTP header, change `op` to `BOOTREPLY`, clear `sname`, `file`, options after the cookie and `siaddr`; later logic sets `yiaddr` and flags | `dhcp::reply::build_reply` | Header/next-server regression test |
| `rfc2131.c:940-956,1382-1389,1574-1581,1742-1751,1797-1820` | OFFER/ACK/NAK/INFORM mandatory message type, server identifier, lease time, rapid commit, and NAK message; broadcast NAK clears `ciaddr`; NAK does not invoke `do_options` | `append_mandatory`, header field writes and NAK option suppression | Focused reply tests plus C differential |
| `rfc2131.c:2074-2129` (`free_space`, `dhcp_packet_size`) | Strict `p + len + 3 < end` fit check; when `do_options` leaves file/sname available (a parameter-request-list is present), reserve overload option; try `file` then `sname`; skip and count options with no space; write `END`; final length at least `MIN_PACKETSZ` (300) | `OptionWriter` | Primary/file/sname overflow test; absent-PRL test; omitted count and overload bits checked |
| `rfc2131.c:565-697` | BOOTP uses a 64-byte vend area, cookie/TLV/END and no DHCP option 53 | `build_reply` BOOTP path + `packet::encode_bootp_vendor` | Cookie/vendor fixed-length test; serializer differential is recorded in `DHCP_SOURCE_MAP.md` |
| `rfc2131.c:138-151` | Option 57 includes IP/UDP headers; response buffer is bounded to 548..16384 | `Packet::response_capacity` and `ReplyError::BufferTooSmall` | Advertised 1500-byte capacity boundary test |

The explicit interface is:

```rust
build_outcome(packet, &outcome, selected_options, output)
    -> Result<ReplyEncoding, ReplyError>
```

Callers that have already evaluated `--dhcp-no-override` may call
`build_reply_with_overload(..., allow_overload, output)` to pass that policy
explicitly; the convenience `build_reply` follows the ordinary PRL-based
default.

`ReplyEncoding` reports the send length, omitted option count and DHCP
overload bits.  `Reply::Ignore` returns `NoReply`; a short destination buffer
returns `BufferTooSmall` before mutating it.  DHCP option 0/255/52 and duplicate
mandatory options are rejected at this boundary.  BOOTP option 0/255 follows
the existing vendor serializer rules.

The C `borken_opt` compatibility bit is preserved for NAK text. Option 81
has priority over option 12; a trailing NUL in the unencoded FQDN/hostname
causes the NAK message option to include a trailing NUL, while an encoded FQDN
does not. This is the historical client workaround in
`rfc2131.c:730-765,1576`, not a general string policy.

The phase intentionally does not claim complete `dhcp_reply()` compatibility.
`do_options`, option request-list filtering, T1/T2 and subnet/router options,
agent-id relocation, FQDN/PXE options, relay destination selection, and lease
file/DNS/script side effects still belong to their respective caller phases.
The current tests prove the wire mutation and bounded placement invariants only;
they are not a full listener, relay, or OpenWrt integration acceptance.

`tools/dnsmasq/dhcp_reply_diff.py` compiles the hash-pinned C helper and runs
the Rust `dhcp_reply_probe`. The current deterministic run covers 1,008 cases
(primary placement, file/sname overload, absent/present PRL, OFFER, ACK,
INFORM and NAK including broken-string handling) with zero semantic
mismatches. Generated C, input and result files stay under ignored
`private/dnsmasq-rewrite/dhcp-reply-diff/`.
