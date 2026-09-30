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
| `rfc2131.c:1486,2751-2783,2882-2891` | Finite OFFER/ACK leases receive T1/T2 from their actual lease duration; configured values require `2 < value < lease`, apply C's timer ordering rule, and subtract the same bounded renewal fuzz; timer options are excluded from the ordinary option loop | `append_lease_timers`, `build_reply_with_fuzz` | Hash-pinned C timer block with identical injected fuzz; duration/override/infinite/INFORM regressions |

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
Complete `do_options`, configured option request-list/tag filtering,
agent-id relocation, FQDN/PXE options, relay destination selection, and lease
file/DNS/script side effects still belong to their respective caller phases.
The current tests prove the wire mutation and bounded placement invariants only;
they are not a full listener, relay, or OpenWrt integration acceptance.

`tools/dnsmasq/dhcp_reply_diff.py` compiles the hash-pinned C helper and runs
the Rust `dhcp_reply_probe`. The earlier deterministic run covered 1,008 cases
(primary placement, file/sname overload, absent/present PRL, OFFER, ACK,
INFORM and NAK including broken-string handling) with zero semantic
mismatches. Generated C, input and result files stay under ignored
`private/dnsmasq-rewrite/dhcp-reply-diff/`.

The timer extension uses `build_reply_with_fuzz(request, reply, options,
allow_overload, fuzz, output)`. The existing builder wrappers supply zero fuzz
for deterministic wire construction; the runtime injects entropy for ACKs to
REQUESTs without option 50 (renewal/rebinding). OFFER, SELECTING, INIT-REBOOT
and rapid commit use zero fuzz. INFORM never receives T1/T2, even when its
explicitly requested remaining lease time is present. Infinite leases omit
both timers. A supplied option 58/59 is a selected four-byte configuration
override; malformed lengths return `InvalidOption` before output mutation.
BOOTP retains its separate raw vendor-option serializer.

The new C helper extracts the timer block verbatim from `rfc2131.c` (SHA256
`14f2e10792ef6108aeb7b69e551f089ba287c8c84d39ea178a5f33acd2038c2c`). Both
sides receive identical selected options, actual lease time and 16-bit fuzz.
The test preserves C's defined unsigned arithmetic, including multiplication
and subtraction wraparound at very large/small synthetic lease durations.
It does not normalize the resulting timer values or generate expected bytes
from Rust. Counter calibration detects mismatches and missing/extra output;
the initial C OFFER independently pins a 600-second lease to T1=300/T2=525.

The final run passed **1,284/1,284** whole-wire comparisons, with C ASan/UBSan.
It includes 276 directed timer/caller boundaries beyond the earlier fixed
cases and 1,000 seeded randomized cases. Inputs, all outputs, generated C and
artifact SHA256 values are under ignored
`private/dnsmasq-rewrite/dhcp-timers-20260930/run-02/`; `run-01` is retained.
This remains a wire/timer oracle, not full `do_options` or service equivalence.
