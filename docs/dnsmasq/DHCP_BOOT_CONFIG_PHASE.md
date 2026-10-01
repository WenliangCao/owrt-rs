# Ordinary DHCP boot metadata

The untagged `dhcp-boot` filename/server-name/IPv4 subset now reaches both the
ordinary DHCP and BOOTP listener paths. `dhcp-no-override` is wired to the same
serializer. This is a functional stage, with no performance or production
acceptance claim.

The reference is the exact patched dnsmasq 2.93 implementation used by the
OpenWrt 25.12.5 nodhcpv6 image. `option.c:4347–4393`, `rfc2131.c:2567–2584`
and `rfc2131.c:2668–2750` define configuration order, boot selection, option
placement and overload availability. The native reference ELF SHA-256 is
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.

| Contract | Implementation / observed evidence |
| --- | --- |
| Last untagged directive wins; empty fields; quoted commas | Typed `BootConfig`, actual C config/service comparison |
| DHCP without PRL, empty PRL, 66 only, 67 only, both | C fixed fields versus explicitly requested 66/67, with terminating NUL except length 255 |
| BOOTP, including PRL and non-RFC cookie | Fixed fields, original cookie, 300-byte response, no DHCP type or timers |
| IPv4 next-server, absent/zero fallback | Explicit nonzero IPv4 overrides selected context; zero keeps context local address |
| `dhcp-no-override` | Fixed fields and disabled overload, including ordinary DHCP |
| Field and option lengths | C truncation to 63/127 bytes; 254/255-byte option boundaries; option omission and overload bits |
| Packet capacity and occupied field | Default versus advertised larger capacity; occupied file cannot be reused for overload |
| OFFER/SELECTING ACK/NAK | Boot options precede timers/defaults; NAK clears boot metadata |

`tools/dnsmasq/dhcp_boot_service_diff.py` runs the C daemon first and then Rust
with identical synthetic configuration and request bytes, in a namespace with
only loopback. It compares all response bytes, option order, packet length and
peer, and checks every daemon exits zero and is reaped. It does not serve or
fetch boot files. Selecting ACKs avoid random renewal fuzz. This gate uses
`leasefile-ro`; lease persistence and immediate DNS publication retain the
separate BOOTP lifecycle regression below.

Evidence under ignored `private/dnsmasq-rewrite/boot-config-20261001/`:

- `c-baseline-01`: first C-only freeze, 12 scenarios / 53 responses.
- `pair-after-01`: 53/53 byte-identical C/Rust responses.
- `calibration-01`: one injected missing reply gives 52 matches, 1 mismatch,
  process exit 1. Known C boot fields are independently asserted.
- `c-baseline-02` / `pair-after-02`: one additional occupied-file boundary,
  final 12 scenarios / **54/54** byte-identical responses, no unexecuted events.
  All 24 final C/Rust processes exited zero and were reaped.
- `bootp-regression-01`: **25/25** prior main-service packet, lease-file and
  immediate DNS events matched, with all 18 processes cleanly reaped.
- `reply-regression-01`: **1,284/1,284** independent C serializer cases matched,
  including capacity/overload and injected renewal fuzz.
- `dhcp-unit.log`: **105** related unit tests passed.
- `musl-clippy.log`: all-target `aarch64-unknown-linux-musl` clippy passed with
  warnings denied.
- `freeze-01`: source archive/manifest, main executable and build logs. The
  initial all-bin build failed because the archive omitted probe include files;
  the explicit main-bin build passed. That failed log is retained. Two new unit
  assertions initially used the request-only parser on replies and one had an
  incorrect byte offset; both test defects were corrected before the final run.

The frozen Linux main ELF SHA-256 is
`eb9b25f5556b19ed9944b71219a77f811075f7a842cb488d02d3056e823c3643`.
Its source-manifest SHA-256 is
`fb1c1ac89b526365bccc53a6afd2fddb8f4aaee24550a3f3bdeec543852efd98`.
This archive preceded the added unit assertions; product code in this phase
was unchanged after the archive. Raw source/configuration/packets/ELFs remain
private. The local independent reply gate additionally tests the final unit-test
source tree; it is not the Linux main-service ELF.

Reproduce on the Linux build host, with the source tools at the repository root:

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dhcp_boot_service_diff.py \
  --c "$EXACT_C_ELF" --rust "$FROZEN_RUST_ELF" \
  --output private/dhcp-boot-rerun
```

At this stage, next-server hosts-name resolution, tags, PXE selection and relay
routing were explicitly unsupported and were **not** counted as C matches.
The subsequent [hosts lookup stage](DHCP_BOOT_HOSTS_PHASE.md) closes only the
next-server hosts-name gap. Strings longer
than 255 bytes are explicitly rejected rather than narrowing a DHCP TLV length;
that is also outside this supported subset. A subsequent stage must connect the
hosts-name form to the same F_HOSTS generation and round-robin lookup as DNS,
including reload and the C port-zero behavior. These results prove the stated
coverage only, not full component equivalence or freedom from all bugs.
