# Ordinary DHCP option overrides and suppression

The local DHCP/BOOTP listener now accepts the ordinary untagged options
1/3/6/12/15/28 and bounded numeric T1/T2 (58/59), including
`dhcp-option-force`. Configuration presence is kept separately from selected
wire values: an empty or unrequested configured option still suppresses its C
default. This stage makes no performance or production-acceptance claim.

The contract comes from exact patched dnsmasq 2.93 `option.c:1459–2005`,
`dhcp-common.c:150–218` and `rfc2131.c:2217–2269,2752–2928`:

- Untagged options retain reverse configuration order. Last configuration wins;
  ignored duplicate options still emit C's per-response warning.
- Netmask/broadcast defaults are normally unconditional; configured values are
  subject to PRL unless forced. Router, DNS, hostname and domain defaults are
  also suppressed by configuration presence before request filtering.
- Empty values for these six defaulted options suppress output entirely.
  Empty string forms for hostname/domain behave the same way.
- Zero IPv4 addresses in configured lists mean the selected context's local
  address. Lists preserve address and option ordering.
- BOOTP uses C's null requested-options list, even when the request contains
  an empty PRL; it receives ordinary configured options without DHCP timers.
- T1/T2 selection is internal and independent of PRL/force. Existing serializer
  logic enforces C's bounds and T1-before-T2 relation; INFORM and BOOTP do not
  emit these timers.
- Configured hostname/domain change their wire options, without replacing the
  lease name used by option 81. FQDN takes precedence over a legacy hostname
  when determining a broken client's trailing-NUL requirement. Length 255 is
  never extended to a 256-byte option.
- Named aliases follow C's table: `option:hostname` and `option:broadcast` are
  rejected as internal names, while numeric 12 and 28 are supported.

`config/dhcp_options.rs` contains the small typed parser. The provider exposes
its configured options; runtime performs one reverse-order selection pass and
passes bounded values to the existing reply serializer. It records configured
codes before applying PRL or empty-value filtering. No new dependency or unsafe
boundary was added. Main did not require another wiring change.

`tools/dnsmasq/dhcp_options_service_diff.py` runs C first and Rust second with
identical synthetic configuration and packet bytes inside a loopback-only
network namespace. It compares every response byte, option/address order and
length, plus duplicate-warning counts and parser rejection exit status. This
uses `leasefile-ro`; persistence evidence remains in the existing lifecycle
gates. The shared boot test runner gained optional DNS-port/request-builder
arguments without changing its existing defaults.

Evidence below ignored `private/dnsmasq-rewrite/boot-config-20261001/`:

| Evidence | Result |
| --- | --- |
| `options-c-baseline-01` | First actual C freeze: 15 service cases, 83 replies, 7 rejected parser configurations |
| `options-c-baseline-02` | Added INFORM/FQDN checks: 17 cases, 87 replies + 17 warning counts + 7 parser results |
| `options-pair-01` | **111/111 observations matched**, zero unexecuted; all 34 service processes exited zero and were reaped |
| `options-calibration-01` | Injected one wrong reply: **110 matches, 1 mismatch, exit 1** |
| `options-dhcp-unit-02.log` | **108** related unit tests passed |
| `options-musl-clippy-02.log` | All-target aarch64-musl clippy passed with warnings denied |
| `options-freeze-01` | Frozen source archive/manifest, Linux release ELF and successful build log |

Coverage includes no PRL, empty PRL, selective/all requested options, forced
values, forced/ordinary duplicate precedence, suppression, self-address lists,
numeric and named spellings, quoted commas, finite timer bounds/order, broken
client NULs, 255-byte strings, larger packet capacity, BOOTP vendor exhaustion,
OFFER/SELECTING ACK/NAK/INFORM, and FQDN independence. Expected service packets
come from the actual C daemon, not Rust. Independent C assertions also verify
self-address substitution and default suppression.

Reference C ELF SHA-256:
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Rust Linux main ELF SHA-256:
`759fa0ace745df828b0b07e16b4b6052eb061a719d331351d3eaa001512b0681`.
Frozen source-manifest SHA-256:
`8cfd2c926bc8bfaf076b37b9df230b8becf2a7f6f4a3eaaa701c8226f9a9c925`.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dhcp_options_service_diff.py \
  --c "$EXACT_C_ELF" --rust "$FROZEN_RUST_ELF" \
  --output private/dhcp-options-rerun
```

The later [boot-options stage](DHCP_BOOT_OPTIONS_PHASE.md) adds ordinary 66/67.
Tags, vendor/encapsulation, other option codes, address/subnet descriptor
encodings and nonnumeric timer representations remain explicit configuration
errors and are not counted as C matches. Timers require a nonempty numeric
value with an optional s/m/h/d/w suffix, within defined nonnegative C int
arithmetic. Arbitrary raw timer blobs, quoted timer strings and empty timers
are outside this stage. Existing serializer/BOOTP state evidence is reused;
this stage does not change those algorithms. Full option grammar, target-image
runtime checks and physical-router acceptance remain open.
