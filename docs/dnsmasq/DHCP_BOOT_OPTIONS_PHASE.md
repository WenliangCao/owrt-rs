# DHCP options 66/67 and boot-field precedence

Ordinary untagged options 66/67 and their `tftp-server` / `bootfile-name` aliases
now share the C placement contract with `dhcp-boot`. This extends the typed
option subset without enabling tags, vendor/encapsulation or PXE selection.
No performance or production-acceptance claim is made.

The exact source contract is `option.c:1459–2005`, `dhcp-common.c:694–695`,
`rfc2131.c:2678–2748,2893–2928` and `util.c:342–350`:

- Without `dhcp-boot`, an unforced 66/67 value goes into its fixed field when
  not explicitly requested. BOOTP always uses this no-PRL selection rule.
  Such a value is then excluded from the ordinary TLV loop.
- Forced values use TLVs; an explicitly requested unforced value also uses a
  TLV. `dhcp-no-override` does not reverse that ordinary-option decision; it
  controls overload and the separate `dhcp-boot` placement rule.
- Any `dhcp-boot` directive, including an empty one, prevents the 66/67 fixed
  fallback. Its own boot fields/options precede timers/defaults; selected
  configured 66/67 TLVs are still appended afterward. C may therefore emit two
  options with the same code; these are retained in their original order.
- No argument encodes a zero-length TLV. An explicit empty string encodes a
  one-byte NUL TLV. Both safely produce empty fixed fields when selected there.
- Boot strings always use NUL termination on the wire, independently of FQDN
  or broken-hostname handling, except length 255. Fixed fields retain C's
  63/127-byte truncation and cannot be overwritten by later option overload.

The runtime selects the fixed fallback before filtering ordinary requested
TLVs, then reuses the existing bounded boot-field serializer. Configuration
presence and last-directive selection remain those established in the earlier
ordinary-options stage. The parser preserves C's empty-string flag distinction.

`tools/dnsmasq/dhcp_boot_options_diff.py` freezes actual C observations before
running Rust, using identical configuration and packet bytes in a loopback-only
namespace. It compares all response bytes, option order, packet size and peer;
SELECTING ACK avoids renewal randomness. No boot files are fetched or served.

Evidence under ignored `private/dnsmasq-rewrite/boot-config-20261001/`:

| Evidence | Result |
| --- | --- |
| `boot-options-c-baseline-01` | C-only freeze: 20 scenarios / 97 responses |
| `boot-options-pair-01` | **97/97** exact matches; all 40 processes exited zero and were reaped |
| `boot-options-calibration-01` | One injected reply difference: **96 matches, 1 mismatch, exit 1** |
| `boot-options-boot-regression-01` | Existing boot fields/PRL/capacity: **54/54** |
| `boot-options-hosts-regression-01` | Hosts lookup, round-robin, reload and warnings: **53/53** |
| `boot-options-options-regression-01` | Existing defaults/force/timers/parser rejection: **111/111** |
| `boot-options-unit-01.log` | **109** related unit tests passed |
| `boot-options-freeze-01` | Exact source archive/manifest, native ELF, successful build and native/musl all-target clippy logs |

The corpus covers ordinary/forced/mixed 66/67; absent, empty, selective and full
PRL; BOOTP and legacy cookie; OFFER/ACK/NAK; no-override; empty/partial/full
`dhcp-boot`; empty values with and without arguments; field-length boundaries;
254/255-byte strings, larger capacity, overload/omission; and FQDN independence.
Independent C assertions verify fixed-field placement, NUL TLVs, and the two
same-code options emitted by combined configuration.

During parallel UBus integration, all-target clippy on the live workspace
encountered unfinished main-to-DNS APIs. That failed run is retained as
`boot-options-clippy-01.log` and is not reported as passing. This phase's
isolated artifact is committed base
`1992d19fd8870cf3ccbaf4ad3f0383478ac75883` plus only this phase's
`config/dhcp_options.rs` and `dhcp/runtime.rs`; `source-base.json` records that
construction. The independent snapshot passed native and musl all-target
clippy with warnings denied. Integration of other concurrent changes requires
its own gate.

Exact native C ELF SHA-256:
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Rust Linux main ELF SHA-256:
`8f2f2b61577c094a2e87d394060ebe6712c169b8206c1a78fa95b715fabc1ade`.
Frozen source-manifest SHA-256:
`e6c75692af379babf31b304b4d2faa607bc781ac50387618570bc9fc55a04c9d`.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dhcp_boot_options_diff.py \
  --c "$EXACT_C_ELF" --rust "$FROZEN_RUST_ELF" \
  --output private/dhcp-boot-options-rerun
```

These observations close this ordinary 66/67 subset only. Other option types,
tag selection, vendor/encapsulation, relay/PXE flows and target-router
acceptance remain separate work.
