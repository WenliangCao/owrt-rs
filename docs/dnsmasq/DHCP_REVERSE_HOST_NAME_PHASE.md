# Static reverse-host names on DHCP ACK and INFORM

This fixes a real ordinary-DHCP mismatch: C selected a name from a static
reverse hosts entry, while Rust retained the client's name or omitted it.
The original executable matched **19/28** responses, with **9 differences**;
the corrected executable matches **28/28**.

`dhcp.c:1092–1119` and `rfc2131.c:1675–1679,1766–1774` define this path. Main
now supplies raw names from `ParentDns.local.hosts.reverse` through a small
fallible callback. The provider applies the exact relevant policy:

- Only static IPv4 reverse hosts entries are candidates. No system resolver,
  forwarded cache or dynamic DHCP name is substituted.
- If the first dot has a nonempty suffix, that suffix must match
  `get_domain(address)` case-insensitively. The short hostname must satisfy
  `legal_hostname`; its original case is retained.
- Ordinary ACK uses the static name unless a configured DHCP name is already
  authoritative. INFORM uses it only when its earlier name selection is empty.
- The chosen ACK name is authoritative in lease state and drives the reply
  and source notification. DNS port zero does not invoke this lookup.

The callback reads the shared current hosts generation under the existing
`event → provider → parent` lock order. Domain/name checks remain in DHCP;
main neither normalizes nor truncates the raw record. A callback error is
reported before the state transaction, rather than treated as an absent name.
Providers with no attached static-host source have no reverse match.

`tools/dnsmasq/dhcp_reverse_name_diff.py` first freezes real C responses and
then sends identical requests/configuration to Rust, in a namespace containing
only loopback. Every response byte, order, length and peer is compared. Cases
cover short names, matching/case-variant/wrong domain suffixes, illegal leading
hostname characters, explicit DHCP names and absence of a static record.
Each case exercises ACK with/without a client name and INFORM with/without a
client name. This uses `leasefile-ro`; startup/restoration/HUP renaming and
persistence are not claimed by this corpus.

Evidence under ignored `private/dnsmasq-rewrite/boot-config-20261001/`:

| Evidence | Result |
| --- | --- |
| `reverse-name-c-baseline-01` | 7 cases / 28 actual C responses |
| `reverse-name-before-01` | **19 matches / 9 differences**, exit 1; retained |
| `reverse-name-after-01` | Initial corrected ELF: **28/28** |
| `reverse-name-after-02` | Final frozen ELF: **28/28**, zero unexecuted; all 14 processes exited zero and were reaped |
| `reverse-name-calibration-01` | One wrong reply: **27 matches / 1 difference**, exit 1 |
| `reverse-name-freeze-02/linux-dhcp-tests.log` | **111** related Linux unit tests passed; 4 socket tests initially ignored |
| `reverse-name-freeze-02/linux-dhcp-socket-tests.log` | All **4/4** ignored socket tests explicitly rerun and passed in an isolated namespace |
| `reverse-name-clippy-03.log` | All-target musl clippy passed with warnings denied |
| `reverse-name-freeze-02/clippy.log` | Frozen native Linux all-target clippy passed with warnings denied |

An all-target clippy pass first caught a test-probe `chunks_exact` lint; its
failed log is retained in `reverse-name-clippy-02.log`. The observer decoder
now uses fixed chunks and rejects odd/oversized hex input. This is test-tool
cleanup, not a protocol change. The final source archive records that update.

Reference C ELF SHA-256:
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Final Rust main ELF SHA-256:
`ece742add80e1fa157cd5046ecc854b9bf05e805e7e1ba4939d9a8dd341352b3`.
Source-manifest SHA-256:
`3d129d2bf26fd0c5c2a749864033429ac4d3a83897dc093ceb81d5f738bdfb29`.
`source-base.json` identifies committed base `bf3a73c` plus the main/provider
hook and observer-decoder overlays, excluding unrelated concurrent edits.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dhcp_reverse_name_diff.py \
  --c "$EXACT_C_ELF" --rust "$FROZEN_RUST_ELF" \
  --output private/dhcp-reverse-name-rerun
```

The related `lease_update_from_configs` fallback during startup restoration
and HUP remains an explicit follow-up: the previous updater only handles
configured `dhcp-host` names. A separate C lifecycle baseline is being built;
it is not counted as passed here. No performance, complete-component or
physical-router acceptance is claimed.
