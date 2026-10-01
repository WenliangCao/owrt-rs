# Ordinary DHCP host configuration and service

This phase covers ordinary IPv4 client-ID and exact hardware-address rules.
It does not establish complete DHCP, BOOTP/PXE, DNS synchronization or service
equivalence. No physical router was accessed.

| Exact C contract | Rust behavior |
|---|---|
| `option.c:4004-4244` | Parse address, hostname and stripped suffix, lease time, ignore, ignored client ID, typed/multiple MACs and text/binary client IDs. Last directive and last MAC appear first. Duplicate addresses across rules fail startup. |
| `dhcp-common.c:320-410` | Search every eligible client-ID rule before any exact MAC rule; accept the IPv4 leading-zero client-ID compatibility form. Fixed addresses qualify by selected context subnet, not dynamic pool membership. |
| `lease.c:257-273` | Startup lookup has no context restriction; a fixed-name rule updates only its own fixed address. |

Tag/set selectors, wildcard hardware addresses and hostname-only rules remain
explicitly rejected. Accepting them while ignoring their selectors would widen
authorization or assign the wrong lease. IPv6 host rules and out-of-range C
integer conversions are outside this implemented boundary.

`NameDomains` retains only the validated DNS default/conditional domain fields
and delegates address selection to `DnsConfig::domain_for_address`. A suffix
written in `dhcp-host` does not replace the address-selected domain.

`tools/dnsmasq/dhcp_host_config_diff.py` links the hash-pinned native C objects,
prints their parsed host list and calls their real `find_config`. The oracle
runs before the Rust comparator. Evidence is retained under ignored
`private/dnsmasq-rewrite/dhcp-static-20261001/`:

- `config-c-baseline-01/`: 94 C inputs, 83 accepted, 11 rejected; 240 selector
  queries per accepted input, including reversed rule order and subnet chains.
- `config-diff-01/`: **86 matching contract cases**, **8 explicit unsupported
  boundary checks**, zero failures. Accepted contract cases compare every field
  and all match indexes; rejected cases compare exit status. Unsupported cases
  are excluded from the semantic-match count.

The tester calibrates address/index differences, success/failure and distinct
error statuses. The matching baseline counts are frozen in the tool. Sources,
generated drivers, raw configuration, stdout/stderr and oracle identity remain
in private evidence. These counts cover this corpus only.

## Daemon, replies and restored names

`LocalProvider` now selects the rule before entering the existing lease state
machine. It retains per-rule DECLINE backoff, supplies all reserved addresses,
applies configured lease duration/ignore/client-ID policy, and supplies the
configured name as authoritative. Ordinary client names remain unauthoritative.
MAC lists permit the matching C static-address handover behavior.

Reply options 12/15/81 follow `rfc2131.c:700-765,800-816,2814-2874`: ordinary
DISCOVER client names are not echoed without matching configuration, configured
names retain case, PRL controls options 12/15, and supplied FQDN option 81 is
independent of PRL. The target default FQDN flags, ASCII/label encoding and
broken-client terminating NUL behavior are preserved. The reply domain uses
the selected address, including addresses outside the dynamic pool.

The startup review found a functional omission: restoring a lease assigned its
short name with no domain; the subsequent same-name configured update returned
early, leaving its FQDN absent. C calls `lease_calc_fqdns` after domain/interface
setup and before the first reload/publication. `LeaseStore::initialize_fqdns`
now performs that separate step before configured-name updates. It does not
dirty the lease file or enqueue helper changes. This also reconstructs dynamic
lease names and picks the current domain after restart.

Retained evidence in the same private directory:

- `lifecycle-c-baseline-01/`: exact native C observations, including 42 requests
  and 36 responses across ten scenarios. Per-scenario event/response counts are
  frozen in the tester.
- `lifecycle-diff-01/`: initial **168 passed, zero failed** checks.
- `lifecycle-calibration-01/`: deliberately replacing one decoded option-12
  value produces **48 passed, one failed**, exit 1; raw bytes remain unchanged.
- `lifecycle-diff-02/`: final **208 passed, zero failed**, ten of ten scenarios.
  These cover configured/client/FQDN names, CLID-before-MAC and a leading-zero
  ID, reuse of a stored ID, multiple-MAC handover, ignored ID/client, reserved
  and occupied addresses, DECLINE, restore, static BOOTP, dynamic renewal and
  INFORM by address. Compare every emitted option, transaction ID, fixed
  address/flag/BOOTP fields including `siaddr`, and ordered lease rows after
  each event. Only renewal randomness and whole-second expiry observation are
  normalized; their allowed C relationships are checked explicitly.
- `dynamic-regression-01/`: the prior DORA/renew/rebind/release/restart,
  idle-expiry and read-only scenarios still pass **114 checks, zero failures**.
  ENOSPC was not rerun: the held-file writer/retry path did not change, and its
  retained successful evidence remains in `DHCP_PERSISTENCE_PHASE.md`.
- `restore-fqdn-c-02/`, `restore-fqdn-diff-02/`: **20/20** extracted exact-C
  startup-name cases, including no name, no domain, different/current suffixes,
  mixed case and a 63-byte hostname. A regression also confirms that the later
  same-name authoritative update preserves the FQDN and startup helper flags.
- `source-identity-02.json`, `service-source-02.tar.gz` and the private saved
  ELF files identify the final daemon snapshot and both service rounds.

The affected 97 DHCP unit tests and library clippy passed before concurrent DNS
publisher integration. After the pending DNS interfaces were supplied, the full
library regression passed **301 tests, zero failed, five ignored**; those ignored
tests are not counted as passed (`full-lib-01.log`). The older offline state probe
now links the actual crate, avoiding stale standalone-module imports; its adapter
compilation passed.
The isolated Linux release build passed. DHCP DNS publication itself remains
unchecked in these daemon runs; the dedicated publisher and full combined
DNS/reload gate are separate. Configured hosts-file name fallback, tags,
wildcards, name-only selection, option overrides, relay/PXE, helpers and full
OpenWrt integration remain open. No performance or production acceptance is
claimed by this phase.
