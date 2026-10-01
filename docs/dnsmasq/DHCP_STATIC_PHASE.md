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
