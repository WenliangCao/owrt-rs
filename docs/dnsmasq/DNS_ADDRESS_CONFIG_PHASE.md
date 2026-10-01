# DNS bogus and ignored address configuration

`DnsConfig.bogus_addresses` and `ignore_addresses` now retain typed IPv4/IPv6
addresses and prefix widths. Their order matches C's newest-first linked lists,
and source host bits remain intact. Runtime policy construction must copy these
fields into the existing address matcher; parsing alone is not a service gate.

The exact `option.c:2941–3000` contract decodes the complete argument before
splitting the first slash. IPv4 and IPv6 default to /32 and /128 respectively.
An empty explicit prefix is /0 because C's `numeric_check` accepts the empty
string and `atoi` returns zero. Other defined integer prefixes must be decimal,
nonnegative and no wider than the address family. Whitespace adjacent to the
slash is trimmed; decoded leading/trailing whitespace outside that boundary
remains significant. Extra slashes, comma lists, zone IDs, bracketed IPv6,
IPv4 shorthand and leading-zero octets are rejected.

`tools/dnsmasq/dns_address_config_diff.py` links real exact-C `read_opts` objects
and compares acceptance, `--test`, family, prefix, address bytes and list order.
Rust generates no expected values. The frozen corpus has 91 cases: C accepts
49 and rejects 42. IPv6 addresses compare as bytes, avoiding display-format
normalization. Inputs exceeding the defined C `int` range are outside this
oracle contract; Rust rejects them without reproducing C integer overflow.

Evidence is retained in ignored
`private/dnsmasq-rewrite/dns-alias-config-20261001/`:

- `address-config-c-baseline-01/`: initial probe build stopped by
  `-Werror=misleading-indentation`; no comparisons were run.
- `address-config-c-baseline-02/`: 91 C cases completed before Rust parser work.
- `address-config-diff-01/`: 91/91 matches, zero failures.
- `address-config-calibration-01/`: one injected decoded-output mutation gives
  90 matches / 1 failure and exit 1; original raw output is unchanged.

No listener, ubus connection or physical router was used. Configuration-DNS
unit tests pass; the environment-dependent C acceptance unit is explicitly
ignored in the local run. Consumer and alias-order interaction evidence belongs
to [the static alias service phase](DNS_ALIAS_SERVICE_PHASE.md).
