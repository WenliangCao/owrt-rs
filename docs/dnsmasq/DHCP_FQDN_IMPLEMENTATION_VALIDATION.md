# DHCP FQDN runtime integration

Product commit `78f1e81` adopts the independent FQDN wiring from private
`eeed470`, without adopting reverse-cache or TCP snapshot code. `dhcp-fqdn`
now reaches lease-file restoration, configured-name updates, request hostname
collision policy and DNS publication. Both syntax checking and runtime setup
require a default domain; an address-conditional domain alone is insufficient.

On the exact product source, one replay of the unchanged **eight FQDN-only
service events** matches both saved native C and actual-image C traces. The
events include real OFFER/ACK/RELEASE, FQDN and PTR publication, forwarding of
the unpublished short name, and removal after release. The unchanged **five
configuration cases** also match both C baselines. These are eight executed
service events and five executed configuration checks, each compared to two
references; this is not a new 62-event reverse-cache pass.

A private wrapper selects the existing `fqdn-only` profile and calls the
original service runner and comparator. It verifies the frozen full matrix,
profile equality, original tool hashes and both saved C traces, then runs the
product binary once. It similarly reuses the original configuration cases and
saved C accept/reject outcomes. It neither changes the tools nor starts new
C processes. All packet, lease, metric and configuration observations remain
private, together with the actual wrapper and commands.

The same source passes native and SDK-linked musl library **391 passed /
16 ignored**, main **7 passed**, all-target Clippy with warnings denied, and
formatting. Tests run from prebuilt binaries inside Linux network namespaces.
The new restoration unit covers retaining equal short names in FQDN-only mode
until domains are calculated; ordinary mode keeps its previous collision rule.
Independent source review is recorded in
[the FQDN/local review](REVERSE_LOCAL_FQDN_REVIEW.md).

| Artifact | SHA-256 |
| --- | --- |
| Product source archive | `1ef15f6a33445b5adb557b036cdfcdff08d59f3d9fb5bea6ac51b14b0ca225f8` |
| Native product daemon | `f126a762fbb0f1bcdac0e4e2eb61290bd92361f56fcf712213278ed9ba33e391` |
| Evidence archive | `188738bbc8d51d2677e78778088ee7bef4eef87368e3ddbbe7cc01e22e84d973` |

The [derived JSON](DHCP_FQDN_IMPLEMENTATION_VALIDATION.json) records test/ELF,
tool, wrapper and baseline identities. All 1,349 files in the combined archive
were checked after download under ignored
`private/dnsmasq-rewrite/reverse-final-validation-20261001/mirror-01/`.

Domain-dependent restored-name and live collision combinations have a separate
C-first service gate in progress. They are not covered by the eight events or
promoted from source review into passes. Full DHCP, target packaging, performance
and production acceptance remain incomplete; the existing inert SDK artifact
still predates this change. No physical router was accessed.
