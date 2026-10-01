# Frozen dhcp-fqdn default-domain configuration anchor

This separate five-case `--test` anchor does not change the 62-event reverse
lease service gate. Existing service evidence has a default domain and does
not qualify its required absence/conditional-domain boundary.

Exact option.c:2621 distinguishes conditional domains from domain_suffix;
option.c:6306 rejects dhcp-fqdn without a default suffix. Freeze these cases
before executing native and verified actual-image C:

| Case | Extra directives after no-hosts/no-resolv | C acceptance prediction |
| --- | --- | --- |
| plain | none | accept |
| fqdn-no-domain | dhcp-fqdn | reject |
| conditional-control | domain=range.test,127.0.0.0/8 | accept |
| fqdn-conditional-only | same conditional domain plus dhcp-fqdn | reject |
| fqdn-default-domain | domain=leases.test plus dhcp-fqdn | accept |

The conditional control proves its syntax is valid independently of the FQDN
requirement. Compare acceptance, not executable names or exact diagnostics;
retain exit/stdout/stderr and complete configuration privately. Finish every C
case before Rust in a paired invocation. Verify C image runner/dependencies,
reject missing cases and detect one changed acceptance result in saved-row
calibration. A rejected C prediction remains visible and prevents a paired pass.

All invocations use run_isolated.sh and fresh private directories; --test opens
no DNS/DHCP listener. No router, lease mutation, timing or deployment work.
This anchor does not qualify conditional-domain lease-name selection, arbitrary
configuration combinations or the complete dhcp-fqdn runtime lifecycle.
