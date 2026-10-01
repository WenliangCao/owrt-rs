# dhcp-fqdn default-domain configuration result

The independent [five-case anchor](DHCP_FQDN_DOMAIN_PLAN.md) calibrates 5/5
against both native and actual-image C. Private Rust source `a4a38bc` matches
both variants on all five cases. The older `62894d6` matches four acceptance
results but rejects the valid default-domain/FQDN case as unsupported.

| Case | Native/image C | `62894d6` before | `a4a38bc` after |
| --- | --- | --- | --- |
| No flag, no domain | accept | accept | accept |
| FQDN flag, no domain | reject | reject | reject |
| Conditional domain without flag | accept | accept | accept |
| FQDN with only conditional domain | reject | reject | reject |
| FQDN with default domain | accept | reject | accept |

The conditional control establishes that its syntax is valid. The FQDN flag
requires a default domain, not merely a conditional suffix. This is the exact
option.c:6306 boundary. Matching older rejections do not imply its FQDN runtime
was implemented; its valid case and real service startup still failed.

Only acceptance is compared; original diagnostics and exit codes are retained.
Every run completes all C cases before Rust. Saved-row calibration detects
one changed acceptance result and rejects a missing case. No daemon listener,
DHCP transaction or lease mutation occurs under --test. The separate 62-event
service gate keeps its original matrix and denominator.

Identities:

- Frozen plan/tool commit: `de344d9`.
- Tool SHA-256:
  `7e8fad998f501e2af4e494f1e552a30f5ec4ca96227273da0d5448cd5eae6738`.
- Before source: `62894d657341827f3ea1e903375a6263dbe4de82`;
  ELF `601550b04418152ba5a865343ee3e44d93c64b610f29440577c1e294a547726e`.
- After source: `a4a38bcf70187c098635944dbfa0fc4dde1ed757`;
  ELF `7ccce278a5ccb251bf4fbb59203c9b51cfcc3f3797dc88452e0e536bb77c3b9e`.
- Native C ELF:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Image C ELF:
  `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`;
  image runner/loader/dependencies are verified before execution.

Raw evidence for `fqdn-native-baseline-01`, `fqdn-image-baseline-01`,
`fqdn-native-before-01`, `fqdn-native-after-01` and `fqdn-image-after-01` is in
`private/dnsmasq-rewrite/reverse-cache-gate-20261001/private/`, mirrored from
`/home/ubuntu/dns-reverse-cache-20261001/work01/private/` and covered by
`fqdn-domain-evidence-sha256.json`. All executions use run_isolated.sh. The
narrow configuration result does not qualify arbitrary domain combinations,
conditional-domain lease-name selection or complete FQDN lifecycle behavior.
