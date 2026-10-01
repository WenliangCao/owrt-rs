# Frozen target package checkpoint: 405b7c1

The inert SDK package built, but the complete retained UBus service gate is
**red: 67/69 paired observations match, with 583 checks passed and 2 failed**.
The failures are a target-musl address parsing side effect and missing TCP
child-to-parent cache writeback. This checkpoint is not replacement or
deployment acceptance. The Rust ELF is **909,102 bytes larger (+337.6%)** than
the exact image's C ELF; resource acceptance remains open.

The product snapshot is `405b7c1bbbf5b932f3b627ba401896b814015163`, epoch
`1790857241`, with source digest
`adaf0574e740ea485f75752c67205e4e62202c53d62ea076205822ebd779acb3`.
The build labels its commit as caller-declared. This recovery audit independently
matched all 95 input hashes against that Git commit, the private freeze and the
recovered package source copy. All 89 prepared-source manifest entries also
match the corresponding component inputs; the remote prepared build tree was
not recovered or re-audited here.

The SDK is the pinned OpenWrt 25.12.5 mediatek/filogic GCC 14.3.0 musl archive
(`ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25`),
using Rust 1.98.1. The manifest records explicit prepare/compile commands,
working SDK file identities and restoration of the original package recipe.
It retains **181 warning/loader lines**, including dependency-discovery and
host preload warnings. The audit does not claim a warning-free build or
independent-build reproducibility.

| Artifact | Verified recovered result |
| --- | --- |
| APK | `owrt-dnsmasq-0.1.0-r1.apk`, 622,772 bytes |
| APK SHA256 | `3947e785e256fa930cf301869bb2de9b7ed3b04df3c604e2ea059e6645d7ba40` |
| Rust ELF | Static AArch64 EXEC, 1,178,407 bytes |
| Rust ELF SHA256 | `f93fc151e7faabb15ae03264650d271145ef88cbe02851317e546e6e6a501590` |
| Regular payload | `/usr/libexec/dnsmasq-rs` and its 24-byte APK ownership list |
| Recorded package ownership/modes | Executable root:root 0755; list root:root 0644 |
| Activation | Inert; no stock binary, init script or UCI replacement |

The C runtime is the exact image's dnsmasq 2.93 `nodhcpv6` ELF and four image
libraries, invoked through their copied musl loader. All five recovered file
hashes and sizes, the runner hash and the reference identity hash were checked.
The C ELF is 269,305 bytes, SHA256
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`;
the canonical image SHA256 is
`144c1283da1fb3ead5e4ee7b8b55f66b7d9e872f785892f87cadf9fca6ed0720`.
The matching implementation source is dnsmasq 2.93 archive
`0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19`
with the two image-recipe patches at OpenWrt revision
`f0a60eee2fe051741c643ea6118718aae1ef17fb`, as recorded in
[the source manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/sources.json).
C's shared libraries remain platform dependencies and are not exclusive space
savings available to this rewrite.

The retained build-host runs use the isolated loopback namespace harness.
Each result identifies this exact Rust ELF and the same pinned C runner;
the strict reference records additionally bind the C ELF and all libraries.
UBus's bus daemon and test client remain native host builds, separately hashed
in the evidence; this is not an all-musl system-stack test.

| Retained gate | Scoped result |
| --- | --- |
| UDP receive/admission and capacity recovery | 43/43 observations; zero mismatches |
| UDP policy | 64/64 comparisons across four rounds; zero mismatches |
| UDP size boundaries | 68/68 comparisons across four rounds; zero mismatches |
| Static alias service | 97/97 observations; zero mismatches |
| DHCP boot options | 20 scenarios, 97/97 events; all 40 daemon runs exited and were reaped |
| DHCP/DNS integration | 34 matched observations; zero mismatches |
| DNS `port=0` with TFTP | 7 matched observations |
| Separate TCP daemon reply corpus | 15 scenarios, 116 replies matched; does not cover parent cache writeback |
| Full UBus service corpus | **67/69 paired observations; 2 failures; gate remains nonzero** |

The two UBus failures were independently recounted from both observation maps:

- `paired-wrong-family-answer`: C changes one byte of the original IPv4 RDATA
  after receiving a subscriber string of the other address family; Rust keeps
  the original address. Other answer fields, including flags, match. The
  verified patched `rfc1035.c:503` passes the packet's RDATA directly to
  `inet_pton` and tests only its return value. That source boundary is consistent
  with the observed partial-write side effect under the target musl runtime.
  This difference is retained; it is not an equivalence pass or an authorization
  to copy the side effect into Rust. The earlier native-glibc UBus result does
  not establish target-musl behavior for this case.
- `paired-tcp-closed`: C reports 8 cache insertions and Rust 7 after the TCP
  upstream answer; all other metrics match, including forwarded=8 and active
  TCP=0. The separate reply corpus does not close this cache transfer failure.

The retained UBus tool returns exit 1 whenever any check fails; its exact hash
matches the committed tool at `31d6056`. The 583 helper passes include readiness
and lifecycle checks and must not replace the fixed 69-observation denominator.
C's stale DNS object type after a bus restart is also recorded as a separate
reference defect, not a paired success. The standalone doctor lifetime gate
in [UBUS_DOCTOR_PHASE.md](UBUS_DOCTOR_PHASE.md) remains separate and unresolved.

Evidence stays under ignored `private/dnsmasq-rewrite/package-405b7c1-stage/`,
with the freeze and C reference in the neighboring `freeze-405b7c1/` and
`package-574f5ed-stage/target-c-reference/` directories. The companion
[sanitized JSON](PACKAGE_405B7C1_RESULT.json) pins the retained report hashes,
artifact identities, counts and audit scope. This audit used local files only;
it did not rerun the services or access a router. No target-router kernel,
production lifecycle, throughput, CPU or memory acceptance is established.
