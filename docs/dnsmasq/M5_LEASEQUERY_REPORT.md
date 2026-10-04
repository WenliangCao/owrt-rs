# M5 leasequery daemon mirror

The exact image C and the leasequery branch candidate pass **22 profiles / 38
queries** in isolated network, mount and PID namespaces. Both sides use a real
UDP DHCP listener and relay client. Physical router state is untouched.

## Inputs and evidence

- Exact image C SHA-256: `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
- Matching source: `rfc2131.c` DHCPLEASEQUERY dispatch and `do_options`, and
  `dhcp.c` interface admission, context completion, lease pruning and relay send.
- Code commits: `5a8038f` (serializer), `83abb61` (single poll-owner integration).
- Candidate SHA-256: `ffedcd274a5569cbdacdf6ec3c2b6db59dc53594cc2b2c2af183df6ccb03e946`.
- Harness SHA-256: `45fd9c4d538430d0dd6d9c17dc5728952c5ec985dfad8801ca373dbaba4720f2`.
- Local raw evidence: `private/dnsmasq-rewrite/evidence/M5/leasequery/close-20261004/final/`.
- Oracle evidence: `/home/ubuntu/m5-leasequery-close-20261004/private/final/`.
- The single family harness is `tools/dnsmasq/m5_leasequery.py`; run it through
  `tools/dnsmasq/run_isolated.sh` with the pinned image root and candidate ELF.

The comparator checks complete response bytes after zeroing only the four
wall-clock timer values (51, 58, 59, 91), then independently checks each timer
within two seconds. It also checks the UDP peer address/port, reply presence,
and fixture status guards. Guards require actual ACTIVE responses for active
fixtures, so two daemons failing to restore the fixture cannot produce a pass.

## Covered behavior

| Boundary | Observed cases |
| --- | --- |
| Admission | Disabled, denied IPv4 ACL, IPv6-only ACL, prefix ACL, no relay source, no-DHCP interface |
| Relay route | Normal giaddr, all-ones giaddr preserved in reply, original source port 1067, ACL source selection |
| State | UNKNOWN, UNASSIGNED, ACTIVE by address/identity, infinite, expired at startup, expiry while serving, old-lease last-transaction |
| Context | Explicit/implicit netmask, missing context, remote classful context, router/broadcast/DNS/name/domain defaults |
| Tags/config | Request MAC/vendor/user/match tags, stored circuit/remote/subscriber tags, tag-if, host tags and lease duration, range tags |
| Options | PRL absent/empty/selective, forced ordinary option still requires PRL, configured defaults suppression, boot values as options, arbitrary and enterprise encapsulation, stored vendor-class echo |
| Encoding | Client ID/agent ID, fixed-header siaddr clearing and chaddr tail preservation, option overload, no-override option boundary |

No thread or secondary polling owner was introduced. The runtime passes ingress
metadata into the provider, which performs normal admission and pruning,
reconstructs the leased client's stored relay tags, narrows the context, matches
host configuration and encodes options. The all-ones relay extension keeps both
the original UDP source port and the sentinel giaddr, matching `dhcp.c`.

The provider owns four new cumulative leasequery counters. The main agent must
map `lease_query`, `lease_unassigned`, `lease_active`, and `lease_unknown` to the
existing corresponding `Metric::DhcpLease*` entries in the shared `main.rs` and
rerun this harness on the integrated candidate. This branch report does not
claim an integrated-main or UBus-counter differential result.

## Validation and size

138 host DHCP unit tests pass. The AArch64 musl release build and cross-target
clippy pass with the baseline's three unrelated diagnostics explicitly allowed
(`large_enum_variant`, `items_after_test_module`, `useless_vec`). Those allowances
are command-line validation scope, not source suppressions.

Using the existing M5 release flags (Rust 1.98.1, opt-level 3, LTO, one codegen
unit, matching OpenWrt musl linker and 4 KiB maximum page size):

| ELF | Bytes | SHA-256 |
| --- | ---: | --- |
| Baseline before leasequery closure | 1,294,448 | `2e19d183e3f1e1ea14b456357cf4f4371e568a3b547c0a7c3f4c37fa3cf1eac9` |
| Leasequery branch candidate | 1,310,832 | `ffedcd274a5569cbdacdf6ec3c2b6db59dc53594cc2b2c2af183df6ccb03e946` |
| Increment | **16,384** | |

This is the branch's incremental ELF result; final M5 full-load RSS and total
ELF comparison remain the milestone exit measurements.

## Retained diagnostics

The inherited harness initially used `leasefile-ro` without an init script.
Both daemons then had no restored leases. The apparent pass in `baseline/` is
invalid for ACTIVE coverage and is retained only as diagnostic evidence.
`baseline-restored/` corrects restoration; `baseline-expanded/` exposes the
actual missing context/options, interface admission, source port and header
behavior that this change fixes.

DNS-enabled `interface=br-lan` startup exposed a separate tentative-IPv6 listener
admission defect (`EADDRNOTAVAIL`) already assigned to the main agent's listener
work. The option-6 fixture uses an explicit IPv4 listen address, preserving
leasequery coverage without claiming tentative-IPv6 listener parity. The failed
runs and syscall trace remain under `boundaries*` and `dns-trace/`.
