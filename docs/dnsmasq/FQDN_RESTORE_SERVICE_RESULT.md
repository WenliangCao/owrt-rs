# FQDN lease recovery and live collision match native and image C

Main's FQDN wiring from `78f1e81` passes the independent [three-profile service
gate](FQDN_RESTORE_SERVICE_GATE_PLAN.md). Native C and the actual image first
calibrate **22/22** each. One subsequent main Rust execution supplies 22 rows
that match both saved C baselines completely; it is not counted as two Rust runs.

| Profile | Observations | Native C differences | Image C differences |
| --- | ---: | ---: | ---: |
| Ordinary lease-file recovery | 6 | 0 | 0 |
| FQDN-only lease-file recovery | 6 | 0 | 0 |
| Recovered FQDN versus live DHCP claim | 10 | 0 | 0 |

All three executions also pass 97 auxiliary process/UBus checks each. The saved
native/image C rows independently compare identically. No calibration failure,
fixture revision or repeated attempt occurred. Changed-flag and missing-row
comparator controls pass.

The fixture uses actual two-line private lease files with equal short names,
different MAC/address pairs, infinite lifetimes and different address-selected
domains. Ordinary mode keeps the last short-name claimant: its short name,
FQDN and PTR answer, while the first lease's FQDN and PTR miss. FQDN-only mode
instead preserves both restored names until domain reconstruction; both FQDNs
and PTRs answer, and the unqualified name is absent.

In the third profile a real third MAC completes DISCOVER/OFFER and selecting
REQUEST/ACK, claiming the same short name in the first domain. The first FQDN
moves to the new address, the old first address loses PTR ownership, and the
equal short name in the second domain retains its FQDN/address. The actual ACK
lease file retains all three addresses, clears only the displaced lease's
hostname and records the new owner. File order is compared without sorting.

The 22 rows comprise 17 actual DNS exchanges, two actual DHCP exchanges and
three startup-file snapshots. Startup file bytes are not mistaken for active
name ownership: C need not rewrite the file merely because restoration drops
an effective short name. A/PTR queries establish that state. Decoded DNS flags,
TTL, records, PTR case, original question bytes, upstream events, DHCP fields
and options, lease rows and all 30 UBus metrics match. Restored zero expiries
remain exact. The one live expiry is checked against its real ACK timestamp
before normalization to ACK+600 seconds; only upstream transaction IDs are
otherwise normalized.

The source contract is C's restore call to `lease_set_hostname` with no domain,
its FQDN-versus-short-name collision scope, subsequent per-address
`lease_calc_fqdns`, and ordinary/FQDN-only DNS publication. This qualifies the
new `restore_with_name_policy(..., fqdn_only)` runtime wiring and the ordinary
default control. No product correction was needed during this gate.

| Identity | Value |
| --- | --- |
| Product feature commit | `78f1e814f9a54c06b6946f7af41e1b10a759672b` |
| Main native ELF SHA-256 | `f126a762fbb0f1bcdac0e4e2eb61290bd92361f56fcf712213278ed9ba33e391` |
| Plan / tool commits | `72738df` / `9eb8db4` |
| Frozen tool SHA-256 | `6f6ca1a093e8209a1d040cd18a857ac01f4b7c555c4925e627d174d20507707a` |
| Native C ELF SHA-256 | `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431` |
| Image C ELF SHA-256 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |

The image runner, matching loader and libraries are verified before its run.
The [derived JSON](FQDN_RESTORE_SERVICE_RESULT.json) retains both C identities,
saved result/matrix hashes, per-profile counts and explicit comparison scope.
All 101 raw files were downloaded and individually hash-verified, including
real lease files, configurations, wire packets, stdout/stderr, the invocation
and main ELF. The ignored archive is
`private/fqdn-restore-service-evidence-01.tar.gz`, 679,369 bytes, SHA-256
`b96a8be7e14c7cf4ebcf6061ee2b47402d08c3d75ff2ecf9229d86c5bb4f8e3e`.
Its manifest SHA-256 is
`bfd9954143fccce39b63c0a04b4dd32ead8c1e98b7f4253575b62c9c7890a419`.
Remote originals remain under
`/home/ubuntu/dns-fqdn-restore-service-20261001/work01/private/`.

Every execution used `run_isolated.sh` with a private /run mount. No physical
router was accessed. The existing 62, 27 and 125 schedules were untouched and
not rerun. This does not qualify arbitrary lease syntax, IPv6, authoritative
configured-name collisions, DHCP scripts, dynamic reverse-cache adoption,
resource/performance behavior or complete DHCP equivalence.
