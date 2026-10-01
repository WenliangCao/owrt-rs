# Static-host address fallback for DHCP rules

Rust now derives an IPv4 reservation for an ordinary `dhcp-host` rule with a
configured name and no explicit address from the static hosts generation.
The unchanged independent C service corpus passes **27/27 startup/HUP
snapshots**, improved from **10/27 matched and 17 differences** before the
implementation. Its complete observation file is byte-identical to C's.

## Existing contract

`dhcp-common.c:449–552` implements `dhcp_update_configs`. It first clears
addresses previously inferred from hosts, then walks DHCP rules in list order.
An explicit address wins; otherwise the configured short name is looked up
among IPv4 cache records. The first result must be `F_HOSTS`. A sole result is
eligible even if it is an alias; multiple results require a reverse-owning
record. The current lookup order and round-robin mutation apply. `host-record`
qualifies, while CNAMEs are not followed. `port=0` disables inference.

`config_find_by_address` (`dhcp.c:754–760`) prevents duplicate reservations.
Explicit addresses anywhere in the list block inference. Among inferred
addresses, the first rule visited wins. Rules are normally latest-directive
first; DHCP file rows precede inline rules. A collision leaves the losing
rule addressless rather than disabling DHCP.

Startup and HUP share the reload sequence in `dnsmasq.c:1838–1850`: DNS hosts,
DHCP files, inferred addresses, configured lease names, lease file, then DNS
publication. Main configuration stays fixed. A subtle HUP boundary matters:
new DHCP-file rows are parsed before old inferred inline addresses are cleared.
Thus a new explicit file row can be rejected against an inline address that
will move later in the same reload. A subsequent HUP can accept that row.

## Frozen actual-service baseline

`tools/dnsmasq/dhcp_host_address_diff.py` requires a successful independent
C-only baseline before comparing Rust. The tool, plan, expected observation
file and native reference identities are checked. Both daemons run with `-k`
inside a loopback-only network/mount/PID namespace and private ubusd. An
inotify read-close event on the DHCP source followed by a synchronous UBus
metrics reply provides the startup/HUP completion barrier. The first DHCP
request then observes the new generation; DNS is queried afterward.

The 15 scenarios include inferred-address move/removal/reintroduction, explicit
and inferred collisions, DHCP-file precedence, the old-inferred-address file
parse conflict, sole and multiple aliases, reverse selection, round-robin and
no-round-robin, `host-record`, short versus fully qualified names, CNAME
exclusion, `expand-hosts`, a restored mismatching lease, and `port=0` with a
hosts FIFO that must never be opened.

All 27 snapshots retain complete DHCP response bytes, first post-barrier lease
rows, all 30 actual UBus counters before/after DHCP, and DNS semantics including
TTL, flags and record order. Offers cause no fabricated lease allocations;
the one ACK allocates through the normal lease path. Infinite leases avoid
clock normalization. Two port-zero snapshots contain no DNS observation.
Missing snapshots and an injected address mutation fail the comparison. There
are 32 actual DHCP requests, 25 DNS queries and 54 complete metric snapshots;
all 263 helper UBus/lifecycle checks pass in the C, before, after and negative
runs.

The C baseline has zero failures and observation SHA-256
`9c12175fea530133d405ad465000e7fe9970f25ae9c671ecc60b3d748cad892f`.
Rust committed base `10b9d19` completes all snapshots with 17 differences;
ELF SHA-256 is
`b7e2db5b16069585bbcea30be55cd000ca6da07d016243547f7ce91238cf3252`.
The exact C ELF is
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.

Raw C and before-fix evidence, source archive and logs are retained under
`private/dnsmasq-rewrite/dhcp-host-address-20261001/` in the isolated worktree
and `/home/ubuntu/dnsmasq-dhcp-address-20261001` on the authorized oracle.
The initial source archive SHA-256 is
`4b20f0fb4b6d525cc82414cd4d322d4a30fd944c38d7106d8ebcac53976d17bd`.

## Implementation and validation

`LocalProvider::set_config_host_lookup` is a separate callback from the boot
next-server lookup because the multiple-address selection rules differ. Main
uses the existing static hosts lookup and reverse ownership. The provider
enriches the ordered configurations before configured lease-name updates, then
updates its packet policies and reserved-address list together. It never
creates a lease for a reservation.

The immutable inline configuration retains the original explicit addresses.
During reload, the current inline tail participates in DHCP-file parsing,
preserving C's old-inferred-address conflict behavior. Inferred addresses are
then reset from the immutable original and derived from the new hosts
generation. Existing inline DECLINE state remains attached to its policy;
fresh file rules get fresh state.

An internal lookup error is returned as `MaintenanceReport.address_error` and
reported by main. DHCP admission pauses until a successful reload so that an
unresolved reservation does not silently become a dynamic allocation. A Linux
unit test exercises partial lookup failure, successful retry, removal of the
derived addresses, retained DECLINE state and unchanged real lease counters.

| Frozen check | Result |
| --- | --- |
| `after-01` against independent C observations | **27/27**, zero failures; observation SHA unchanged |
| `negative-01`, corrupt one C expectation | **26/27**, exactly one mismatch, exit 1; actual observations unchanged |
| Ordinary static lifecycle | **208/208** |
| DHCP host-file reload lifecycle | **41/41** |
| Unsupported-selector pause/recovery | **11/11** |
| Reverse-host startup/HUP | **87/87**, fresh independent C baseline **72/72** |
| Linux library filter `dhcp:: --include-ignored` | **116 passed**, zero failed/ignored; includes `config::dhcp::` |
| Native and aarch64-musl all-target clippy, warnings denied | Both passed |

The earlier reverse-name phase used a different test filter; its 117 count
must not be compared directly with this 116 count. A supplemental
`config::dhcp_` invocation selected zero tests and is retained without claiming
coverage. The intended host-file parser test was already in the 116 run; its
explicit rerun also passes. An initial whole-crate format check exposed
pre-existing formatting in `dns/daemon_poll_tests.rs`; only the two edited
Rust source files were formatted, and the unrelated file remains untouched.

The tested Rust ELF SHA-256 is
`3a62e87e45d8038314b3182e52d4b70bcc1f78e248b955a8b6ed0f7b0f29e260`.
The 92-file component source manifest SHA-256 is
`555f36e3ebc241d475d93961f13b08e514b75b8c73acb91ec08c1855abe1d9a8`;
every file was checked against the isolated worktree after the runs.
The frozen source archive is
`8b9630a6760f8d55f19d1ce2cbb233e6934bc2ef9c14ef18e8463078d2028721`.
`after-source-01.tar.gz`, `after-evidence-01.tar.gz` and their extracted logs
remain beside the initial evidence. These identities describe the isolated
candidate; later integration has its own affected checks.

This bounded corpus does not qualify tags, PXE, name-only selectors, IPv6 DHCP,
retained DHCP DNS versus newly loaded hosts-alias ordering, C's duplicate and
multiple-address syslog warning parity, target execution, resource improvement
or production acceptance. No physical router is involved.
