# Frozen FQDN lease recovery and collision service gate

This small, independent service gate covers the restored-name policy newly
wired by main `78f1e81`. It does not rerun the existing 62, 27 or 125 schedules.
Use real private lease files, real daemon startup, UDP DNS and one live DORA.
Complete native and verified-image C calibration before executing main Rust.
The saved C observations, not Rust or fabricated wire replies, are the oracle.

Source contract: `lease.c:148` restores short names through lease_set_hostname
with domain=NULL. Its OPT_DHCP_FQDN collision test (`lease.c:1104`) ignores a
name until an FQDN exists; ordinary mode instead removes a previous equal short
name. After interface enumeration, lease_calc_fqdns chooses get_domain for each
address (`dnsmasq.c:379`, `lease.c:1032`). DNS publication omits short names only
under OPT_DHCP_FQDN (`lease.c:598-613`). A later unauthenticated live hostname
claim may displace a restored unauthenticated lease with the same FQDN, while
the equal short name in a different address-selected domain survives.

## Three profiles, 22 observations

Every profile starts with the same private two-line lease file: two different
MAC/address pairs, infinite lifetime (expiry zero), the same short name
`client1`, and no client ID. File order is fixed: first-address then
second-address. A default domain satisfies dhcp-fqdn configuration validation;
two conditional address domains assign those leases `one.restore.test` and
`two.restore.test`. A third available address selects the first domain.

1. **restore-default** (6): ordinary mode. Observe the initial lease file,
   then DNS A for the short name and both FQDNs, followed by PTR for both
   addresses. The second short name wins restoration; only its short/FQDN/PTR
   publication survives. The first FQDN and PTR miss.
2. **restore-fqdn** (6): identical file/config with dhcp-fqdn enabled. Observe
   the same file and five queries. Both address-selected FQDNs and PTRs survive;
   the unqualified short name is not published.
3. **restore-fqdn-live-collision** (10): restore in FQDN mode, observe the file
   and both FQDN A answers; a third MAC performs real DISCOVER/OFFER and
   selecting REQUEST/ACK for the third address while claiming `client1`.
   Observe short-name miss, first-domain A moving to the new address,
   second-domain A unchanged, old first-address PTR miss, and new PTR naming
   the first-domain FQDN. Capture the actual lease file after OFFER and ACK.

Totals: 17 DNS observations, two DHCP exchanges and three startup-file
observations. These are separate from readiness barriers and auxiliary checks.
Use explicit DHCP TTL 60, lease time 600, no-ping and no-round-robin. Unknown
DNS requests receive controlled upstream NXDOMAIN; no-negcache prevents a miss
probe from changing later results. No configured host name competes with the
restored/client names. The fixture does not assume startup rewrites the lease
file: effective names are established by DNS, while actual file bytes and row
order are retained.

Compare C's complete decoded DNS replies, original PTR case, question bytes,
ordered upstream requests, parsed DHCP fields/options, ordered lease rows and
all 30 UBus counters. Only upstream IDs and the newly ACKed lease's absolute
expiry are normalized; that expiry must first fall within ACK wall-clock +600
seconds (one-second timestamp allowance). Restored expiry zero stays exact.
No record/file sorting. Reject missing rows and detect one altered DNS flag.

Each run uses run_isolated.sh and a private /run mount. Keep configs, leases,
packets, logs, binary identities and all failures under ignored private paths.
No physical router, performance experiment, helper/script lifecycle, arbitrary
lease-file syntax, IPv6, dynamic reverse-cache adoption or full DHCP acceptance
is included. Preserve all completed C rows before any correction or comparison.
