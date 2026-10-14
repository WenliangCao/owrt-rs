# Retained DHCP entries during hosts bulk loading

All observations use the exact OpenWrt 25.12.5 C daemon in isolated Oracle
namespaces, synthetic lease files and the six-row F10 hosts fixture. No physical
router was changed. Exact C SHA-256:
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.

The daemon starts with an empty hosts file and an optional DHCP DNS lease
`a.test -> 192.0.2.1`, verified by an actual DNS query. HUP then loads:

```text
192.0.2.2 old.test
192.0.2.1 x.test
192.0.3.186 a.test
192.0.3.185 a.test
192.0.2.1 y.test
192.0.2.2 y.test
```

`--edns-packet-max=1232` gives the C bulk reverse hash 187 buckets in its 1497-byte
packet buffer. The finite lease expires at probe time +3600 seconds; an infinite
lease has expiry zero. The lease file establishes DNS state, not a simulated
DHCP packet exchange; these cases do not claim to validate DHCP ACK handling.

## Exact C controls

| Initial lease | Repeats | Post-HUP PTR owners for 192.0.2.1 | Post-HUP a.test addresses |
| --- | --- | --- | --- |
| none | 4 across v2/v3 | x.test, y.test | 192.0.3.186, 192.0.3.185 |
| infinite a.test | 2, v2 | x.test, y.test | 192.0.3.186, 192.0.3.185 |
| finite a.test | 2, v3 | x.test only | 192.0.3.186, 192.0.3.185 |

UDP and fresh TCP agree on the PTR sets. All C processes remained alive and exited
normally after the probes. PTR order differs across processes because C uses a process
address dependent name hash; set membership is the finding here.

The matching source explains the finite/infinite distinction. `cache_reload`
retains F_DHCP records while replacing F_HOSTS/F_CONFIG. During bulk ingestion,
`cache_find_by_name` rewrites the same `next` links used by the temporary reverse
hash. A finite reverse DHCP entry has different F_IMMORTAL flags from a hosts
entry. It can follow the same-name hosts node in that temporary chain, making
the old lease address visible to the next duplicate-address check. The later
lease rebuild suppresses `a.test` because its static addresses conflict, but the
bulk PTR flags already reflect the retained lease. An infinite lease produces
a different chain order and does not suppress the extra y.test PTR owner.

This requires loader-only DHCP shadows carrying name, address, reverse and
immortal state. They must participate in temporary lookup links without becoming
published hosts or being retained by a TCP snapshot. The new allocator tests
exercise the actual configured-hosts bulk helper with finite/infinite retained
`LeaseNames`, single/persistent failures and held/unshared owners.

## Same-name lease controls

The exact `lease_set_hostname` implementation removes an earlier IPv4 lease's
same short name. `v4` confirmed two leases with short name `a` expose only the
later address. A legal cross-alias case does exist: short names `a` and `a.test`
with domain `test` produce two `a.test` addresses, because one is an FQDN and the
other is a short name. Four initial A queries kept their order; their reverse
flags differ. These observations support the current active-entry shadow input
for the demonstrated states; they do not prove all possible DHCP lookup-order
behaviour.

The `v5` attempt to make both lease aliases non-reverse with preexisting hosts
PTR entries instead caused C to rename the leases from those hosts records.
Its `a.test` answer was absent. This is retained as a negative control, not
reported as a successful same-flags rotation test.

## Candidate b99e replay

Source `b99eae7e54c1d3922368513714da2eaef09cef58`, ELF
`/dev/shm/full-f10-product-20261014/private/release-b99e/dnsmasq-rs`, SHA-256
`edf0f62ca08946cd35aa5b48255575546baaec53d3273723fb25550eb14e5fac`.

The infinite, finite and cross-alias scenarios all produced the correct PTR owner
sets on UDP/TCP. The retained lease records did not leak into the published static
answers. However, all three returned the first post-HUP `a.test` A answer in the
opposite order: Rust `.185,.186`, exact C `.186,.185`. A no-lease Rust control
matched C `.186,.185`, narrowing the difference to the retained-lease path.
These are partial passes, not complete protocol equivalence.

The cross-alias comparison uses `cross-alias-c-matched`, which has precisely the
candidate's query sequence. The earlier `v4` included four extra initial A queries
and is not used as that candidate's sequence control. The later repair/replay
must record a new source/ELF identity rather than replacing these observations.

## Candidate 435f replay

Source `435fe2d65e6b5a59ff77c38a355236627dd2aeea`, ELF
`/dev/shm/full-f10-product-20261014/private/release-435f/dnsmasq-rs`, SHA-256
`0624759903bfc147cfa177b812111498b351202ecd2a5b776b06a19e7d7313bb`.

The same three probes were replayed with only candidate/output identity changed.
Infinite and finite single-lease cases now return the C first A order `.186,.185`.
The cross-alias case still returns `.185,.186`, opposite its matched C control.
All three PTR owner sets remain correct on UDP and TCP, and the processes remained
alive with normal cleanup exits. The additional C/C control below establishes
that this cross-alias order alone is not evidence of a product defect.

The single-lease repair removes an early rebuild against stale lease names. C
first reconciles lease names against the new hosts PTR owners and then publishes
that final source. Rebuilding the old `a.test` lease beforehand performs an extra
hosts lookup and changes the first A order. The main owner tests use the real
provider and `LeasePublisher`, including a held DHCP-options FIFO, to check that
hosts and leases stay on the prior generation until the final provider callback.

### Cross-alias C/C ordering boundary

Three fresh exact-C processes then replayed the same cross-alias inputs and query
sequence. Two renamed the `.1` lease to `x` and returned first A `.185,.186`; one
retained lease name `a` and returned `.186,.185`. All returned the sole PTR owner
`x.test` over UDP and TCP. The [derived control](cross-alias-order.json) retains
both the lease-file identities and the ordered responses.

`host_from_dns` uses only the first `cache_find_by_addr` match: a retained DHCP
record before the hosts record prevents renaming. Their relative name-hash bucket
positions vary between C processes. The later lease publication consequently
checks `a.test` a different number of times and changes its next A order. Thus
435f's cross-alias response is one of the observed C states. This withdraws the
earlier single-reference interpretation of that difference as an open defect;
it does not prove that a hosts-only reverse lookup models every mixed DHCP/hosts
state. The general mixed-chain contract is reviewed separately.

## Evidence and reproduction

The [derived results](derived.json) bind each result to its SHA-256 and retain the
first A order separately from PTR owner observations. `derive.py` regenerates the
derived file from the raw directories in
`/dev/shm/full-f10-dhcp-20261014/private`. The committed Python files are the exact
executed diagnostic drivers; their fixed output directories must be changed
before rerunning. The helpers (`probe.py`, `m2_rootfs.py`, `dns_service_probe.py`,
`run_isolated.sh`, `elf_cost.py`) are preserved in the private evidence archive.

Example execution, after selecting a fresh output directory in the copied driver:

```sh
BASE=/dev/shm/full-f10-dhcp-20261014/private
TOOLS=/dev/shm/full-f10-ptr-20261014/private/tools
sudo -n env PYTHONPATH="$TOOLS" PYTHONDONTWRITEBYTECODE=1 \
  sh "$TOOLS/run_isolated.sh" python3 "$BASE/probe_dhcp_v3.py"
```

Private local backups under this worktree retain the actual requests/responses,
daemon logs, process identities and diagnostic drivers, excluding staged rootfs:

| Archive under private/full-f10-dhcp-20261014 | SHA-256 |
| --- | --- |
| evidence.tar.gz (v2/v3 and helpers/exact C) | f29535b34a53d7a4c042dcdd5bb61602ee4e6d41bc3a65195b0f81a02bfd5345 |
| order-evidence.tar.gz (v4/v5) | 07c378c19ccca90fdd36dc90ae79f7d4621051db7df30615bd98c741e3f10d16 |
| candidate-b99e-evidence.tar.gz (candidate and matched C) | af37eff629ed0d1a3706970982b981daf0a59c4e22043a7961fe4cb7346ba6ce |
| candidate-435f-evidence.tar.gz | 73b7577e4e66c3e247615452225832d600e57bc2bc28e8b46d85629bbb1f222a |
| cross-alias-c-repeats-evidence.tar.gz | e36fe97ff5c4ecbe519ccdfbe472e40cc92a7d7de1a7b7f2083aa34a67a59d20 |
