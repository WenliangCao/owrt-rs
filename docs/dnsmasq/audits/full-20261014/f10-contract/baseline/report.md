# F10 contract: exact-C controls and 340ed negative baseline

13 finite scenarios cover 704 DNS observations. All C and old Rust scenarios completed with expected process identity, readiness and clean shutdown. The old candidate remains a negative control: 81 RRset/TTL/count/header differences and 51 forward-order differences.

- C ELF SHA-256: `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
- Negative source: `340ed73e83e58ba845e0a645eb21e9ead0d0f108`.
- Negative ELF SHA-256: `edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d`.

| Case | DNS observations | RRset/TTL/count/header differences | Forward-order differences |
| --- | ---: | ---: | ---: |
| six-addn | 28 | 8 | 6 |
| six-default | 28 | 8 | 6 |
| six-host-record | 28 | 8 | 6 |
| six-hostsdir-initial | 28 | 8 | 6 |
| split-addn-bulk | 28 | 0 | 0 |
| ipv6-three-duplicate | 100 | 8 | 6 |
| no-round-robin | 100 | 8 | 0 |
| mixed-sources | 28 | 8 | 6 |
| hostsdir-transitions | 252 | 0 | 0 |
| leases-dhcp | 46 | 12 | 9 |
| udp-truncation | 5 | 0 | 0 |
| ipv6-repeated-ptr | 28 | 8 | 6 |
| ptr-truncation | 5 | 5 | 0 |

Independent C processes demonstrate PTR order variability: 40 order-only differences across the original 671 observations, plus 3 order-only differences across the 33 focused IPv6/long-PTR observations. No C/C RRset, TTL, count or header difference occurred. Raw ordered replies are retained; these controls do not justify claiming byte equality or silently ignoring forward order.

The six-row addn/default/host-record/hostsdir-initial fixtures expose the missing repeated-address PTR owner. Splitting the same rows into two addn files, hostsdir create/replace/delete/recreate/HUP with held/new TCP snapshots, and 48-address UDP truncation are retained as passing adjacent controls. Restored and live DHCP leases include a real ACK and DNS/PTR observations.

The focused IPv6 fixture uses the ::1/::bc address-hash collision. The long-PTR control uses two 252-character names: exact C returns UDP 40-byte TC=1/AN=0 replies and complete 572-byte TCP replies with two owners. Old Rust omits an owner and therefore misses the UDP truncation boundary.

`f10_contract_probe.py` retains full ordered semantics and wires. Its `matches_c`/`--require-match` remain strict, including PTR order. `difference_counts` and `set_and_forward_order_match_c` expose the separately reviewed PTR-order exception without altering raw observations. The classification-only update was checked offline against all 704 archived negative-control observations; no runtime cases were repeated for that update.

Original 11-case runs were preserved. Two focused cases were then added, with one further C pass over the original cases and independent C repeats for the added pair; only the added pair was rerun on 340ed. No large rolling workload or memory gate was rerun.

Oracle raw root: `/dev/shm/full-f10-contract-20261014/private`. Local ignored backup: `private/f10-contract-20261014/baseline-evidence.tar.gz`.
Backup SHA-256: `9dcfab0fe04b9f65f0e331fd1e9584d01e49e519997f901416a14a119dcfaf7f`; 321 regular files verified against the archive. Cleanup found no fixture-rooted processes or host-namespace mounts.

Artifacts: [derived result](result.json), [raw index](raw-index.json), [derivation](derive.py). The fixture remains isolated on Oracle; no physical router was accessed.
