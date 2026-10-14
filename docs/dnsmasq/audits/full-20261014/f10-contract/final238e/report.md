# 238e candidate: observed-only strict contract result

**Not accepted under the current observed manifest.** One run completed all 13 cases and 704 DNS observations, but `--require-contract` returned exit 1: 28 PTR-order differences have no corresponding observed C/C state. No source-derived proposal was used, and no C process was rerun to seek another initial order.

- Source: `238e7ca4374b1889696f91816c1c239d7fe32baa`.
- ELF: `/dev/shm/full-f10-product-20261014/private/release-238e/dnsmasq-rs`.
- ELF SHA-256: `2692c760be3719b15f4bcadb6c5a1445a9f37993a11c1369619550218e4c76eb`; 2,122,208 bytes.
- Test tool snapshot: commit `d72ca9d9`, independently staged under `tools-final238e`.
- Test checker SHA-256: `1134ed0b6768ee49465241aeb5f8fb70b8079110df902f2d0594123226c01577`.
- Frozen source checker SHA-256: `f0a06e3790bfa4371f861dc68f8afbdc30190770652d9cc8a93bf279f735deec`.
- The checker is the only tool differing from the frozen source: it supports explicitly reviewed source-bound entries, but this run supplied none (`source_bound_checks=[]`). Probe and other helpers match.

The input ELF, each running process ELF, post-run ELF and the independent tool snapshot identities matched their recorded hashes. The manifest remains the original 11 tracks / 23 observed states.

| Unqualified case | PTR question | State families | C order | Candidate order | Count |
| --- | --- | --- | --- | --- | ---: |
| six-hostsdir-initial | 192.0.2.1 reverse | UDP/TCP before/after | y.test, x.test | x.test, y.test | 8 |
| leases-dhcp | 192.0.2.1 reverse | UDP/TCP before/after, after-DHCP before/after | y.test, x.test | x.test, y.test | 12 |
| ipv6-repeated-ptr | 2001:db8::1 reverse | UDP/TCP before/after | x6.test, y6.test | y6.test, x6.test | 8 |

Each listed state has two observations. All detailed labels and full records remain in the result. The separate six-host-record proposal does not qualify these cases.

Another 16 PTR-order differences match the precise observed state and complete C sequence. No RRset/header/TTL/count/TC or A/AAAA-order difference occurred. There were no runtime errors or same-state instability findings across 205 repeated PTR state families.

| Case | DNS observations | Current contract | Qualified PTR order | Unqualified differences |
| --- | ---: | --- | ---: | ---: |
| six-addn | 28 | PASS | 0 | 0 |
| six-default | 28 | PASS | 0 | 0 |
| six-host-record | 28 | PASS | 0 | 0 |
| six-hostsdir-initial | 28 | FAIL | 0 | 8 |
| split-addn-bulk | 28 | PASS | 0 | 0 |
| ipv6-three-duplicate | 100 | PASS | 0 | 0 |
| no-round-robin | 100 | PASS | 8 | 0 |
| mixed-sources | 28 | PASS | 8 | 0 |
| hostsdir-transitions | 252 | PASS | 0 | 0 |
| leases-dhcp | 46 | FAIL | 0 | 12 |
| udp-truncation | 5 | PASS | 0 | 0 |
| ipv6-repeated-ptr | 28 | FAIL | 0 | 8 |
| ptr-truncation | 5 | PASS | 0 | 0 |

Raw output: `oracle:/dev/shm/full-f10-contract-20261014/private/final238e`. Local ignored backup: `private/f10-contract-20261014/final238e-evidence.tar.gz`.
Backup SHA-256: `2ded32e7b05bb945e79767fdd50963b0dae57c9c860f6352b2006aa3b5470be2`; all 104 indexed regular files verified. Cleanup found no fixture-rooted processes or host-namespace mounts. Prior C, b99e and 4ff6 results remain unchanged.

Artifacts: [result](result.json), [raw index](raw-index.json), [derivation](derive.py). This run touched no physical router, product source or remote Git state.
