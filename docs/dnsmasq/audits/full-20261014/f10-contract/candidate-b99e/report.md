# F10 b99e candidate: early contract result, qualifier superseded

This is an early result whose global PTR-order exemption was too broad. It is **not final acceptance**. Offline requalification of the unchanged raw evidence now fails: 16 PTR differences have matching C/C state and complete-query-sequence evidence, but 12 `leases-dhcp` differences have no such qualification. See [the recheck](../qualifier/b99e-recheck.json).

All 13 planned cases ran to completion across 704 DNS observations. RRset/header/TTL/count/TC and A/AAAA-order comparisons matched, but those narrower checks did not establish the required PTR ordering contract.

- Source: `b99eae7e54c1d3922368513714da2eaef09cef58`.
- Candidate: `/dev/shm/full-f10-product-20261014/private/release-b99e/dnsmasq-rs`.
- ELF SHA-256: `edf0f62ca08946cd35aa5b48255575546baaec53d3273723fb25550eb14e5fac`; 2,130,400 bytes.
- Probe SHA-256: `7e240b2f03f112b63cb552e725834a378556bc7df6e46908012d0f6d718d21c8`.
- Run duration: 28.722 seconds. Candidate SHA-256 matched before/after and each running process identity matched.

| Case | DNS observations | Original narrower checks | PTR-order-only differences |
| --- | ---: | --- | ---: |
| six-addn | 28 | PASS | 0 |
| six-default | 28 | PASS | 8 |
| six-host-record | 28 | PASS | 0 |
| six-hostsdir-initial | 28 | PASS | 0 |
| split-addn-bulk | 28 | PASS | 0 |
| ipv6-three-duplicate | 100 | PASS | 8 |
| no-round-robin | 100 | PASS | 0 |
| mixed-sources | 28 | PASS | 0 |
| hostsdir-transitions | 252 | PASS | 0 |
| leases-dhcp | 46 | PASS | 12 |
| udp-truncation | 5 | PASS | 0 |
| ipv6-repeated-ptr | 28 | PASS | 0 |
| ptr-truncation | 5 | PASS | 0 |

The remaining 28 differences concern only PTR owner order: six-default 8, ipv6-three-duplicate 8, leases-dhcp 12. Exact C independently showed 43 PTR-order-only differences across repeated processes, with no set/TTL/count/header variation. That fact applies only to the evidenced case/question/transport/state and complete query sequence, not globally. The ordered wires and all 28 candidate differences remain in the original results. Full ordered equality is false; the current state-scoped qualifier also fails on the 12 lease-case differences.

The original narrower checks covered the six-row repeated-address counterexample, IPv6 collision, three-address/duplicate/no-round-robin variants, split bulk files, source mixtures, and hostsdir create/replace/delete/recreate/HUP. Held old/new TCP snapshots were observed through all directory transitions. Restored/live lease DNS and the real DHCP ACK passed. Both the 48-A and two-long-PTR fixtures showed UDP truncation with complete held/new TCP answers; the long PTR UDP response omitted the whole RRset as C does.

The retained 340ed negative control has 81 RRset/TTL/count/header differences and 51 forward-order differences across the same 704 observations. This early run used the existing C results without overwriting them and did not repeat large rolling or memory-budget gates.

Oracle raw output: `/dev/shm/full-f10-contract-20261014/private/candidate-b99e`. Local ignored backup: `private/f10-contract-20261014/candidate-b99e-evidence.tar.gz`.
Backup SHA-256: `4b148e5c71bf27b9da260bac5d00403a759749a57bc6fd9a7946bbfc24d01b7d`; all 101 indexed regular files verified. Cleanup found no fixture-rooted processes or host-namespace mounts.

Artifacts: [derived result](result.json), [raw index](raw-index.json), [derivation](derive.py). No product, physical router, main branch or remote Git state was changed by this probe.
