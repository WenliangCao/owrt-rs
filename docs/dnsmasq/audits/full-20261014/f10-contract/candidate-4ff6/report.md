# F10 4ff6 candidate: strict observed-manifest result

**Not accepted.** The single 13-case run completed 704 DNS observations, but real `--require-contract` returned exit 1. Eight `six-host-record` PTR order differences have no corresponding C/C state in the unchanged manifest. No additional C run or generalized exemption was used.

- Source: `4ff6a8a27f6a835b5e8cb90a256211fa96383eb5`.
- ELF: `/dev/shm/full-f10-product-20261014/private/release-4ff6/dnsmasq-rs`.
- SHA-256: `a2e4fa11516a39c8018b7fb40bd94ec91ff5df5e15366b160309dbf0d2a07df4`; 2,114,016 bytes.
- Checker and probe exactly match `source-4ff6`; their hashes and argv are recorded.
- The observed manifest remains 11 tracks / 23 states. Candidate input, running process identities and post-run ELF hashes match.

All eight failures query `1.2.0.192.in-addr.arpa`, type PTR, in `six-host-record`. C controls return `[x.test, y.test]`; the candidate returns `[y.test, x.test]`. The unqualified states are `udp-ptr-before-192.0.2.1`, `udp-ptr-after-192.0.2.1`, `tcp-ptr-before-192.0.2.1` and `tcp-ptr-after-192.0.2.1`, with two observations each. These remain failures pending a separately reviewed source-derived contract or product change.

The other 19 PTR order differences match the exact manifest state and one complete C query track. There are no RRset/header/TTL/count/TC or A/AAAA-order differences, runtime errors, or same-state PTR instability findings. All 205 repeated PTR state families were checked.

| Case | DNS observations | Contract | Qualified PTR order | Unqualified differences |
| --- | ---: | --- | ---: | ---: |
| six-addn | 28 | PASS | 0 | 0 |
| six-default | 28 | PASS | 0 | 0 |
| six-host-record | 28 | FAIL | 0 | 8 |
| six-hostsdir-initial | 28 | PASS | 0 | 0 |
| split-addn-bulk | 28 | PASS | 0 | 0 |
| ipv6-three-duplicate | 100 | PASS | 8 | 0 |
| no-round-robin | 100 | PASS | 0 | 0 |
| mixed-sources | 28 | PASS | 8 | 0 |
| hostsdir-transitions | 252 | PASS | 0 | 0 |
| leases-dhcp | 46 | PASS | 0 | 0 |
| udp-truncation | 5 | PASS | 0 | 0 |
| ipv6-repeated-ptr | 28 | PASS | 0 | 0 |
| ptr-truncation | 5 | PASS | 3 | 0 |

Raw output: `oracle:/dev/shm/full-f10-contract-20261014/private/candidate-4ff6`. Ignored local backup: `private/f10-contract-20261014/candidate-4ff6-evidence.tar.gz`.
Backup SHA-256: `a5b1ca072623d0f3b126fee969ff9f953e330d463817afe51632caaef0dcf8ab`; all 104 indexed regular files verified. Cleanup found no fixture-rooted processes or host-namespace mounts. Prior b99e and C evidence remains unchanged.

Artifacts: [result](result.json), [raw index](raw-index.json), [derivation](derive.py). No physical router or Git remote state was accessed.
