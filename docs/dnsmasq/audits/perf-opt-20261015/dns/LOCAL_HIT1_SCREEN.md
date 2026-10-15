# Local address path screen

Candidate `6f594d7b` is independently based on E source `4f869c88`. Exact C/E cycle profiles identified the two local-answer functions as 20.32% of E UDP user-cycle self samples and 14.41% of TCP samples. The candidate checks only whether an A/AAAA query has a configured raw record of its type; otherwise it runs the existing address-family loop directly. The same loop remains in the generic path.

The address-family loop is byte-identical to E (SHA-256 `8419b0013ccd17119e00d520fb4fc29c7ef9a8aa6230dfe402431b7ab824c140`). Interfaces, lease lookup, hosts rotation/localisation, logging and synthetic/cache suppression retain their order. Raw A/AAAA and ANY stay on the generic path, which passes the existing raw prefix into the helper and preserves prior ownership. No fixed bucket seed, new configuration cache, inline directive or data-structure rewrite was added.

Mac library tests passed 713 with eight ignored; Linux passed 828 with 20 ignored. The two new tests cover mixed raw/address ordering and synthesis suppression, plus unrelated-raw invariance across addresses, CNAME, misses, other types and rotation. Independent source review found no blocker.

## Native controls and quiet screen

The existing whole-answer probe was extended with typed-record, raw-address, synthesis, lease-address and local-network controls. Both sides use the same fixture and native compiler/LTO settings. All 30 allocation-control processes completed 8,000 operations with matching answer-length checksums and zero final live bytes. `hit-typed` removes one allocation and 23 requested bytes per query. Other allocation counts match. The localised-host control has different bucket-copy reallocation totals across processes; the unchanged hosts hash mixes relocated pointer bytes, so these one-process totals are retained without assigning the difference to this patch.

The frozen quiet screen completed all 150 windows: 15 scenes, five alternating pairs, 200,000 operations/window, CPU2, uninstrumented allocator, no perf/strace. Every checksum matches its allocation-control value scaled by25; all plain diagnostic counters are zero. No timing window was retried or replaced.

| Scene | CPU median change | W | Improving pairs | Diagnostic classification |
|---|---:|---:|---:|---|
| hit | -2.695% | 2.209% | 5/5 | improvement |
| hit-upper | -2.699% | 2.699% | 5/5 | indistinguishable |
| hit-leases | -2.271% | 1.046% | 5/5 | improvement |
| hit-typed | -10.922% | 1.213% | 5/5 | improvement |
| miss | -4.452% | 1.098% | 5/5 | improvement |
| miss-leases | -3.866% | 1.024% | 5/5 | improvement |
| host | -2.065% | 1.579% | 5/5 | improvement |
| host-localise | -2.715% | 2.857% | 5/5 | indistinguishable |
| raw-address | +0.098% | 0.574% | 2/5 | indistinguishable |
| synth-address | -2.481% | 0.534% | 5/5 | improvement |
| lease-address | -1.268% | 0.575% | 5/5 | improvement |
| rrset | -1.946% | 0.619% | 5/5 | improvement |
| cname | -1.811% | 0.571% | 5/5 | improvement |
| cname-leases | -1.493% | 0.807% | 5/5 | improvement |
| cname-config | -2.227% | 0.177% | 5/5 | improvement |

Twelve scenes improve beyond the existing native-screen W rule, three remain indistinguishable, and none meets its regression rule. The ordinary cache-hit result is −2.695%; configured typed records benefit more. These results support testing the patch in F. They do not establish a daemon/network or physical-router improvement, and are not additive to the separate UDP-admission or packet-info changes.

Two pre-workload tooling failures remain in the receipts: the first standalone probe link omitted LTO, and the first timing launcher passed a leading-dash argument in a form argparse rejected. Both were corrected before the corresponding workload began; no measured result was discarded.

Full evidence: [source/build/allocation receipt](local-hit1-count-screen.json), [frozen plain plan](local-hit1-plain-plan.json), [all 150 plain rows and derived statistics](local-hit1-plain-summary.json). Native binaries/logs remain under Oracle private `dns/private/local-hit1-screen`.
