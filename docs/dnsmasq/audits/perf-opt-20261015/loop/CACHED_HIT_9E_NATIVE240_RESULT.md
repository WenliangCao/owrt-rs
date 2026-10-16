# Original G / integrated9e native240 result

All 240 original windows and four build commands completed once. Under the original CPU rule, 12 scenes are faster; host, host-localise and raw-address remain inconclusive. No current native CPU regression is discernible. Earlier adverse 6ab/1df screens remain evidence from their own sources.

| Original scene | G CPU ns/op | 9e CPU ns/op | Change | W | Same pairs | Original decision |
|---|---:|---:|---:|---:|---:|---|
| hit | 426.976 | 389.376 | -8.806% | 2.678% | 5/5 | faster |
| hit-upper | 442.423 | 410.904 | -7.124% | 0.443% | 5/5 | faster |
| hit-leases | 555.406 | 430.558 | -22.479% | 1.447% | 5/5 | faster |
| hit-typed | 427.561 | 389.824 | -8.826% | 0.649% | 5/5 | faster |
| miss | 387.320 | 378.678 | -2.231% | 0.715% | 5/5 | faster |
| miss-leases | 486.236 | 407.099 | -16.275% | 1.418% | 5/5 | faster |
| host | 880.649 | 863.380 | -1.961% | 4.505% | 4/5 | inconclusive |
| host-localise | 1713.216 | 1624.094 | -5.202% | 12.563% | 3/5 | inconclusive |
| raw-address | 6707.215 | 6673.710 | -0.500% | 0.540% | 5/5 | inconclusive |
| synth-address | 827.990 | 809.221 | -2.267% | 1.890% | 5/5 | faster |
| lease-address | 720.418 | 633.216 | -12.104% | 0.706% | 5/5 | faster |
| rrset | 1515.117 | 1449.608 | -4.324% | 0.403% | 5/5 | faster |
| cname | 1083.626 | 1057.536 | -2.408% | 0.763% | 5/5 | faster |
| cname-leases | 1345.690 | 1096.783 | -18.497% | 0.454% | 5/5 | faster |
| cname-config | 23002.775 | 22875.810 | -0.552% | 0.378% | 5/5 | faster |

This is frozen G185 versus `9e8459dd704d339b10596721eaa2d3bef1f943c1`, including inherited 6ab and multiple integrated changes. It does not isolate a component. The original hot15 probe never recycles replies and does not execute the main owner; these observations do not cover the warm-buffer branch or establish physical-device gain.

Original 15 scenes, three stat and five plain pairs, operation counts, checksums, allocation predicates, CPU2/nice10 and build flags are unchanged. All 180 grouped PMU events were unscaled. CPU uses the original whole-child RUSAGE delta, including setup, priming and teardown. Complete per-round CPU/PMU/IPC values and full ranges remain in the [original summary](cached-hit-9e-native-summary.json); no alternative estimator or outlier selection was used.

The controller started at 12:29:14 UTC on 2026-10-16, including four builds. The first measured command started at 12:30:02.378639 UTC. The last command recorded start epoch 1792154122.2049572 and elapsed 4,613,934,340 ns; their sum gives an approximate end of 12:35:26.818891 UTC. The original controller records no separate final exit epoch. Its completion and subsequent [postflight](cached-hit-9e-native-postflight.json) establish that all original windows finished and the controller exited.

The postflight rehashed 578 command files, both original 162-file native source sets and both probe ELFs. The [transport receipt](cached-hit-9e-native-download-receipt.json) verifies all 592 archive members, including both ELFs; nothing was omitted from native transfer. The original local analyzer ran once and produced SHA-256 `9d9168cf8711e2b2633966072df423d1ed74044a55def55cb43f0ccf9b3a761d`.

The [manifest-scope correction](cached-hit-9e-native-manifest-scope-correction.json) was made before any build or window: native returned to the original 162-key set, while the outer SDK prerequisite verified both full 179-key sets. Original disabled input bytes remain in before-ready evidence. The [scope text note](cached-hit-9e-plan-scope-text-note.json) records stale preparation wording in frozen executed plans; actual ready/launch and qualification evidence, not that prose, identify the executed run. No timed plan was edited.

Original native timing overlapped the separately hosted device ten. That device screen found all three primary metrics inconclusive. Owner32 followed the original native raw/postflight and fresh-quiet boundary; all additional bulk waited until both timing phases finished. Following the [fresh handoff](cached-hit-9e-screen-release-to-correctness.json), the [independent native audit](../correctness/cached-hit-9e-native-independent-audit.json) passed (commit `33855b34`, SHA-256 `9516d584e740430ab7c73ab62b225769dfbe46d3edfc47958c121b111b68a670`). No promotion or full110 follows from these native results.
