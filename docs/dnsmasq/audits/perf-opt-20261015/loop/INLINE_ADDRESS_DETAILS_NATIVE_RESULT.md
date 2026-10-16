# Frozen G / bare 1df native240 result

The original 240-window screen completed once: ten scenes faster, one slower,
four within variation. Preserve the miss regression: +0.954% CPU, W=0.388%,
five of five pairs slower. This is G185 versus 1df, including all inherited
6ab changes; it does not isolate the inline-address change.

| Scene | CPU change | W | Same pairs | Original decision | User cycles change |
|---|---:|---:|---:|---|---:|
| hit | -5.932% | 0.592% | 5/5 | faster | -5.745% |
| hit-upper | -4.792% | 0.546% | 5/5 | faster | -4.784% |
| hit-leases | -20.718% | 0.428% | 5/5 | faster | -20.597% |
| hit-typed | -5.803% | 0.738% | 5/5 | faster | -6.077% |
| miss | +0.954% | 0.388% | 5/5 | slower | +1.119% |
| miss-leases | -13.523% | 0.647% | 5/5 | faster | -13.702% |
| host | -0.027% | 2.798% | 2/5 | within variation | +0.858% |
| host-localise | -1.414% | 3.007% | 3/5 | within variation | +0.939% |
| raw-address | +0.268% | 0.558% | 5/5 | within variation | -0.324% |
| synth-address | +0.366% | 0.883% | 3/5 | within variation | -0.593% |
| lease-address | -11.061% | 2.679% | 5/5 | faster | -11.090% |
| rrset | -2.876% | 0.466% | 5/5 | faster | -2.789% |
| cname | -1.255% | 0.566% | 5/5 | faster | -1.377% |
| cname-leases | -17.697% | 0.805% | 5/5 | faster | -18.201% |
| cname-config | -0.425% | 0.220% | 5/5 | faster | -0.444% |

Frozen G source is `185db90c9cabd26c0af09765636ef15bf6d35f79`; candidate
`1df135dc2401a9f0ec2f219b1e4a8f07dd637db1` is based on 6ab. The original
15 scenes, counts, checksums, zero-allocation assertions, order, placements,
opt3/LTO build and statistical rules were unchanged. All 244 commands exited
zero, including 90 stat and 150 plain windows. All 180 PMU event rows were
unscaled. No measured failure, replacement or retry occurred.

The [complete result](inline-address-details-native-result.json) retains all
rows and original decisions; derived SHA-256:
`48ef6c28ed983c6e37c635092d278e3fb7f1963179da6f1b2d421c5fe24ec74f`.
The [postflight](inline-address-details-native-postflight.json), SHA-256
`f43a44e0f44d9bc00d65aeb67e26e8016d57dad5db02bbdbd221179d1a4c2818`,
rechecks 578 command files, both 162-file protected source inventories and
the two actual probe ELFs. Raw result SHA-256:
`239912cb5c076a1f80d3ba91ebdb4127cdc6a0af097103f94febff7e864e7ecf`.

The full private archive is 1,534,678 bytes, SHA-256
`b5b79d77ae27ba0644094da0b669f163496cd7fb528d61655da412e3460fe3c5`;
collection SHA-256:
`14631431ed4158abcb39c16b6ac45aef512998c97aa71f69bb43e5642be47e6e`.
All 591 members were downloaded and rehashed under
`private/perf-opt-20261015/inline-address-details-native-results/`, including
both probe ELFs. The original analyzer ran locally once after all timing.

Whole-process CPU and PMU include exec/setup/priming/teardown. The public
library probe omits SinglePoll, owner recycling, private socket Rc and owner
clocks; this is not exact-SDK or physical-device performance acceptance.
Existing 6ab adverse results remain evidence and are not replaced by this
new candidate run. Independent raw review is pending; no promotion follows
from these native results alone.
