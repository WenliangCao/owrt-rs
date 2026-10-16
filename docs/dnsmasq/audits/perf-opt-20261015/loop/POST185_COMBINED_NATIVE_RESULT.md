# G / 6ab native hot15 screen

The original 240-window screen completed once: nine scenes were faster, two
were slower, and four remained within variation. Preserve both regressions;
this screen does not qualify or promote 6ab.

The sources were accepted G `185db90c9cabd26c0af09765636ef15bf6d35f79`
and combined `6ab0f064b69087add3be1cb2bf5604fbaf42dffa`. The reviewed
[plan](post185-combined-native-plan.json) and original adapted runner/analyzer
were unchanged during execution. The probe explicitly uses opt3/LTO; these
results do not test the separate 803 opt2 candidate.

| Scene | CPU change | Original W | Same-direction pairs | Decision | User cycles change |
|---|---:|---:|---:|---|---:|
| hit | -6.268% | 1.875% | 5/5 | faster | -6.130% |
| hit-upper | -5.471% | 1.131% | 5/5 | faster | -5.706% |
| hit-leases | -20.911% | 1.039% | 5/5 | faster | -19.822% |
| hit-typed | -6.224% | 2.364% | 5/5 | faster | -5.665% |
| miss | -0.089% | 0.728% | 3/5 | within variation | -0.010% |
| miss-leases | -14.500% | 0.419% | 5/5 | faster | -14.524% |
| host | +0.965% | 1.670% | 5/5 | within variation | +2.166% |
| host-localise | +2.020% | 3.010% | 3/5 | within variation | +0.320% |
| raw-address | +0.001% | 0.447% | 3/5 | within variation | -0.038% |
| synth-address | +2.621% | 1.531% | 5/5 | slower | +2.090% |
| lease-address | -9.219% | 0.583% | 5/5 | faster | -9.111% |
| rrset | -2.941% | 0.274% | 5/5 | faster | -3.092% |
| cname | -2.060% | 0.768% | 5/5 | faster | -2.203% |
| cname-leases | -18.602% | 0.646% | 5/5 | faster | -18.540% |
| cname-config | +4.765% | 0.329% | 5/5 | slower | +4.433% |

All 244 commands completed, including 90 stat and 150 plain windows. All 180
instruction/cycle event rows were unscaled. Operation counts, checksums and
inner-probe zero-allocation checks passed. The author verified 578 command
files and 162 source files per side; no measured window failed or was replaced.
The [derived result](post185-combined-native-result.json) includes every window
and the unchanged analyzer's decisions. The
[postflight](post185-combined-native-postflight.json) records raw hashes and the
quiet boundary before owner32.

Raw result SHA-256:
`e32339dc5822cc05f1f9f543925338f7c2f57a55a204178dbd9402fdc6ed4862`.
Derived result SHA-256:
`ed7e1ac7ea658d1eb176e2fbf2fe271c4fda0e3b438ddf8c5a90c35318812615`.
The complete 590-file private download, including the two probes, is retained
under `private/perf-opt-20261015/post185-combined-native-results/`.
Its archive is 1,555,785 bytes, SHA-256
`d8c808d3679ca3e96d680b4f20685dfd0ddf818b0b4f4f4ae67a8670fea82bde`.

Whole-process `RUSAGE_CHILDREN` includes exec, setup, priming and teardown.
The public probe does not exercise SinglePoll, socket Rc, owner clocks or reply
recycling. These are native host measurements, not physical A53 acceptance.
Independent raw review is pending; correctness owns the host for that review
and the original full44. No full110 or promotion is authorized by this result.
