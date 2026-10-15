# Independent dotted/singleton native screen: gains with retained regressions

Both F-based prototypes improve ordinary cache hits, but each has discernible
regressions under the frozen native decision rule. Dotted has 10 faster, four
within-variation and one slower scene; singleton has seven faster, four
within-variation and four slower scenes. Neither result supports selecting the
prototype unchanged for a candidate requiring no performance regressions.

All 480 windows completed: 180 grouped PMU and 300 plain, with six successful
build commands. There were no failed or replaced measurement windows. The
unchanged layout runner used the separately committed plan `b0cd7fd8`; the
earlier 320-window instruction/allocation results were excluded. Each
prototype was compared against its own alternating F controls, with no pooling
between candidates and no combination of the two changes.

CPU changes below use five whole-process `RUSAGE_CHILDREN` pairs, normalized by
the actual operation count. W is the larger relative range of either side.
The original decision requires an absolute median change greater than W and
at least four of five pairs in that direction. Setup, priming, process startup
and teardown are included; controller CPU is excluded. These are native
mechanism results, not daemon tick-resolution claims or device acceptance.

| Scene | Dotted CPU change / W | Decision | Singleton CPU change / W | Decision |
| --- | ---: | --- | ---: | --- |
| hit | -4.240% / 1.758% | faster | -3.714% / 0.339% | faster |
| hit-upper | -4.200% / 0.509% | faster | -3.360% / 1.378% | faster |
| hit-leases | -2.886% / 0.442% | faster | -2.846% / 0.424% | faster |
| hit-typed | -3.650% / 2.434% | faster | -3.714% / 1.741% | faster |
| miss | -5.019% / 0.759% | faster | +0.627% / 0.354% | slower |
| miss-leases | -4.340% / 0.462% | faster | +0.909% / 0.939% | within variation |
| host | -2.884% / 2.964% | within variation | -0.864% / 3.089% | within variation |
| host-localise | -3.289% / 4.630% | within variation | -0.618% / 2.841% | within variation |
| raw-address | +0.016% / 0.421% | within variation | -0.320% / 0.516% | within variation |
| synth-address | -1.519% / 1.845% | within variation | +2.214% / 1.244% | slower |
| lease-address | -2.075% / 0.574% | faster | +0.421% / 0.373% | slower |
| rrset | -1.673% / 1.410% | faster | +1.683% / 0.654% | slower |
| cname | -1.020% / 0.310% | faster | -1.698% / 0.833% | faster |
| cname-leases | -2.765% / 0.913% | faster | -1.024% / 0.653% | faster |
| cname-config | +5.089% / 0.236% | slower | -1.312% / 0.385% | faster |

Dotted ordinary-hit instructions/cycles fall 4.373%/4.334%, with per-window
IPC medians 2.621 to 2.620. Configured CNAME instead has instructions -0.049%,
cycles +4.841%, and IPC 3.272 to 3.118; all five plain pairs are slower. This
run therefore exposes an execution-efficiency loss despite almost unchanged
instruction count. The experiment does not isolate its microarchitectural
cause.

Singleton ordinary-hit instructions/cycles fall 4.502%/3.550%, with IPC 2.628
to 2.602. Its four CPU regressions also have higher median cycles: miss
+0.680%, synth-address +1.982%, lease-address +0.426%, rrset +1.933%.
Lease-address has four of five adverse CPU pairs; the other three have five.
The within-variation miss-leases increase of 0.909% is retained as well.
Three-pair PMU measurements describe these mechanisms; they do not inherit
the five-pair CPU significance decision.

The independent completion check verified all 480 unique labels and their
exact fixed execution order, operation counts, checksums, 180 unscaled
same-window PMU groups and IPC ratios, and 30 comparisons. The runner checked
source identities before and after execution; a final read-only check again
verified 486 source-file hashes and all three ELF hashes. No screen process
remained. Allocation tracking was disabled for timing; zero allocation fields
are the expected disabled-counter sentinel, not an allocation-free claim.
The probe's answer-count/rcode/ID priming checks and length checksum are coarse
work sentinels, not frozen-C correctness evidence.

The complete result SHA256 is
`a78fc0cb191c1c7c904087e2c2fcd94f4a41cf7a6d6f887ca1cf7ced3e3d5e73`.
Only its 51,128-byte compressed JSON was transferred during the separate
device stage experiment. Raw stdout/stderr, perf CSVs and native ELFs remain
in Oracle private `dns/private/post-f-native-cpu-screen1`; the complete JSON
is also retained locally under private `perf-opt-20261015/post-f-native-cpu-screen`.

[All 480 derived rows, identities and comparisons](post-f-native-cpu-result.json),
[fixed plan](post-f-native-cpu-plan.json),
[unchanged runner](run_layout_native_screen.py),
[path-adapted analysis](analyze_post_f_native_cpu.py).
