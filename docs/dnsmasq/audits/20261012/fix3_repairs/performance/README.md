# Shared UDP/TCP answer performance evidence

The plan was frozen before any performance window. It binds the reused, fresh
FIX3 main release and its source inputs, the new Oracle release, complete
candidate product inputs, measurement tools, exact-image files and helper
identities. The SDK payload is separately source-built and used by the full
functional suite; it is not the Oracle release measured here.

- Root: `/home/ubuntu/dnsmasq-fix3-repair-20261013`.
- Candidate source: `0ff33bb025bd789aac78e3f6878456449fbde7fc`.
- Product change tip: `8c1cfefcddea08166e349964c144544b9dd4786b`.
- Main: `be531cee49e366bb5044443d473944dbea45b87e`.
- Main ELF SHA256: `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`.
- Candidate ELF SHA256: `05f35c832c7d405aebdc8ef94ac8f479f81bfcdc6f1f066625ab94a5c0c0303a`.
- Plan SHA256: `6f52ba6de35fb7d81707ed9c1937bd61eb23bfd5f4141a52a98bd677a5837c82`.

TCP cache hits with 100 and 1,000 unrelated `dns-rr` entries each have six
adjacent same-seed main/candidate pairs, three AB and three BA. The primary
profile order alternates each round. Two opposite-order UDP/1,000 and TCP/0
pairs are descriptive controls, interleaved after primary rounds three and
six. There are 32 windows total. Each has 10 seconds of idle observation,
30 seconds of warmup and 120 seconds of measurement at 1,000 queries/second,
20 clients and 4,096 proved cached A names. The native TCP client reconnects
after every 100 queries. The upstream stops answering after the per-name
cache proof and still counts attempted upstream requests.

The primary estimator is cgroup CPU microseconds per correct completion in
the measurement epoch. Each primary scenario reports six paired ratios,
their geometric mean and a 95% paired log-t interval with five degrees of
freedom. The exact previous estimator is reused by SHA. A lower bound above
1 confirms increased cost for that workload. Crossing 1 is unresolved;
10% is a scale marker, never a permitted regression. The two-pair controls
have no inferential intervals and do not close S1. Cross-profile subtraction
is not causal attribution. Every window, behavior error, skip and failure is
retained; there is no rerun, replacement or range/unanimity filter.

The driver refuses an existing run, requires a completed build/function
receipt, takes the shared build lock, checks for competing task workloads
before every window and pins daemon/upstream/generator/controller to CPUs
0/1/2/3. The full command list is in `plan.json`. Only the primary controller
may start after functional testing has finished.

To reproduce in the retained Oracle environment, choose a fresh private
output directory and run the `prepare`, then `run` subcommands from
`paired_tcp_records.py`. Supply the frozen source commit, ELF SHA and a
truthful completed build/function receipt. To reproduce in a new environment,
first prepare the frozen source, main artifact, image, native tools and SDK
as recorded, update the driver's root constants, and freeze a new plan.
Never overwrite this run's output. The source-built SDK driver and exact
standard/map clean-build identity are recorded separately under `../build/`.

This is an Oracle AArch64 fixed-rate synthetic comparison, not physical
router, saturation, long-duration leak, or broad performance equivalence
qualification. Host pressure snapshots and cgroup counters can reveal task
interference or throttling, but cannot exclude virtual-machine neighbor
noise.

## First shared-answer candidate: N4 remains open

All 32 planned windows completed and were accepted. This is an unfavorable
performance result, retained before further changes; it is not a final pass.
The candidate is still product `8c1cfefc` / source `0ff33bb0` above.

| Primary profile | CPU geometric fix/main ratio | Paired 95% interval | Pairs with increased CPU |
| --- | ---: | --- | ---: |
| TCP, 100 unrelated records | 1.123818 | [1.018827, 1.239627] | 6/6 |
| TCP, 1,000 unrelated records | 1.267995 | [1.125444, 1.428601] | 6/6 |

Both profiles confirm increased CPU; the 1,000-record lower bound also exceeds
1.10. The 100-record AB/BA median ratios are 1.069444 / 1.118534; the
1,000-record ratios are 1.354697 / 1.251136. The original multiples of CPU cost
have decreased, but the remaining configuration-related increase prevents
closing N4. No window was discarded, including the higher individual samples.

The UDP/1,000-record control ratios are 0.242928 / 0.235866; the TCP/0 ratios
are 0.974013 / 1.024059. These are two-pair descriptive controls, without
inferential intervals, and do not close S1 or causally isolate a source
function. No extra experiment or repeat of this artifact was started.

Warmup plus measurement planned/sent/correct totals are all 4,800,000;
wrong/timeout/transport-error/skipped totals are zero. All 4,096 names per
window passed the cache proof, upstream answers were disabled, and attempted
upstream requests during hits were zero. All paired configuration hashes
match. The 480 retained cgroup counter observations show zero throttling;
all pre-window competing-workload checks and the final check were empty.
This does not exclude virtualization-neighbor variation.

- [First candidate statistics](shared-answer-first-summary.json)
- [All raw input and controller hashes](shared-answer-first-raw-index.json)
- [Cache, counters, configuration and identity checks](shared-answer-first-counter-check.json)

The original full summary remains at
`private/performance-paired-01/summary.json` on Oracle, SHA256
`a16e334a32f17f944e04d428968b58ddac1cdd139f27dab5bf3560262bcaa4b0`.
`collect_performance.py` only derives the retained summaries after completion.
`launch_performance.py` preserves the actual controller exit across an SSH
session ending, and `performance_status.py` reads completion/acceptance only;
neither changes the frozen benchmark plan or uses interim CPU values to stop
or select windows.
