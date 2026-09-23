# R138 bounded Oracle REMOVE screen

Use the unchanged [R137 fixed-path builder](../r137/README.md) and
[R136 five-lane runner](../r136/README.md). No router jobs or runtime edits
belong to these tools. The only candidate is the conservative REMOVE fast path;
the three named object-event lanes deliberately exercise its fallback.

The build manifest has exactly two variants, `r136` and `remove`, each with an
immutable clean `components/` snapshot. Set `r136.expected_sha256` to
`ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`.
Both compile at `/tmp/owrt-build/r135/r136-combined-01` in separate namespaces.
Candidate and control sources differ only by the reviewed runtime patch.

Run on Oracle as `ubuntu`, from the repository/tool snapshot. Use new paths for
each run; commands below assume inputs at `/home/ubuntu/r138/build-plan.json`
and the frozen R136 manifest at `/home/ubuntu/r136/screen-manifest-02.json`.

```sh
python3 tools/r137/build_batch.py /home/ubuntu/r138/build-plan.json \
  --build-script /home/ubuntu/r136/tools/build_variant.sh \
  --jobs 2 --output /home/ubuntu/r138/build-01
python3 tools/r138/make_screen_manifest.py /home/ubuntu/r138/build-01 \
  --reference /home/ubuntu/r136/screen-manifest-02.json \
  --output /home/ubuntu/r138/screen-manifest.json
```

Finish all builds and exact-candidate unit/wire gates before timing. Coordinate
exclusive host use for timing; no compilation, tracing or other performance
jobs may overlap. Correctness probes that demonstrate successful daemon and
caller operation satisfy the smoke gate; otherwise run one registration cycle
separately, without adding it to the screen.

The frozen screen is C, R136 and REMOVE; two disjoint daemon:caller CPU pairs
`1:0,3:2`; four balanced forward/reverse blocks; 10,000 measured cycles and 20
warmups; register 1/16 methods and object-event fanout 1/8/no-match; caller
split-core and pair-allowed affinities. This is exactly 240 raw records. Each
pair runs independently; shared host resources remain a limitation and the two
pairs are never pooled. Do not extend the screen in response to its results.

```sh
sudo -n python3 tools/r136/oracle_batch.py /home/ubuntu/r138/screen-manifest.json \
  --output /home/ubuntu/r138/screen-01 --pairs 1:0,3:2 \
  --repeats 4 --iterations 10000 --warmup 20
python3 tools/r138/analyze_screen.py /home/ubuntu/r138/screen-01 \
  --output /home/ubuntu/r138/screen-results.json
```

`make_screen_manifest.py` accepts only a successful fixed-path build with the
exact measured R136 control. It retains the deployment C, benchmark and shared
library identities from the frozen reference. The unchanged runner rechecks
every ELF/library live. `analyze_screen.py` runs the complete R136 archive
verifier, then adds same-pair/block/affinity/lane contrasts to the actual R136
control. It does not rename R136 to the old R134 control. Report every signed
delta, including tails and caller CPU; absolute paired median at most 1% is
unresolved. These exploratory results cannot authorize deployment or claim
router gains.

The [frozen policy](screen-policy.json) is embedded in the screen manifest
before timing. Eligibility requires register-1 mean and daemon CPU each below
−3% paired median with at least 3/4 decreases on both split CPU pairs. Any of
the five lanes, either affinity and either pair vetoes eligibility if mean,
p95 or p99 exceeds +3% paired median with 4/4 increases. Report all remaining
conditions, including register-16 and pair-allowed, without pooling. An
ineligible result stops this direction; no further variants or repeats.

After timing finishes, instruction/syscall diagnostics may run in a separate
output tree. Their latency and CPU samples are excluded from timing evidence.
Oracle exposes an ARMv8 PMU and has `perf` and `strace`; root permission is
needed (`perf_event_paranoid=4`). PMU availability must still be confirmed by an
actual bounded counter invocation; do not change sysctls to make it work.
