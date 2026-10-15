# Independent local/cache layout experiments

The E/C user-cycle increase (+55.44%) is much larger than the instruction
increase (+6.86%). That motivates examining execution efficiency as well as
instruction count. It does not establish instruction-cache misses as the sole
cause: dependencies, branch prediction, data locality and context-switch effects
can also change IPC. The two local-answer functions occupy20.32% of the E UDP
user-cycle samples; a single sample capture is a diagnostic, not a per-function
speed guarantee.

Both prototypes are independent children of frozen F. Neither skips a local
lookup, changes CNAME priority, changes cache/LRU behavior, or alters compiler
options. Their Linux829-test runs and18 ignored-live checks passed. Full44
candidate qualification remains separate.

- `2bd0d6b2` moves the owned-answer construction body verbatim behind a
  non-inlined helper. This aims to reduce the ordinary cache-hit entry footprint.
  The local Linux-target inspection reduced the entry frame848→656B, but the
  owned-answer chain rises848→1264B. The extra call/stack work on local answers
  is a concrete adverse mechanism, not an assumption that all paths improve.
- `26aefa79` moves the general RR body verbatim behind a non-inlined helper.
  The compiler can then inline the small address dispatcher; the ordinary
  address chain loses a1408B frame in the local Linux-target inspection.
  General/raw RR paths retain the separate helper and may pay extra overhead.
  Reserved stack bytes are not equivalent to bytes touched on each query.

These codegen observations are from the local Rust-bundled-musl ET_EXEC build,
not the OpenWrt SDK PIE. The unchanged SDK recipe separately built exact F and
the two prototype artifacts within the existing size budget. SDK runtime data
must establish whether either mechanism matters for the shipping build.

The committed plan fixes all scenes, counts and orders before measurement.
It reuses the existing hot15 probe: three grouped user-instruction/user-cycle
pairs and five plain CPU pairs for each prototype independently against F.
PMU counts cover setup, priming, query loop and teardown; IPC is the ratio of
the two unscaled counters from the same window. Plain CPU uses one child-tree
RUSAGE delta, with no observer, and the original five-pair W/direction rule.
This is a native mechanism screen, not daemon/device acceptance.

Before the first run, retained prior200k command durations (hit0.207s,
raw-address1.411s, configured-CNAME4.622s) fixed the workload lengths:200k for
all PMU windows;2m for plain windows except raw-address/configured-CNAME200k.
All are complete multiples of each fixture's800/400/100-name population.
All480 windows remain mandatory, including adverse controls; no selective
reruns or suppression of increases. The fixed checksum comes from earlier F
controls, not from the first new sample. It checks workload and coarse answer
structure; the functional gates establish wire compatibility. The fixture does
not provide performance coverage for every ANY/PTR/MX/SRV configuration.

Then32 independent original-SDK owner windows compare each layout to F:
three PMU pairs and five uninstrumented pairs at200 UDP cache-hit queries/s,
with the same800-name70/30 A/AAAA workload and CPU placement as read-one.
The original tick-precision limit remains in force. Neither native timing nor
static frames automatically selects or qualifies a next candidate. Read-one's
low/high result and these layout results must both be available first.

Artifacts: [fixed plan](layout-screen-plan.json),
[native replay](run_layout_native_screen.py),
[SDK replay](run_layout_sdk_screen.py).
