# Independent F-based dotted/singleton native CPU screen

Freeze the same 480-window design as the completed layout screen, now for
`dotted` (`c627927d4352643631a6b3f9332209184a7d6ae8`) and `singleton`
(`b1180f728543d56132df0f144467b3c97ef7b410`), separately against F
(`3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`). No product code changes or
prototype combination are part of this task.

Use [the original runner](run_layout_native_screen.py) without modification and
[the new fixed plan](post-f-native-cpu-plan.json). The original layout plan
hash, unchanged runner hash, source hashes and excluded older instruction
screen are recorded in the plan. Each candidate retains its own interleaved F
controls: 15 scenes, three grouped PMU pairs at 200,000 operations, then five
plain pairs at 2,000,000 operations except raw-address/configured-CNAME at
200,000. Fixed checksums, actual operation counts, unscaled same-window grouped
instructions/cycles and the existing `perf_opt_analyze.compare` W/direction
rule remain unchanged. No results from the older 320-window instruction and
allocation screen enter these comparisons.

Before this plan was committed, all three source identities were verified
locally against Git and the previous frozen source manifest. Oracle's existing
source directories also matched all 172 files in that older manifest. The
new plan retains the layout design's 162 build-source files and checks them
again before and after execution. The retained probe matched SHA256
`72d836d1f868d4e608c14a47105b29dda35f8533ec6ce3456ca1bbc539db76bd`.

Run in fresh Oracle private `dns/private/post-f-native-cpu-screen1`, with the
exclusive Oracle workload reservation. Build all three probes before timing;
preserve any failed or interrupted attempt without selective reruns. Upload
only small text inputs; retain raw logs and binaries remotely while the
separate device stage experiment runs. This is native mechanism screening,
not exact SDK evidence, frozen-C correctness, or device acceptance.
