# G Cortex-A53 target: local size risk, no runtime result

Source478acea6 replays the earlier isolated c076 target-cpu patch onto G,
adding only `-Ctarget-cpu=cortex-a53` to the package recipe. The separately
committed hosts collision fixture is test-only; its non-test prefix is exactly
G. The179-input manifest records both files honestly. opt3, fat LTO, one
codegen unit, panic, allocator and linking policy remain unchanged.

The fresh local control reproduces G ELF46cc6939. The A53-targeted local
.text grows1823896→1982200B (+8.68%); file-backed load bytes grow2088504→2251408.
Whole local ELF5022408→5285592 includes nonloaded sections and is not the SDK
shipping size. Canonical SDK budget is unmeasured: this is a size risk, not a
fabricated SDK failure. Several hot emitted ranges also grow, including
process_udp4672→5644B, wait_for_files7304→7596B and names_for380→504B.

The pinned compiler adds AES/CRC/PMUv3/SHA2 target features, matching the earlier
F preparation's compiler observation. Target-cpu is not a scheduling-only
switch; original device feature evidence and PMU limitations remain in
F_A53_CODEGEN_PLAN.md. The musl all-target check passes with the actual A53 flag.
No instruction counter, target binary or new helper has run on either machine.

Keep this independent experiment below the already prepared803 opt2 screen.
No baseline/candidate source is changed during current6ab timing. Neither local
ELF size nor a CPU-specific option proves better IPC or latency; actual SDK
budget and original correctness/device comparisons would still be required.

[Exact inputs, local compiler commands and code ranges](185-a53-local-codegen.json).
