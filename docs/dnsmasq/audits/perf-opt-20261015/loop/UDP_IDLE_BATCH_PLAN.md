# Follow-up idle/busy UDP batching screen

Source `1b934951` is a separate F-based prototype. Fixed read-one is not selected
because its high-load pipeline rate fell22.3% and CPU/query rose28.8%; retain
all36 captures and the original source. No previously measured candidate changes.

The owner already measures time spent around poll. Reuse that duration only
as a scheduling hint: after a wait of at least1ms, permit one true-result UDP
step per ready listener; after a shorter wait, restore the original shared
16-result draining budget. Initialize to the original limit for startup and
non-Linux/direct-step paths. No changes to `step_udp`, error handling, listener
readiness, deferred resend invalidation, or inter-service order are made.

The threshold is fixed before any new measurement. It distinguishes a normal
idle wait from a prompt queued-work poll and is not tuned against results.
The elapsed duration includes scheduler delays and poll's EINTR retries, so it
cannot guarantee that a busy poll always selects16. A wrong hint only changes
batching: the next level-triggered poll still sees remaining packets; total
true results never exceed the previous budget. The old >16-listener fixed-prefix
starvation possibility is neither introduced nor repaired by this experiment.

The real-socket test forces1→16→1 scheduling modes to avoid relying on wall-clock
scheduler behavior, and retains valid, short-invalid and oversize false-return
cases. It checks that queued packets survive both modes and that busy work
still yields at the original budget. Actual threshold selection is assessed
by the syscall screen. Local Linux-musl all-target compilation passed after a
statistics-only usize→u64 cast; the initial type error is retained. Linux runtime
and SDK build remain pending.

After the current layout reservation, build this source with the unchanged SDK
recipe, recheck all179 bound inputs and run the existing Linux bin and four
ignored-live owner tests before performance. Then freeze the new ELF/map/build
identities and repeat the exact36-window read-one plan against unchanged F:
low200/s and high unpaced,4 strace captures,12 grouped PMU windows,20 separate
plain windows; same names, counts rules, CPU placement, alternating order,
prewarm/warmup/drain and no selective retry. Preserve high costs, loadgen CPU,
all failures and the original fixed-N precision limits. Do not treat a threshold
hint as a correctness guarantee or a microbenchmark win as device acceptance.

No compiler, allocation or local/cache layout changes are mixed into this
prototype. A next combined candidate requires results from both headline
mechanisms and fresh complete correctness and performance qualification.
