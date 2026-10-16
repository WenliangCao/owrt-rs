# Separate runtime guard safety from fresh-baseline qualification

This corrects the unapproved `da49cb69` preparation. Its runtime consumer reused
the baseline120-second and probe-sufficiency checks, which could reject a valid
resume with only one timed window left. Runtime now calls an explicit shared
safety validator; baseline qualification retains all original requirements.
No padding, window replay, historical-prefix joining or new CLI is introduced.

The original7c93 and first repair already skipped an entirely completed scene
before `guard_start`. That behavior is unchanged and now has a dedicated
regression. The actual repaired defect is a **partially completed** scene or
short remaining segment, not a newly created zero-window guard.

| Tool role | Exact SHA256 |
| --- | --- |
| Corrected device full110 controller | `d2bb00f7579cf578156737c0916137838533707cc5159d11e5928094063b2b69` |
| Corrected shared health helper | `8e3367d933207920b4d59f65bd4bd807002ffd0c4d9e0eea36828c9bcd868b1e` |
| Original controller for fresh-health/Oracle bundles | `7c93cfb1ec060a11cebfa14d1a5cf1a31d6bdf40853ed6c4287b4630108e21df` |
| Current ten-window/fresh-health frozen helper | `0926acd8d2a204fbd1fe18ca7d2f1e7edd0d02b8ca727544d2217db99e16ebad` |

## Explicit validation scopes

`validate_runtime_guard_evidence` checks the complete pre-stop capture,
including partial last-line bytes, against the full final log. The capture's
whole-line prefix must match exactly. It retains start/terminal shape,
monotone elapsed values, absence of guard STOP events, and every final sample's
production PID/starttime, memory and route constraints. Every observed complete
pre-stop DNS/HTTP outcome and external result must satisfy its original allowed
status. The full shutdown tail remains evidence and is not called a successful
probe.

Runtime requires no120-second duration, DNS/HTTP sample count, or per-segment
dual-stack sample presence. A short segment can contain only a start record
before the stop request. Missing observations are not invented or counted as
successful probes. The continuous external monitor is still joined before
success, and all of its completed final records must pass. An already-complete
resume need not manufacture new external samples.

The existing `validate_guard_evidence` wrapper calls the common validator, then
retains the original baseline qualification: nonempty qualified samples with
last elapsed>=120 seconds, final elapsed>=120, successful DNS and scheduled valid
HTTP samples, and both IPv4/IPv6 external observations. `validate_baseline`,
the original125-second collector `main`, capture producer, and p95/threshold
calculation are byte-identical to0926. No first-sample bound is added.

## Full110 behavior and evidence layout

Each executed scene segment captures only after all of its remaining original
timed windows, CPU endpoints and verified archives finish. The original
alternating schedule, labels, completed-window skips and stored progress remain
unchanged. Each segment gets a fresh unique `<prefix>-<scene>-guard-<time_ns>`
directory containing `pre-stop-capture.raw`, `pre-stop-prefix.jsonl`,
`stop-request.json`, `external-health-capture.raw` and `guard-verification.json`.
The original top-level `<guard-label>.jsonl` and `.stderr` hold the complete
final logs. No old segment contributes bytes or duration to a new one.

A segment with no qualified sample records stores `pre_stop_elapsed_seconds:
null`; this is evidence absence, not a fake duration. Any byte/safety/probe/
external validation failure follows failure+task STOP and raises before success.
Measurement-invalid row handling and the original analyzer's full-valid-matrix
requirement are unchanged. Resume still binds exact new controller/helper
identities, so old7c93 evidence cannot silently become captured-prefix evidence.

The timed loop, all non-main generic functions, all11 scenes, case/loadgen,
analyzer, Oracle controller and existing ten wrapper are unchanged. No product,
physical router, active private snapshot or current full44 input was modified.

## Tool-directory boundary and verification

Fresh-health collection and the current ten continue using their existing
private **7c93+0926** directory. The corrected device full110 directory must
contain **d2bb00f7+8e3367d9** and invokes the runtime API only. Keep these bundles
separate; do not relax the standalone producer's original controller pin.
The new helper's baseline behavior is retained for compatibility, but rebinding
the active fresh-health/ten snapshots is unnecessary. Oracle110 remains the
unchanged1e80 controller with its original7c93 import companion.

48 local tests pass with all device/process calls mocked. They include the
original110 schedule/11 boundaries, complete-scene skipping, all-done resume,
one remaining31-second window, a short HUP remainder without DNS/HTTP samples,
unchanged prior archives/prefix bytes, no padding, and failed probe handling
on a short resume. Separate tests demonstrate that these runtime cases do not
pass baseline qualification, and that missing baseline DNS/HTTP/IPv6 samples
remain rejected. Existing unsafe-tail, partial-byte, external-failure,
archive/prune, miss-cohort and ten-wrapper tests still pass.

Actual local Python imports were checked in both orders and in separate old
baseline/new full-run directories. The baseline mock uses Git-retained7c93
bytes with their real hash. [The corrected receipt](full110-runtime-boundary-repair.json)
records exact identities, test outputs and scope. Independent review and actual
full qualification remain required before formal110 execution; none was run by
this local repair.
