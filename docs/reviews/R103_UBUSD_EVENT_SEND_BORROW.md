# R103: borrow user event fields before dispatch

The R100 lazy event path already deferred internal/object event encoding, but `event_send` still copied the user event ID and data into two vectors before dispatch. This happened even when no event pattern could receive the event. The R103 candidate keeps both slices borrowed from the request and passes a one-shot builder to the existing lazy dispatcher. The frame is allocated only after the first eligible receiver is found.

The change preserves ACL checks, reserved `ubus.` rejection, event round advancement, per-receiver object ID patching, monitor mirroring, queue ownership and wire bytes. It adds no fields and changes no event matching algorithm.

Build-host tests pass 35/35. On the physical router the candidate passed all seven C/before/candidate wire differentials and its unit binary passed 35/35. Boot/configuration/production identity and cleanup passed. Six host gates are still running; no performance result exists yet.

The failed initial compile against the old pre-lazy source was discarded and not measured; it correctly caught a mixed-base mistake. The accepted candidate was rebuilt from the full R100 source and only this change was applied.

## Fanout evidence

A fresh 16-window physical fanout series (four arms × four blocks × `watch_1_1`, `watch_8_1`, and `watch_1_0`) passed all cleanup and byte-validation checks. This workload exercises object add/remove events and validates integration of the repaired R100 dispatcher, but it does not directly exercise `ubus_send_event`.

## Direct user-event evidence

The exact-image C `libubus` caller was cross-compiled from the matching image sources. It sends a fixed validated blobmsg payload through `ubus_send_event`, pumps one or eight registered handlers synchronously, tests an unmatched pattern, pins the daemon to CPU 1 and the caller to CPU 0, and measures only the daemon's `CLOCK_PROCESS_CPUTIME_ID` interval. Every window validated event count/payload, removed all temporary handlers, and passed stock identity, boot/config/mount and cleanup checks.

Four C/before/R103 blocks at 20,000 sends per scenario are recorded in [`r103-user-event-results.json`](r103-user-event-results.json). Candidate daemon CPU versus C median ratios are 0.9474 (−5.26%) for `user_1_1`, 0.9904 (−0.96%) for `user_8_1`, and 0.9094 (−9.06%) for `user_1_0`. The same run gives R100-before ratios of 0.9969, 1.0060 and 0.9439. Four R89 blocks give candidate/R89 median ratios of 0.7806 (−21.94%), 0.8689 (−13.11%) and 0.6720 (−32.80%).

An additional eight-block alternating C/R103 series is recorded in [`r103-user-event-aa-results.json`](r103-user-event-aa-results.json). Its candidate/C median ratios are 0.9603 (−3.97%), 0.9728 (−2.72%) and 0.9198 (−8.02%); all eight paired ratios are below 1 in each scenario. This is stronger evidence for the direct user-event CPU direction, but it remains a workload-specific pilot estimate rather than a whole-daemon or memory acceptance gate.

The direct user-event path now has physical performance evidence and is no longer an unmeasured R103 tail. Whole-system latency, PSS/heap, sustained concurrent fanout, and the nine-component combined target remain separate acceptance questions.
