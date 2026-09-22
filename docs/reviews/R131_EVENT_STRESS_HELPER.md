# R131 event completion helper

The separate `r131-event-stress-libubus` ELF links against matching source
imports and runs against the image's original libubus/libubox. It does not
change the R131 CPU or latency callers. It is a test artifact only.

Usage: `event-stress SOCKET grouped|interleaved|monitor|slow N SUBJECT_PID`.
The caller pins itself to CPU 0 and requires the disposable daemon on CPU 1.
`tools/r131_ubusd_event_stress.sh` runs all four cases, each on a fresh daemon
with argv[0] `/sbin/ubusd`, through the existing recovery-gated driver. Supply
the helper as `--event-benchmark` and the ordinary static benchmark as
`--benchmark`. `N` applies to the first three cases; slow is fixed to 192.

| Case | Fixture | Required behavior |
| --- | --- | --- |
| grouped | Two owners, four handlers each, register AAAABBBB | All eight deliveries, exact bytes/target/per-owner order/global event sequence |
| interleaved | Two owners, four handlers each, register ABABABAB | Same checks; no owner reordering |
| monitor | One owner, eight handlers, exact libubus monitor | Same checks plus all outgoing mirrored event targets, bytes, order and event sequence; monitor sequence continuous |
| slow | One owner, eight handlers, 2048-byte payload, 192 sends without reads | Exercise the bounded drop cap; drain surviving complete frames in order, then deliver a fresh eight-frame recovery event |

The first three cases have 20 warmups and retain per-operation wall-clock
samples. Their latency includes send STATUS and all listener/monitor callback
validation. Their daemon and caller CPU clocks cover the timed loop. This is
a new instrument; its absolute CPU values are not pooled with the earlier
aggregate-only caller. Slow-loop latency measures sender acknowledgement
only and must not be compared to normal end-to-end latency.

The exact source revision `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` defines
`UBUS_CLIENT_MAX_TXQ_LEN` as `UBUS_MAX_MSGLEN`; the matching CMake default and
image build use 1,048,576 bytes. `ubusd.c:143` drops a frame when enqueueing
it would exceed that cap. The test therefore requires a nonzero strict
subset of the flooded events, without assuming C and Rust must drop the
same count. Batching can change kernel socket occupancy before the same
userspace cap is reached. A later event must still arrive in full.

Every callback checks its real `ubus_request_data` target, peer, sequence and
absence of an attached FD. It compares the entire encoded payload with an
expected blob, including padding. It rejects duplicate or reordered
per-handler events and owner frames. The slow path permits forward sequence
gaps only. The final lookup/removal barriers and FD-count return to baseline
check recovery and cleanup. Memory snapshots at empty/registered/delivered
or flooded/drained/closed are immediate diagnostics, not settled residency
measurements.

Oracle validation passed all 12 C/R124/R131 × four-case combinations, using
100 operations for normal cases and 192 for slow. This is helper protocol
validation, not a router performance result. An initial helper check used
`ctx->msgbuf.hdr.seq`, which is not reliable while libubus drains pending
callbacks during a synchronous request; the helper now checks
`ubus_request_data.seq` in the object method handler. The final validation
uses the exact same ELF proposed for physical testing.

Final helper SHA-256:
`1705d989c64640353e556d0cc307899504b08e7b8ccbbcc8963f6821680b3499`.
Source SHA-256:
`d2a1e7a37ef4cc901537b75b35deb602a3d7ae8c25d8af86ca68b9e37ee58c64`.
Raw Oracle evidence is ignored under
`private/r131-completion/stress/stress-oracle-03`; no router was accessed by
this helper's validation work.
