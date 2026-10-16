# Keep inactive upstream processing out of the cache-hit frame

Independent6ab child117d3e61 contains two separately committed function
boundaries.4f256499 drains upstream query notices at the original point, then
returns an empty response vector when no events exist. The unchanged event
body moves to an outlined helper.117d3e61 preserves the original
no_timer_or_socket_work guard, release consumption and event draining; only
the subsequent active poll body moves to a second outlined helper. Neither
step changes timer order, event order, reply admission, logging or cleanup.
The original body spans (4576 and2856 bytes) compare byte-for-byte.

| Local revision | poll_inner bytes / frame | Completion helper | Active-poll helper | Whole ELF vs6ab |
| --- | ---: | ---: | ---: | ---: |
|6ab control|12448 /1520|inlined|inlined|0|
|4f256499|6784 /1104|5664 /1024|inlined|+248B|
|117d3e61|528 /224|5664 /1024|6260 /1088|+576B|

The final local ELF's empty path does not call either new helper. The
process_udp range/frame remains4660/1056 and consume_releases2696/160. The
active path pays extra calls, and the first revision's nested completion
frame grows; no global stack reduction or runtime improvement is inferred.
All numbers are from locally linked AArch64 bundled-musl ELFs, not the SDK
artifact, deployment size budget, A53 IPC or CPU measurement. Both control
builds reproduce77096845 and5,022,240 bytes; final117 is9f001802 and5,022,816.

Each committed step passes the existing725Mac library tests with8ignored;
final musl all-target compilation passes. No new test names, state, clocks,
unsafe code or benchmark framework were introduced. Source-only independent peer66a23ce1 passes; it did not rerun local
checks or attest codegen. This prototype is unselected for remote preparation; G-stage and
warm6dad retain their existing queue positions, and no measured source changes.

A private analysis script initially shadowed Python's inspect module, failing
before disassembly. Renaming that script fixed import resolution; the failed
receipt is retained. A generic-symbol filter was also widened to include the
new monomorphized helper in the same immutable ELF inspection. Neither changed
product source, compilation, tests or measurements.

[Exact sources, checks, body comparisons and local codegen](upstream-completion-frame-local.json).
