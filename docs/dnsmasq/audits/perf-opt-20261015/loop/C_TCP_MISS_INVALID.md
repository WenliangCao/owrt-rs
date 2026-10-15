# Candidate C TCP-miss round 2: retained invalid window

`candidate-c-tcp-miss-r2-rust` remains invalid under the frozen zero-skips gate.
The [local diagnostic receipt](candidate-c-tcp-miss-invalid-diagnosis.json)
verifies all 37 raw files and the neighboring nine TCP-miss window archives.
No new runtime test, retry, replacement, product edit or gate change was made.

The exact C artifact completed its warmup correctly. During measurement the
load generator scheduled 4000 operations, accepted/sent 3987 and recorded all
3987 correct, with 13 scheduled skips and zero timeout/wrong/transport errors.
The upstream received and replied to exactly the 4987 accepted warmup plus
measurement queries, without malformed requests or queue drops. Both client
and daemon completed normally; this does not rescue the invalid workload.

## What caused the skip counter

In frozen `m6a_loadgen.c:296`, `start_request` increments `scheduled` and then
returns with `skipped++` if the assigned client is already busy. This happens
before incrementing sequence/sent. The rate loop at line 568 assigns clients
round-robin and processes due schedule slots before its next receive poll.
With 8 clients at 200 qps, each slot is selected every 40 ms. A late client
loop can therefore encounter busy state even when a reply is waiting unread;
these logs do not tell us whether that occurred.

For every completed query, reconstructing
`scheduled_ns = actual_sent_ns - send_lag_ns` produces the same 5-ms grid.
Exactly 13 grid slots are missing among indices 0–3999, matching the counter:
2301, 2302, 2303, 2307, 2308, 2312, 2313, 2314, 2315, 2317, 2318, 2334, 2335.
They span measurement +11.505065565 to +11.675065565 seconds. At each missing
slot, the preceding accepted query on that assigned client has a recorded
completion later than the nominal schedule time. The receipt lists each one.

Nine replies have client-observed latency above 40 ms; the maximum is
79.562809 ms. Send lag reaches 22.329788 ms. These values establish a short
busy-client/progress-delay burst. Client latency includes upstream, daemon,
kernel and client receive scheduling; send lag also includes work before the
first successful send. They do not isolate daemon processing time.

## Corroborating observations and limits

The 1-second resource interval enclosing the whole skip burst has aggregate
host busy CPU of 45.23%, versus 12.50% in the preceding interval. The measured
daemon accumulates 11 CPU ticks in each interval. This is compatible with
contention or delayed progress, but aggregate 1-Hz counters cannot locate
per-core contention or assign its cause. No scheduler trace or packet timing
at the burst is available.

All 28 resource samples retain daemon PID 8552/starttime 4784907 and one thread,
without process-tree truncation; available memory stays at least 90,688 KiB.
The guard's wall-clock window contains 12 successful DNS probes (maximum
0.650 ms) and six expected HTTP 403 results (maximum 58.902 ms). Production
PID 3086/starttime 2115 and the IPv4 default route remain stable; no guard
failure event occurred. Unprobed `-1` sentinel samples were not counted as
passes. The guard does not provide a complete trace of the isolated service.

All other nine TCP-miss windows have zero skips. All ten use 56 connections
and 48 reconnections, so this window has no excess reconnection count. That
does not rule out an unusually delayed individual reconnect or another
product-path delay. The retained evidence establishes no reproducible product
bug and does not justify a fix. It also cannot exonerate the product by
assigning the event exclusively to the scheduler or test client.

## Earlier transfer is a separate event

The recorded 9,489,587-byte archive transfer occurred at 10:18:26.868264 through
10:18:27.492215 UTC and overlaps `candidate-c-udp-miss-r1-rust`, as documented
in [the C profile receipt](owner-profile-c.json). This TCP window begins at
10:39:33 UTC, about 1265.5 seconds after that transfer ended. It has no temporal
overlap with the transfer. No evidence connects that earlier UDP-window
overlap to these TCP skips.

The full attempted series remains retained. There is no selective sample
exclusion, replacement window, relaxed zero-skips criterion or performance
qualification based on this diagnostic interpretation.
