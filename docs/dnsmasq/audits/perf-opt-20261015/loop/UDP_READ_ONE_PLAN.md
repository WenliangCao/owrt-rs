# UDP read-one experiment, after F's independent timing

Source `4bd3c9a4` is an independent child of frozen F `3a3d8e3e`. The user
explicitly authorized reassessing the terminal EAGAIN and the old batching
constraint. No change is made to F or its running 110-window comparisons.

The first variant changes the per-listener receive `while` to `if`. Each ready
UDP listener therefore consumes at most one datagram before the next poll;
the existing cross-listener bound, TCP admission and other service ordering
remain. `step_udp` itself, its errors, admission, invalidation and resend logic
are unchanged. In particular, false can mean a consumed oversized/discarded
packet, not just no work. No error is deferred inside recvmmsg.

Exact C `dnsmasq.c` SHA `d4bb7cde522376200a0293427b0812625ebc457f10dc9d3e2bef243ccba8ccd1`
has a stricter whole `check_dns_listeners` boundary: it handles the first
ready pipe/upstream/UDP/TCP event and returns; main calls it once after poll.
The retained private source sections 1924--2008 and 1294--1324 establish this.
This prototype matches the single-ready-UDP receive frequency, not C's entire
multi-service scheduling policy. Keeping the cross-listener cap is a scope
choice for this first experiment, not a prohibition on later C-like variants.

Local Linux-musl all-target compilation passed. The added real-socket test
queues two valid queries, a short invalid packet then a query, and an oversized
packet then a query; the second datagram must remain until the next owner poll.
Runtime execution on Linux remains pending. The initial temporary-borrow test
compile failure remains in the private directory beside the corrected log.

## Fixed measurement order

Only after the exclusive F/E Oracle run ends, first run the new queued-packet
test and existing normal/probe UDP, same-wake reload, UDP ACL and resend tests
against source-bound binaries. Build exact F and this variant through the
unchanged SDK recipe/flags; preserve ELF, map, Git input and build identities.
No compiler-option or local/cache prototype is combined with this variant.

Reuse `loop_owner_profile.py` with the minimal explicit diagnostic options
from tool commit `bec57a22`. Use the newly fixed loadgen
`f7c7d8e94a96e5c23f06aec1396539c439516fa4408a3657835cf78bdceb618e`
and unchanged upstream `01c25e6a…`. Fresh isolated loopback namespace per window,
daemon CPU2/nice10, loadgen CPU3, upstream CPU1; same 800-name A/AAAA 70/30
cache-hit data, 1000-query prewarm at 200/s, five-second warmup, twenty-second
measurement, and fixed one-second post-load drain.

Compare low load at 200 queries/second and unpaced high load (`--rate 0`,
32 clients, one outstanding request per client). The latter intentionally
finds sustainable throughput; it is a separate diagnostic, not a replacement
for any frozen acceptance scene. Keep every attempted window and all errors.

1. Four strace captures: F/variant at low load, then F/variant at high load.
   Compare successful/error receive, ppoll and send counts and their actual
   parameters per completed query. Traced throughput is not a speed result.
2. Three alternating pairs at each load, twelve separate stat-only windows,
   using the existing grouped user/kernel instructions and cycles. Require
   complete unscaled events; preserve failed/unknown results. Report cycles
   and instructions/query plus user IPC, not just fewer syscall invocations.
3. Five alternating pairs at each load, twenty windows with `--observer none`.
   Report CPU/query with tick precision stated, latency, send lag and completed
   throughput. CPU endpoints surround the entire cohort and drain. Preserve
   the original five-pair medians/ranges/directions; low CPU tick differences
   below the original precision floor remain inconclusive.

High-load throughput/CPU/latency costs must be reported alongside low-load
savings, including adverse results. Saturated windows still require scheduled
= sent = correct, nonzero cohorts and zero timeout/wrong/transport/skip errors;
no such error is relabelled a tool failure. No selective reruns or automatic
promotion follows. The next candidate is selected only after this result and
the independent user-path locality/layout result are available, as requested.
