# Deferred wait cardinality: measurable remaining cost

All 21 predeclared cases passed in one Oracle slot after the exclusive timing
reservation ended. Strict GCC warnings passed, and the `NDEBUG` negative
control failed as intended. Source `b789d78c…` produced ELF `4723d8cf…` with
native GCC 13.3.0. The [complete count receipt](ppoll-cardinality-counts.json)
retains every command, result, compiler/kernel/source/ELF identity and raw-file
hash. No workload was retried or replaced. Raw files stay on Oracle; only the
verified 33,660-byte derived summary was copied.

| Mode / ready position | 1 fd instructions/iteration | 14 fd | Increment |
| --- | ---: | ---: | ---: |
| Empty, zero timeout | 1671.96 | 4582.60 | 2910.64 |
| Ready first, zero timeout | 1677.08 | 4586.62 | 2909.54 |
| Ready first, finite timeout | 2364.79 | 5301.87 | 2937.08 |
| Ready last, finite timeout | 2364.79 | 9063.04 | 6698.25 |
| Deferred timer first | 12073.79 | 21831.79 | 9758.00 |
| Deferred timer last | 12073.79 | 21498.21 | 9424.41 |

The six-fd deferred increments are 3143.73/3138.23 instructions with the
timer first/last. First and last positions are both retained; no favorable
position was selected. These are total instruction counts divided by fixed
iterations, not elapsed-time performance results.

The deferred controls exhibit actual blocking evidence. The one-fd and both
14-fd runs each recorded 1000 not-ready prechecks and 1000 voluntary context
switches. Timer expirations were respectively 1008/1009/1006, with 7/8/6 reads
coalescing multiple expirations. The six-fd last-position run recorded one
already-ready precheck and 999 voluntary switches; it remains in the result.
Involuntary switches and coalescing differences are preserved. The precheck
is not an exact blocked-wait counter: expiration may occur between it and the
main wait.

Every deferred iteration includes the same extra one-fd precheck and timer
read. External perf counts also include setup, cleanup, assertions and JSON
output. The 14-minus-1 difference is a same-mode mechanism screen; it is not
all application cost or a measurement solely of kernel registration.

Projecting the entire deferred increment across C's 5052 TCP-hit poll entries
against its separate 263,529,427-instruction profile gives an optimistic
18.07–18.71% instruction share. This exceeds the rough 10.39% CPU precision
floor implied by 154 microseconds/operation and the unchanged greater-than-
eight-tick gate. Instructions are not CPU or latency, and a future mechanism
could not remove all waiting/lifecycle work. Nevertheless, the result does
**not** support rejecting readiness-cardinality work as below noise.

The zero-timeout control substantially understates the deferred increment.
The earlier one-fd estimate cannot establish that the actual owner wait is
irreducible. Conversely, timerfd plus idle UDP descriptors on Oracle is not
the device TCP/file/socket mixture; the result does not select epoll or prove
that any persistent backend would improve the complete daemon. Interest
updates, file compatibility, duplicate masks, fd reuse/generations, logical
work, the DHCP probe wait, errors and fairness remain the boundaries in
[the interface audit](WAIT_INTERFACE_AUDIT.md).

Current decision: retain this as a concrete remaining optimization direction.
The next step is exact D residual attribution with the existing profile tool,
followed by a small mechanism proposal justified by that evidence. No backend
or product edit is included here.
