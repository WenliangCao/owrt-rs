# Narrow TCP-style readiness group: no product fork

The 14-direct versus 6-direct-plus-8-member-group primitive completed all 16
predeclared cases. The group presents seven outer poll entries and performs
one zero-timeout epoll extraction per ready iteration. Strict compilation,
three old invocation smokes and separate mask/level/EOF/close/same-number-reuse
controls passed. [The full receipt](ppoll-group-counts.json) retains all raw
hashes, commands and outcomes; only its verified 31,332-byte summary was copied
from Oracle. Source `25c21e9f…` produced ELF `bbbb2c51…`. No product changed.

| Deferred case | Direct instructions/iteration | Group | Saved | Rough whole-D-TCP-hit projection |
| --- | ---: | ---: | ---: | ---: |
| First group member ready, stable | 20482.68 | 16626.04 | 3856.64 | 7.30% |
| First group member ready, churn | 20810.29 | 16640.57 | 4169.72 | 7.89% |
| Last group member ready, stable | 20245.08 | 16458.94 | 3786.15 | 7.16% |
| Last group member ready, churn | 20206.95 | 16403.85 | 3803.10 | 7.19% |

Every deferred run has 5000 not-ready prechecks and 5000 voluntary context
switches. Expiration/coalescing differences remain in the receipt, ranging
from 5000 to 5022 expirations; they were not used to replace any run. Each
case includes the same timer precheck and timer read. The timer is explicitly
a stand-in for deferred socket readiness, not a TCP packet workload.

Initial eight additions and final eight deletions are included in external
perf counts. Churn performs 48 additional delete/close/create/bind/add cycles,
giving 56 total group additions/deletions, matching the earlier 56-connection
lifetime count rather than accidentally adding 56 replacements on top of the
initial eight. All 48 reused the previous numeric fd. The selected ready
timer was not replaced. No phase-change MOD is hidden in the count: the
independent mask control uses MOD, while these stable-readiness loops do not.
An application adapter would add real phase changes and generation bookkeeping.

Already-ready finite-timeout cases are less favorable. Readiness at the first
group member costs 108–152 *more* instructions/iteration with grouping; last
member cases save about 2520–2558. Both positions and both churn cases remain
in the result. The event buffer holds all eight members and is read once;
there is no invalid "drain until empty" loop over unconsumed level readiness.

The whole-D projection uses C's 5052 observed TCP-hit poll entries and D's
separate 267,053,903-instruction profile. It is an optimistic screen, not a
paired result or CPU/latency prediction. Nevertheless, 7.16–7.89% before
application bookkeeping is below the approximate 10.39% CPU precision floor
represented by the frozen >16-microsecond delta at C's 154 microseconds per
operation. The first-member ready regression further weakens the case.

Decision: **stop this narrow downstream TCP group before a product fork**.
The previously projected 18% 14-to-1 opportunity was not the cost of a real
seven-entry group with extraction. There is no reason to build a full adapter
and failure framework for this screened gain.

This does not prove all readiness work irreducible. A wider group could remove
more direct entries, but then it spans dynamic listener/upstream/UBus/log/file/
netlink lifecycles, regular-file compatibility, duplicate consumers, invalid
descriptor/error mapping and the DHCP probe subset. Its savings, memory/FD
cost, cleanup and failure behavior are unproved. It is neither implemented nor
rejected merely by extrapolating this narrow experiment. D's ongoing gate
failure diagnosis takes priority; no further backend/framework work or remote
capture is started here.
