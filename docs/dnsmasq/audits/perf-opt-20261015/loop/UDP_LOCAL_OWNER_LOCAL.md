# Keep private UDP socket ownership local to its single owner

Sourcec95610c6 builds on99b519dc. The private listener and pending-admission
handles useRc instead ofArc, retaining shared ownership and exactly the same
last-owner socket closure. SinglePoll already containsRc/RefCell and cannot
move between threads. Signals use atomics and a pipe, and startup daemonization
forks single-thread state into independent address spaces. Library config,
lease, interface and cache Arc types remain unchanged.

Only handle types, factories/clones and corresponding private test fixtures
change; original assertions remain.23Mac binary tests and both default and
m6b musl all-target checks pass. Linux-only runtime gates are still pending.

The fresh local final AArch64 control reproduces99's exact previous ELF hash.
Across step_udp/process_admitted_udp/step_edns_udp/process_udp, static outlined
atomic call sites change2/2/1/2→0/1/0/0. The remaining site is the separate
Arc<DnsConfig> replacement when loop detection changes config. This proves
the socket mechanism in this local build, not an atomic-free daemon or a
measured number of atomic calls per query. step_udp remains1700B/384Bframe;
other selected function sizes are retained in the report.

No SDK or performance screen has run. Source remains independent from frozen185
and the a15 combination. [Exact local code-generation and validation receipt](udp-local-owner-local.json).
