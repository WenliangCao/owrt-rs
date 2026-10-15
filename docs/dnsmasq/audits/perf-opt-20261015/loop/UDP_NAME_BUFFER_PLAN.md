# Reuse the synchronous UDP decoded-name allocation

Independent F-based product source: `f404ed754a26f9385c733e7474f28e4595520957`.
The implementation commit is `f0a96480`; `8955d17c` and `f404ed75` add error and
capacity regressions. No layout, singleton, dotted-buffer, compiler or idle-batch
prototype is combined with it.

A53 E's cached-query5 allocator requests/270B match source paths32+32+14+64+128.
F's admission validation already removes the first32B name materialization.
This prototype reuses the second decoded-name allocation in the normal UDP
`answer_udp_prepared_with_local` caller. The existing `walk_name` still validates
compression, label types, expanded lengths and cursor bounds. Successful names
remain owned. Forwarding retains independent owned question/recipient/packet
state; no borrowed name representation or replacement cache index is introduced.

A private daemon Vec is taken for decoding. Partial decode failure returns it;
all ordinary local/cache/stale/policy/forward Result paths also return the owned
name buffer through a single exit. Header errors occur before taking it. Cold
construction keeps an empty Vec; the first decode reserves32 as before. This
saves one steady short-name allocator request/release, but that is not a measured
CPU saving yet.

There is one scratch per daemon, not one per name. Valid wire names are at most
255B. Capacity is not universally256: fixed-toolchain Vec amortization can retain
380B for labels30/63/63/63; the new regression proves this. The usual fixture
retains32B. Do not confuse requested capacity with allocator overhead, RSS or
fork-private memory, and do not call this a zero-memory-cost optimization.

Local Mac library715 tests pass with8 ignored; the initial new fixture and
Linux-musl all-target check pass. Added controls then pass separately for partial
truncation/invalid-label/overlong errors, compressed questions, retained replies,
a maximum name followed by a short name, and uneven-label capacity. Actual Linux
normal lib + original18 live gates and normal bin + original ignored gates must
complete before screening. These are related gates, not full44 qualification.

## Fixed original-SDK owner screen

Build exact source through the unchanged SDK recipe and retain ELF/map/build
and all179 input identities. The product release-size gate remains mandatory.
Compare independently to the immutable F SDK control, with the existing owner
driver/loadgen and CPU placement,800-name A/AAAA70/30,1000 full prewarm,5s warmup,
20s measurement and1s drain.

Run32 fixed windows: three alternating PMU pairs at low200/s and high unpaced,
then five alternating plain pairs at each load. Require complete unscaled grouped
user/kernel instructions/cycles, complete correct traffic and child-tree drains,
all identities and zero query errors. No strace matrix is added: this patch does
not alter receive/poll/send code, and the question is allocator/cycle cost. The
existing low/high syscall evidence is not pooled into this experiment.

Report same-window IPC and every plain pair, latency, sender CPU and observed
throughput. Low CPU uses the original precision/W/direction rules. Variable-N
high throughput remains a closed-loop pipeline diagnostic; no fixed-N precision
pass is invented. Retain all failed attempts and do not selectively rerun.
A positive result only admits consideration for the next immutable candidate;
full correctness, full matrices and physical qualification remain mandatory.
