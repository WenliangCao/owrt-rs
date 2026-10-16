# Combine the narrowed cache path with the remaining decoded-name reuse

Source `0161ad9c` is a clean child of `54bd1e56`, adding only the previously
reviewed synchronous UDP name-buffer commits `f0a96480`, `8955d17c`, `f404ed75`.
There were no cherry-pick conflicts or manual product edits. The standalone
name-buffer prototype's inconclusive A53 CPU and small high-load SDK result
remain unchanged; they are not summed into an expected combined improvement.
The combination is a separate experiment, not a selected G candidate.

Mac720 library tests with8 ignored and musl all-target checking pass. A small
private adaptation of the existing allocation counter now calls the actual
public prepared-UDP answer API, including admission and query metadata. It
imports800 real fresh A/AAAA responses at70/30, primes1000 queries, then counts
8000 calls. [The complete receipt](prepared-udp-hit-allocation.json) binds source,
probe,9 build/run commands and logs. F, narrowed cache path and this combination
all return matching checksums with zero net live bytes and zero reallocations:

| Source | Allocations/call | Requested bytes/call |
| --- | ---: | ---: |
| F | 4 | 245 |
| Narrowed cached-only bypass54bd | 2 | 160 |
| Cached-only plus decoded-name reuse0161 | 1 | 128 |

The final128-byte allocation is the owned answer buffer. This scope excludes
socket receive/send and the rest of the owner loop; these are not new physical
whole-query counts or allocator CPU attribution. Requested bytes exclude
allocator overhead. The steady name scratch retains32B for this fixture and
can retain380B for the already tested uneven-label input, not universally256B.

## Fixed independent accepted-E comparison

After exact-source related Linux gates, source-interaction review and the
unchanged SDK build, compare this artifact directly to accepted E
`4f869c88` / ELF `8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27`.
This answers the current incremental goal; old F controls are not pooled.
Predeclare the existing32-window exact-SDK owner screen: low200/s and high
unpaced UDP hits,3 grouped PMU pairs then5 plain alternating pairs at each load.
Use the unchanged workload/driver/CPU placement and original low-load precision,
W/direction rules. High load remains a variable-N pipeline diagnostic.

An independent exploratory A53 screen uses the original ten windows, five
alternating E/variant pairs, the same800 names/70-30 types,1000 prewarm,
5s warmup+20s measured,200/s, all existing health/restore/archive gates and
original >8tick/W/direction criteria. Bind actual ELF/map/build/gate hashes
before starting. Keep every original attempt; no reruns to obtain a favorable
result. No compiler option, profile or other prototype joins this source.

The existing hot15 public local/cache probe bypasses prepared UDP parsing and
therefore cannot measure this added name reuse. Do not present it as that
mechanism's timing control. Cold behavior/latency still require the original
full44/67 correctness and both full11-scene matrices before acceptance. No
release qualification, device run or CPU benefit is claimed by local preparation.
