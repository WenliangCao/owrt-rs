# Exact candidate D residual attribution

The existing tool captured all five DNS scenes once, serially in the released
fourth Oracle slot. Source `9f2a905289c6c009edd747abc590a1d013b114e5`, SDK ELF
`4167609f5fe1c17a480f0a395fba1e3c15142f6c2ad7c3998d133a04829965e8` and map
`00d5ba5b2d216dfad6984b239f25ebe5b7e0a423d74fdd51538ccadeeb212b13` were verified.
[The receipt](owner-profile-d.json) contains all commands' existing raw hashes,
process/mapping identities, sample scopes, counts and historical C totals.

Every scene completed 1000 warmup plus 4000 measured queries correctly, with
valid perf ACK brackets and no lost samples. Each raw sample inventory contains
one daemon PID/TID, matching its captured one-thread stat and in-process owner
model. Hit scenes used the existing UDP prewarm. Independent correctness jobs
could overlap these counter windows; no quiet timing or statistical acceptance
claim follows. All raw stays on Oracle; the only downloaded file is the
verified 54,500-byte derived summary.

| Scene | C total instructions | D total instructions | D insertion self samples |
| --- | ---: | ---: | ---: |
| TCP hit | 263,529,427 | 267,053,903 | 0 |
| UDP hit | 188,060,152 | 197,895,203 | 0 |
| UDP miss | 826,621,047 | 709,818,707 | 238 / 41,913 (0.568%) |
| UDP mixed | 310,349,175 | 336,693,417 | 19 / 24,084 (0.079%) |
| TCP miss | 936,190,419 | 679,773,254 | 231 / 40,091 (0.576%) |

C's insertion section had 11.09%/4.29%/18.12% of all samples in UDP
miss/mixed/TCP miss. Its large sampled contribution is absent in D, consistent
with the screened expiry-bound mechanism. These unpaired PMU changes are not
causal CPU percentages, speedups or regressions; the complete frozen timing
results remain separate.

Concrete remaining user work includes `Cache::names_for` at 14.66% of UDP-hit
samples (1756) and the local answerer at 4.39% (526). In UDP miss, exact
`names_for` has 6.60% (the receipt's broad name label also includes a small
mutable variant), local answer processing 4.52%, and local-cache matching
3.61%. TCP miss now emphasizes malloc (4.75%), TCP upstream stepping (4.22%),
reply insertion processing (3.81%) and routing dotted-name work (3.47%).

TCP hit still has sparse userspace attribution: 1001 user samples among
20,043; `wait_for_files` accounts for 163 (0.813% of all samples). Kernel-mode
samples are not an exact share of service CPU or proof that work is
irreducible. The separately measured deferred-wait cardinality term remains
potentially material and requires a compatibility-preserving mechanism screen.
No new product change or backend is selected by these profiles.
