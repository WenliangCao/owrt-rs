# Exact-SDK owner32: 0161 directly against accepted E

This executable plan implements the accepted-E comparison declared in
`CACHED_LOCAL_NAME_PLAN.md` at `b25e8ad6`. It binds candidate
`0161ad9c103459c7f59c44ebce9600db1f1697c6`, not the earlier8d572 prototype or
standalone F/name-buffer comparison. The candidate adds reviewed synchronous
decoded-name reuse to the narrowed cached-only path. It is not selected.

| Side | Source | ELF SHA256 | Bytes |
| --- | --- | --- | ---: |
| Accepted E | `4f869c885b47dcf60d56c872e5b0b3c62237beea` | `8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27` | 2,136,859 |
| Cached-local-name | `0161ad9c103459c7f59c44ebce9600db1f1697c6` | `f4230f03137bd235489cda2cfa186e44aefe390d9a5f9afd8368c80e73658aff` | 2,140,955 |

The candidate same-link map is
`b9a67ea66d81d3141e2ee8a4ffc5f0b860ef92177a5d96a15ada55739bfab96f`;
build receipt is
`972a6f3c1b9d6121fef854d18cae24bc12be776b097e96d21b843571fe1b2165`.
Both original-SDK artifacts retain release budgets and hardening. Each source's
179 receipt files were independently checked against its named Git revision.
Candidate ELF/map/build were downloaded and verified before any timing; the
existing E artifacts were already retained locally.

The related Linux gate is the exact939-pass receipt
`42e9e5de497aff73e9dc82feba9dd60fbe61caa183dce8e5e8ad34b9436b85ea`,
paired with the source-interaction review in `77198f81`. This is not the full
44-family qualification. The runner checks its exact hash, status, candidate
source, pass count and absence of owned processes before starting.

The [frozen machine plan](cached-local-name-owner32-plan.json) and
[runner](run_cached_local_name_owner32.py) retain the original owner driver,
workload and CPU placement. There are32 windows: stat low200/s three pairs,
stat high-unpaced three pairs, then plain low five pairs and plain high five
pairs. E goes first in odd pairs and the candidate first in even pairs. No
strace windows are added. All labels are unique and outputs must be fresh.

The unchanged driver uses800 names, A/AAAA70/30,1000 full prewarm operations,
5s warmup,20s measured and1s drain. Driver/controller stays CPU0/nice0; the
daemon stays CPU2/nice10 and the sender CPU3. Existing upstream placement and
grouped PMU capture remain unchanged. All correctness, unscaled counters,
complete tree-tail and process-identity gates must pass. Any failure retains
its partial sample and stops; no favorable replacement or extra pair is allowed.

[The analysis copy](analyze_cached_local_name_owner32.py) differs from the
previous reviewed owner-screen analyzer only in the baseline label F→E and
scope text. Reversing those substitutions restores it byte-for-byte. Actual
warmup+measurement N remains the CPU/PMU denominator; throughput and latency
use only the20s measured cohort. Low CPU retains the original >8tick precision
and W/direction rules. High variable-N throughput/CPU remains a closed-loop
pipeline diagnostic; no fixed-cohort precision pass is invented. IPC comes
from the same PMU window. Previous F or candidate controls are not pooled.

The runner's source/artifact linkage explicitly ties the fixed candidate
commit to its artifact source, build source directory, all179 source hashes,
ELF, same-link map and build receipt. Source/tool/artifact checks repeat after
the full screen. Process-group cleanup and partial progress are retained even
on interrupted or failed windows. The original workload driver itself is
unchanged.

Both SDK builds and all artifact/input downloads, uploads and hashes finish
before timing. Loop's separate54bd native240 screen runs first; this owner32
starts only after that screen and its postflight/transfer activity are released.
No concurrent research build, workload or bulk transfer is allowed. All inputs
needed for the later offline derivation are uploaded before the first window.
This experiment does not run a router, change production state or bypass the
full correctness and11-scene matrices required before acceptance.
