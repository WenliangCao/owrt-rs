# 2026-10-15 performance and correctness freeze

Frozen before product optimization. Starting source: `51b039597af13f9c9cf07c9f80e388e25cd8ae5d`.
The complete source/tool hashes are in `frozen-inputs.json`. Existing C expected
results, qualifiers, and correctness thresholds must not change.

## Product identities

- Deployed v0.2.0 file: SHA256 `8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7`, 2,124,571 bytes.
- Exact image C 2.93: SHA256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
- Historical Rust `50e591a9…` measurements do not qualify the deployed file.
- Copy the deployed file read-only, verify local/file/live hashes, and retain it
  as the comparison artifact. Build candidates using the unchanged SDK recipe,
  compiler, flags, allocator and feature set; keep every artifact identity.

## Unchanged performance contract

Use `PERF_DEVICE_20261014.md`, its device-safe v3 protocol, lifecycle scene
manifest and home6 supplement exactly for workloads and statistical rules.
DNS: UDP hit/miss/mixed and TCP hit/miss, 200 qps, 5 s warmup + 20 s measured,
800 hot names, A/AAAA 70/30, cache 1000, EDNS 1232, upstream TTL 120 and 1 ms,
UDP 32 clients, TCP 8 connections/100 replies, mixed 80% hot/20% unique.
DHCP: both 6 and 150 clients, 100 operations/s, 5 s warmup + 20 s renewals.
Lifecycle: startup, configuration stop/start, hosts HUP 8 and 1000 names,
6/150 leases, 20 repetitions/round, minimum 1 s period and 1 ms DNS probe.
Keep all CPU, memory components, process tree, FD and byte-size measurements.

Initial complete baseline: five alternating exact-C/deployed-v0.2.0 pairs per
scene, C/B, B/C, C/B, B/C, C/B. This is a fresh deployed baseline; old C data
may also be shown only as historical context. Candidate acceptance: five fresh
alternating deployed/candidate pairs B/N, N/B, B/N, N/B, B/N per scene.
Use median [min,max], W=max(relative full ranges), absolute relative median
difference > W and >=4/5 pairs same direction. CPU additionally requires all
rounds >=10 ticks and median difference >8 ticks. Lifecycle differences below
the 1 ms probe resolution cannot establish a latency improvement. No p99 for
fewer than 10,000 samples. Preserve failures/skips and the entire attempted
series; no selective replacement or repeated runs until a favorable result.

No new completed candidate is accepted if any scene regresses beyond these
rules. Most scenes must have discernible improvements, especially current
weaknesses. Memory and ELF growth must be measured and justified.

## Unchanged correctness contract

Every complete candidate must pass all existing unit/integration tests,
including allocation-failure tests (`hosts_allocations` included), the F10
contract (13 cases, 704 observations and existing exact-C qualifiers), TCP
upstream parity, and the existing full C differential regression families.
Run Linux service tests within the existing isolated net/mount/PID wrapper.
The independent correctness agent records exact invocations and reviews other
agents' changes. Any failure rejects the candidate and invalidates its
performance eligibility; never change C controls or expected results to pass.
An engineering direction is not a qualified candidate until all these gates
have passed on its exact frozen source/artifact.

## Isolation and scheduling

Only the root agent accesses the router. Never stop/reload/replace production,
write flash, install packages, change configuration or deploy. Own temporary
instances use a fresh loopback-only netns, private files under `/tmp`, nice 10,
and unchanged device affinity. The existing health guard watches production
PID/starttime/ELF, DNS, LuCI, routes and >=64 MiB available memory. First collect
>=120 s health baseline and freeze max(200 ms,10*p95), with independent 700 ms
timeout. Local IPv4/IPv6 HTTPS checks run every 30 s. Stop on health failure;
never restart production. Archive and hash all owned results before cleanup.

Oracle timing is globally serialized and pinned to a CPU; no other agent
compiles or profiles during its timing reservation. Counter-only work and
1-job compilations may overlap outside reservations. Per the user's explicit
parallel-work instruction, independent Oracle preparation/counter work may
proceed while the router runs, with no extra router load. All agents have
separate source/output directories and share dependency compilation caches.
Never restart Docker or touch existing service data.

## Research and stopping

First screen hypotheses with instructions/cycles, syscall/allocation/copy
counts or focused benchmarks. Only meaningful directions get full timing;
only complete timing and correctness successes reach the router. Keep all
hypotheses and rejection reasons. No workload special cases, feature changes,
memory-limit relaxation, allocator replacement or compiler-only claims.
Continue beyond the first gain. Stop only when measured residual costs are
irreducible kernel/network/syscall work or every remaining concrete direction
has an expected benefit below measured variation. Record the evidence and
limitations; do not substitute an engineering-time cutoff for that finding.
