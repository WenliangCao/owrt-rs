# Performance research continuation

Branch: `perf/dnsmasq-20261015`; worktree:
`/Users/USER/Developer/owrt-perf-opt-20261015`.
Starting main: `51b03959`. Do not merge main, push, or deploy.
Original main worktree has user prompt edits; leave them intact.

Status: frozen protocol; first algorithm directions screened. Device baseline initial attempt was excluded after a controller archive incompatibility and overwritten guard segment. All completed/interrupted raw windows retained; fresh entire 110-window baseline uses prefix base2. No selective replacement. Current best remains
deployed v0.2.0 SHA256 `8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7`.
See `audits/perf-opt-20261015/FROZEN.md` and `frozen-inputs.json`.

Oracle initial observation: root 53 GiB used / 142 GiB free; `/dev/shm` empty,
12 GiB free. No cleanup needed to obtain space; no deletion performed. All
seven existing containers healthy, including vaultwarden/pocket-id/caddy,
with original September 24 start times. perf hardware counters available.
Matching SDK and exact image bases retained under `/home/ubuntu`.

Active directions (separate worktrees/branches):

- `perf/dnsmasq-dns-20261015`: DNS cache/name/answer allocation and copy cost.
- `perf/dnsmasq-loop-20261015`: UDP/TCP owner loop/syscalls/start-stop.
- `perf/dnsmasq-dhcp-20261015`: DHCP persistence/hosts loading and publication.
- `perf/dnsmasq-correctness-20261015`: immutable gates and independent review.

Root controls all router activity and Oracle timing reservations. Oracle task
root will be `/home/ubuntu/dnsmasq-perf-20261015`, separate agent subdirectories.
Raw artifacts/configuration/logs belong in ignored `private/` only.

Next: complete fresh base2 C/v0.2.0 suite; integrate screened DNS/DHCP/loop changes into candidate A, run independent complete correctness gates and Oracle full timing before device eligibility. Health baseline:125s,48 DNS samples,p95 0.753ms,max2.780ms;23 LuCI403 checks,max80.381ms;threshold200ms. F10 original reference fully restored to original raw SHA4021e120… and13 case SHAs without changing checker/qualifiers. Record every attempt in `PERF_OPT_20261015.md`.

## 00:32 CEST checkpoint

- Fresh device suite: `private/perf-opt-20261015/base2/`, controller stdout/stderr alongside. Tool exec session 68952. Prefix base2, all 110 planned windows; currently DNS mixed, prior hit/miss complete. Never mix old `baseline/` attempt (DISQUALIFIED.md) into acceptance.
- Router temp root `/tmp/dnsmasq-perf-20261015`; production daemon PID3086/starttime2115/hash8472…, PID3082 is ujail. Device guardian is per-scene with unique timestamp suffix. No production operation authorized.
- Candidate A product snapshot tag `perf/dnsmasq-candidate-a-20261015` at `a7164697ba8d27e8bea2e37a7f1c783533acb240`: DNS1/2, lease hex/canonical key, TCP framing, UDP borrowing and upstream poll scratch. No DNS3 stack, no hosts map removal.
- Oracle immutable A `/home/ubuntu/dnsmasq-perf-20261015/root/source-a`; baseline source `root/source-baseline`. SDK builds in progress: `root/private/sdk-baseline-control`, then `root/private/sdk-a` (tool exec88215). Unchanged recipe/profile, linker-only Map wrapper, stable `root/private/sdk-build-slot` and shared dependency cache `root/private/sdk-cargo-target`. Native-host baseline differs from canonical deployed ELF; preserve original8472 as primary. Need measure/record matching build control to separate build layout effects. First SDK exploratory run `sdk-baseline-native` retained as harness-failed after successful package because SDK autoremove deleted optional prestrip ELF; timestamp argument also was not source epoch. New run uses correct epoch and disables only build-cache deletion, no codegen change.
- Correctness agent has recovered original F10909279B JSON rawSHA4021e120…/canonicalc927… and original native Cbba5… exactly. Baseline ordinary/namespace/config/allocation924 tests, F10,368protocol,TCP all pass. Three44-family preflight groups complete; prepare all44 for exact candidate A SDK ELF+same-build map. Old native target metadata recovery still being handled without changing C expected stdout.
- First native Oracle micro timing completed: DNS1/2 up to15.2% local API improvement, DHCP D1 serializer46% instrumented micro improvement. Device gains unclaimed.
- Rejected/pending: DNS3 stack reduces common instructions but400configured-CNAME micro +2.43%, excluded A. Hosts D3 map removal load−23% but presence+37–83%, rejected. D3b representative-map deletion+7.43%, not accepted; D3c next-index chain in research. D5 batched prefix+22–27% instructions, rejected; single-sort subchange pending. Empty shared cache blocks rejected because first-insert infallible allocation moves OOM boundary. recvmmsg saves calls but preserving deferred error needs extra getsockopt and loses benefit.
- Second batch in progress: DNS agent `perf/dnsmasq-cache-20261015` worktree owrt-perf-cache-20261015 does blockwiseCache::clear (same COW/drop order, no new representation). Loop agent `perf/dnsmasq-loop-exit-20261015` does terminal pure-cache-memory retirement after all explicit cleanup (independent mechanism review passed; IO Drops retained). DHCP agent does D3c/D4publication/single-sort.
- Oracle timing is idle; agents currently allowed1-job compilation, correctness and counters. Root must reserve a globally quiet slot for full timing before any candidate reaches router. `tools/dnsmasq/perf_opt_oracle_run.py` mirrors all11 frozen scenes, fivepairs, CPU2, isolatedloopback. It is prepared but not run.
- Root offline analyzer `perf_opt_analyze.py` rechecks hashes/counts, nearest-rank latency, W/4-of-5/CPU precision, memory/FD and DORA (home6 not ranked). Reviewer checked formulas; full raw independent audit still required.

## Correctness hold / B build checkpoint

Candidate A is NOT qualified: unchanged `stale_metadata_diff` reported two of1100 observations differing only in stale metadata for `cname-nx-q1-at-110`, profiles finite/min-max (C T0 vs Rust T1). Reviewer is reproducing source51b03959 with the same C fixture; no expected result or exemption changed. A cannot go to device even though928other tests/F10/368/TCP pass. Full44 continues for breadth. B inherits A and is also unqualified until this is resolved and every frozen gate passes.

B product tag `perf/dnsmasq-candidate-b-20261015` = `9b91a192583282fa546811977ee124d5873dd2db`, epoch1792017878. Adds blockwise cache clear, reuse uniqueempty roots, terminal pure-cache-memory retirement, hosts count index, lease-publication key borrowing. Exact source snapshot `root/source-b`. Only use Git-bound SDK output `root/private/sdk-b-git-bound` once status is built-unqualified; previous sdk-b/sdk-b-verified/sdk-b-final are retained harness attempts (incorrect caller metadata, existing cache symlink, recipe-target shadowing respectively), never qualified artifacts. Source Git blob+epoch binding now checked before SDK work; frozen performance/correctness comparators remain unchanged.

DHCP plain quiet (4cases×5pairs) accepted D3d/D4: 8hosts−4.40%,1000hosts−9.50%,clone+remove+0.42% withinW1.81%,publication−6.36%. All old rejected variants remain separate. New C research uses actual SDK2bf/b353 profile: names_for~15% of instruction samples, exact380B function range; investigate repeated FNV+SipHash work without changing randomization/side effects. Loop metrics gating rejected at0.046–0.124%samples. DNS4 question validation skip rejected at~54instructions/query(<device variation).

Base2 device current51/110 completed valid (DNS5 groups complete, DHCP6 started). Main analyzer verifies raw hashes/counts independently; no production health failures. Per-window archive+hash copies retained. The root task must still finish baseline, all finalist gates, serialized full Oracle timing, qualified device comparison, stop-evidence research, and final cleanup/report.
