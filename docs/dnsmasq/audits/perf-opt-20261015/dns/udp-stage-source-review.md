# Excluded UDP stage diagnostic: independent source review

Reviewed source: `cb8cd619eabb9d8d158c79ae2ea047aea94f48da`, based on
E `4f869c88`. This review reads source only. It does not independently repeat
the reported unit/cross checks, compile an ELF, access Oracle or a router, or
establish accepted performance or C equivalence.

## Result

No blocking reply-contract or cut-point mismatch was found for an isolated
UDP-hit fixture with 800 names, the loadgen's deterministic A/AAAA selection,
no local ownership, no interface/MAC deferral, and cache TTL longer than the
run. The run must establish these conditions and the counter gates below.
The diagnostic's hardcoded `full_path_prewarm:1000` is a threshold, not evidence
of 1000 completed full-path replies.

## Reply and cut-point checks

| Source location at reviewed commit | Independent observation |
| --- | --- |
| `dns/udp_stage_diagnostic.rs:23` | Only the 32-byte RD, QD=1, IN query shape is eligible; other header counts/flags, additional bytes, non-A/AAAA types, uppercase/nonhex index characters, and indices >=800 are rejected. ID is unrestricted and preserved. |
| `dns/udp_stage_diagnostic.rs:49` | A/AAAA answers preserve the question, use one compressed-owner answer, class IN, TTL120, and exact address/RDLEN pairs. Final sizes are 48/60 bytes. |
| `tools/dnsmasq/m6a_loadgen.c:164` | The original validator accepts those ID, flag, owner, question, type, class, TTL, address and exact-end conditions. TTL120 satisfies its nonzero/<=3600 rule; naturally ageing full answers may differ, so this is not frozen-C wire equivalence. |
| `main.rs:4987` | Receive cut follows successful receive, oversize rejection and resend invalidation, but precedes admission and owner processing. It reuses the existing scratch and the original socket's destination/interface send policy. It counts an intervention attempt, not a successful send. |
| `main.rs:5284` | Before-answer cut retains admission, owner metadata/decorating/interface preparation, then replaces the daemon answer call. Polling completions, event draining, dump/send and owner accounting after that call remain. |
| `dns/local.rs:251` | Skip-local replaces the local-answerer body while retaining `inspect_name` and its hint. The daemon's subsequent cache answer path still consumes that hint (`dns/daemon.rs:1861`). It also skips lease expiry and local validation, which is intentional only for the stated fixed fixture. |

## Required run gates and limits

1. `matched_queries` counts eligible received datagrams before admission, not
   successful replies or populated cache entries. For the intended fixture,
   require matched count to equal the sender's successfully sent eligible
   requests and require correct completions for prewarm and measurement with
   no wrong/timeout/transport/stale events. Full mode must have all cut counters
   zero; each intervention must have only its selected cut counter nonzero,
   equal to `max(matched_queries - 1000, 0)`.
2. The first 1000 sequential loadgen requests cover all 800 indices because
   `choose_dns` uses `sequence % cache_names`. Its `aaaa30` type selection is a
   function of the index, so it needs 800 entries, not 1600. This coverage is
   conditional on delivery/completion. Preserve upstream/cache evidence that
   warming completed and the measured interval remained a hit workload.
3. `selected` re-reads the process-global matched counter at each later cut.
   A request received among the first 1000 can be cut if deferred until after
   the threshold. Thus the source comment that those requests "always run in
   full" is stronger than the implementation. Keep MAC/interface deferral
   absent in this fixture. If deferred traffic is required, retain the
   request's eligibility/ordinal through the pending owner path before making
   that stronger claim.
4. Skip-local sits in the shared UDP/TCP local answerer and does not itself
   prove UDP provenance. Matching TCP traffic after the UDP threshold can
   take this cut without incrementing the parent's received-UDP count. Use an
   isolated UDP-only fixture; this is not a general transport-scoped facility.
5. Full mode is instrumented E, not the original E ELF. All modes share one
   immutable diagnostic ELF, but matching scans, atomics, branch outcomes,
   synthetic reply construction and allocation differ between modes. Receive
   skips owner work; before-answer allocates a 60-byte reply; skip-local keeps
   real downstream cache reply construction. Treat differences as cumulative
   interventions, not additive exact function costs or product speedups.

Minimal reporting correction before interpreting results: call the constant
`prewarm_threshold` (or document it as such), rather than presenting it as a
measured full-path completion count. Preserve actual matched/cut/sender/cache
evidence separately. This does not require a new diagnostic framework.
