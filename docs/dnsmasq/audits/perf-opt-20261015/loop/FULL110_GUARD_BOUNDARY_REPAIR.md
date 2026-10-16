# Preserve each full-run scene's health boundary before stopping its guard

This is the retained **superseded, unapproved** first implementation. Its use
of baseline coverage rules for runtime segments was incorrect for short resume
segments. Use the corrected [runtime/baseline separation](FULL110_RUNTIME_BOUNDARY_REPAIR.md)
and its hashes; the initial implementation was not deployed.

The generic device controller now captures guard evidence after every scene's
original ten windows, CPU endpoints, validation and verified archives finish,
and before its existing `guard_stop` sends SIGTERM. The unchanged health helper
validates the captured prefix and complete final log. A cancelled shutdown
probe stays visible as a tail observation; it is neither a successful probe nor
grounds to discard an actual failure within the captured prefix.

This is preparation for a future full110 run, not a run or acceptance result.
The current185 ten-window private snapshot and all historical attempts remain
unchanged. No device or Oracle action was performed for this fix.

## Exact tools and separate bundles

| Role | SHA256 |
| --- | --- |
| Historical generic controller | `7c93cfb1ec060a11cebfa14d1a5cf1a31d6bdf40853ed6c4287b4630108e21df` |
| New device full-run controller | `c4f196805889abf996e006d52ef53539423f4ad8d88d9d512180dadf76791a2c` |
| Unchanged capture/health helper | `0926acd8d2a204fbd1fe18ca7d2f1e7edd0d02b8ca727544d2217db99e16ebad` |
| Unchanged Oracle controller | `1e80a915686c14ed7a07dc163f38019fe842f60dde2ce43c0fce63f13670ecb3` |
| Unchanged analyzer | `10addedf927936df6bc112e4dcc8d5f0c9ef9af8466a6cde11dc1a56ebad2283` |

Keep two tool directories. Fresh-health collection uses helper0926 alongside
the original7c93 controller, whose hash its standalone `main` still requires.
The new device full110 directory uses controllerc4f19680 alongside helper0926;
it calls only the helper's capture/validation functions. Do not run standalone
fresh-health collection from that new full-run directory or relax its old pin.
The new controller imports the helper inside `main`, avoiding a top-level
circular import. Both import orders and both actual local directory bundles
were checked.

Oracle's controller is unchanged and imports only the identical `SCENES`,
`validate` and `write` definitions. Its existing frozen7c93 input bundle remains
usable for Oracle110. No Oracle timing code, guard binary, case script, load
generator, scene, alternating order, source/ELF, analyzer or statistical rule
changes in this fix. The full device measurement loop and all non-main generic
functions were checked byte-for-byte against7c93.

## Per-scene evidence

Every executed segment keeps its existing unique label
`<prefix>-<scene>-guard-<time_ns>`. A directory with that name contains:

- `pre-stop-capture.raw`: every byte read before the stop call, including any
  partial last line.
- `pre-stop-prefix.jsonl`: its newline-complete prefix, selected by byte boundary
  without inspecting status fields.
- `stop-request.json`: capture lengths, hashes and pre-stop timestamps from0926.
- `external-health-capture.raw`: a snapshot of the existing continuous external
  monitor. Only whole records enter the scene check; its final complete log is
  checked after the monitor joins.
- `guard-verification.json`: helper identity, qualified/final/tail sample counts,
  coverage and complete-final digest.

The original top-level `<guard-label>.jsonl` and `.stderr` remain the complete
final logs. A bounded post-stop wait allows the original `monitor_stopped`
record to arrive; missing or malformed completion still fails. The helper
requires the entire raw capture, including partial bytes, to be an unchanged
prefix of the final log. All final PID/starttime, memory, route and stop-event
checks remain. DNS/HTTP qualification uses every complete captured record.
No first-sample threshold, status filtering or new health probe is added.

Each scene is validated before another scene starts. The external monitor
continues across scenes as before. After the final scene it must stop cleanly,
and every complete IPv4/IPv6 external result must pass before `complete.json`
is written. Every new guard/evidence/external validation exception enters the
existing failure path, retains results, attempts task-only STOP and re-raises
without success. Original measurement-invalid row semantics are unchanged;
the existing acceptance analyzer still requires the complete valid matrix.

Resume now binds the exact controller and helper identities, so an old7c93 run
without captures cannot be relabelled as new evidence. Resumed segments receive
new unique capture directories. The unchanged helper's120-second coverage rule
is not manufactured by padding a short resumed segment or borrowing another
segment's samples; insufficient evidence fails and remains retained.

## Local verification

42 tests passed using mocked SSH/process/guard interactions, including a complete
original110 schedule with11 distinct capture boundaries, cancelled tails,
prefix failures, changed partial captured bytes, unsafe tails, missing shutdown,
external failure after capture, a monitor that does not exit, helper identity
mismatch, old-controller resume rejection and original archive/prune failures.
The standalone baseline test uses the actual Git-retained7c93 bytes and their
real hash, with only device calls mocked. The original ten-wrapper tests remain;
only their temporary mock-plan controller hashes were rebound for this worktree.
Production ten plans and private copies were not modified.

[The derived repair receipt](full110-guard-boundary-repair.json) records test
output hashes, unchanged inputs and exact scope. Independent correctness review
and the actual source's full qualification are still required before either
formal110 launch. Historical failed health attempts are not reclassified.
