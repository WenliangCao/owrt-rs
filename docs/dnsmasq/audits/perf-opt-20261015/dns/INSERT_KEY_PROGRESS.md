# Borrowed insertion key: local research after E freeze

Base: exact E `4f869c885b47dcf60d56c872e5b0b3c62237beea`.
Candidate: `43df58994a82aaf52b993752161c6423f449823d`, branch
`perf/dnsmasq-insert-key-20261015`. E is unchanged. This work uses only the
local Mac while Oracle timing and root-owned device work proceed separately.

## Attribution before choosing a change

The existing frozen-workload diagnostic confirms 4,000 singleton inspections
and 4,000 successful hint reuses: the ordinary hit has no redundant second
name-index lookup left. Exact SDK disassembly shows eight-byte NEON tag
comparison, followed by length/byte equality; no evidence supports replacing
the table, randomized hasher or 64-shard policy.

The high self-sample concentration is not a count of repeated source work.
For example, the fresh C profile assigns 1,151 instruction samples to the
first `cmeq`, with period 10,000, yet the validated ordinary path reaches that
first-group instruction once per initial lookup. Its 11.51 million weighted
sample period must not be read as that many executions of this instruction.
Periodic sampling concentration/skid is a plausible explanation; it is not
independently diagnosed here. The earlier rejected FNV control-work shortcut
and global Name shard field are not revived. A concrete allocation site was
selected instead of optimizing the largest sampled PC.

## Existing insertion boundary and small change

`insert_at_counted` receives an owned Record, creates an owned canonical name
copy, and uses that copy only for the immediate name-index conflict lookup.
The lowercase common case therefore copied bytes that were already canonical.
The accepted lookup/inspection functions already borrow such names, but the
insertion function did not.

The change borrows `record.name.as_wire()` when no ASCII uppercase byte is
present; uppercase retains the existing canonical allocation. Binary labels,
root terminator and length bytes keep exactly the old key bytes. The borrow is
of the caller-owned record, so cache removal, expiry and eviction cannot
invalidate it. The record moves into its Arc only after the borrow is unused.
No representation, new retained state, shard/hash policy, allocator, capacity,
record order, failure check or compiler option changes. The removed allocation
was infallible; no new allocation or failure boundary is introduced.

Independent static review found no blocker. The new 256-byte case test covers
binary names, case-insensitive replacement, preserved original stored case,
and retained snapshots. Local DNS tests: 386 passed, five existing fixture
tests ignored. Full frozen correctness remains pending for any final candidate.

## Local allocation screen

Both variants use the same real Cache API probe and System allocator, with
8,000 measured operations after setup/priming. Checksums and live-byte deltas
match for every scene:

| Scene | Allocations per operation, E → candidate | Requested bytes saved |
| --- | ---: | ---: |
| Lowercase replacement, 23-byte wire name | 7 → 6 | 23 per operation |
| Full pressure | 10 → 9 | 23 per operation |
| Reverse insertion | 21 → 20 | 23 per operation |
| Actual workload-length 16-byte name | 7 → 6 | 16 per operation |
| Four uppercase controls | unchanged | 0 |
| Binary long names | 56,000 → 49,500 total allocations | 260,000 total bytes |

The binary fixture includes ASCII-uppercase payload bytes in 15 of 80 names,
so precisely the other 65 names avoid the canonical allocation. All ten
whole-answer allocation controls remain identical, including RRsets and both
CNAME forms. Existing probe cases are unchanged; lowercase short names and
uppercase variants are narrow new controls in the same probe.

`insert-key-local-screen.json` records source/probe/compiler/artifact identities
and all results. This is **not a CPU or device speedup claim**. The new uppercase
detection scan may cost CPU, so future Oracle PMU and plain timing must include
uppercase, reverse, binary, ordinary read and configured-CNAME controls. No
remote work begins until root releases the current timing reservation. The
candidate is not integrated or correctness/performance qualified.

## Reverse-path refinement

Root independently noted that reverse insertion never uses the canonical key.
Revision `60c3bdf2` moves the entire key construction into the existing forward
branch, with the same conflict/expiry loop. Reverse names now avoid both the
discarded copy and the new uppercase detection scan. No helper or state is
added. The prior `43df5899` source, allocation results and binaries remain
preserved rather than being replaced by the better result.

The same 386 DNS tests pass again. The same nine insertion and ten answer
allocation controls were rerun: the only counter change from the first variant
is uppercase reverse insertion, now also 21 → 20 allocations and 23 fewer
requested bytes per operation. Every checksum/live-byte balance matches E.
`insert-key2-local-screen.json` records the new artifacts and raw hashes.
CPU remains unmeasured; the forward-uppercase detection overhead still needs
the deferred Oracle controls. No remote work was run.

## Native Oracle counter screen after E timing completed

Root released the exclusive E timing reservation before this work. Oracle's
existing source E was copied locally into separate DNS baseline/candidate
directories; 172 source files were checked against Git, and exactly the two
cache/test files changed to `60c3bdf2`. E was rechecked unchanged. Only 28,853
bytes of patch/identity/probe input were uploaded. Builds used one job on CPU3
at nice10; no bulk source or artifact transfer occurred. Native Linux cache
tests pass 42/42.

The allocation results match the local screen. Three-pass native instruction
changes against E show the limits of the allocation saving:

| Insert scene | Instruction change |
| --- | ---: |
| Replacement | −1.966% |
| Full pressure | −1.244% |
| 16-byte name | −2.069% |
| Reverse / uppercase reverse | −0.369% / −0.371% |
| Uppercase replacement / pressure / short | +0.442% / +0.738% / +0.494% |
| Binary long names | +2.594% |

The uppercase detection scan has a real instruction cost, and the binary-long
control regresses despite fewer allocations. Six whole-answer instruction
controls are effectively unchanged, except hosts at −0.709%, which cannot be
accepted as a timing gain from counters. All ten whole-answer allocation
controls remain exactly equal. These results do not justify automatic
integration or a universal improvement claim.

`insert-key2-oracle-screen.json` preserves every counter sample, source/artifact
identity and raw hash. Only its 40,698-byte derived result was retrieved; raw
logs and binaries remain on Oracle. No plain timing has run: root must decide
whether this small local gain merits a complete focused timing attempt once
other work is quiet, or reject it with the current cost evidence. D/E remain
unchanged and no router access occurred.
