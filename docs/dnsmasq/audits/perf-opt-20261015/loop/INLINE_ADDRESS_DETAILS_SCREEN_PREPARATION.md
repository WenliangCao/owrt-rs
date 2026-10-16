# Prepare bare 1df native240 and owner32 versus G

Local preparation only. Frozen G remains
`185db90c9cabd26c0af09765636ef15bf6d35f79`; the bare candidate is
`1df135dc2401a9f0ec2f219b1e4a8f07dd637db1`, based on 6ab. No
210/849/2b/803 or lazy-metrics changes are combined. Actual candidate SDK,
related gate, independent SDK review and exclusive release remain null.
Nothing was transferred, built or measured.

The [native preparation](inline-address-details-native-preparation.json)
retains the original 15 scenes, 90 stat windows, 150 plain windows and four
build commands. Operation counts, checksums, zero-allocation assertions,
paired ordering, CPU/nice placement, opt3/LTO/codegen settings and original
statistical decisions are unchanged. The runner changes only its descriptive
scope; the analyzer changes only candidate names and evidence paths.
Whole-process counters include exec, setup, priming and teardown. The probe
can screen cache/lease paths and regressions but omits SinglePoll, private
socket Rc, owner clocks and reply recycling.

The [owner32 preparation](inline-address-details-owner32-preparation.json)
retains all 32 windows, 12 stat and 20 plain: low 200/s and unpaced high load,
800 names, A/AAAA 70/30, prewarm, warmup/measurement/drain durations, original
placement, paired order, normalization and W/direction/precision decisions.
The f0b39 driver, f7c7d8 loadgen, upstream and all eight analysis imports remain
unchanged. The wrapper substitutes only candidate identity, paths, descriptive
scope and expected related count 961 to 963. The analyzer changes only scope.
There is no longer window, new estimator, measurement or tool relaxation.

The [binding manifest](inline-address-details-screen-preparation.json) records
exact script substitutions and every owner32 argv. Both sides' 162 native and
179 SDK input hashes were checked against their named Git commits. DNS's
`0d90579d` manifest has SHA-256
`e913ee10beaaf34cc2d38e510f5bd8ba69c838384b23fe03380e2eba7c544d03`.
Only `cache.rs`, `cache_engine.rs` and `cache_tests.rs` differ from 6ab among
the candidate SDK inputs. The original hot15 probe remains byte-identical,
SHA-256 `72d836d1f868d4e608c14a47105b29dda35f8533ec6ce3456ca1bbc539db76bd`.
The canonical f454 SDK builder and f280 helper are unchanged. The projected
963 count is identity metadata, not a completed gate or inherited PASS.

803's original owner32/routerten and complete raw audits, transfers and
explicit quiet release have priority. After that boundary, 1df still requires
fresh original related groups, canonical SDK build, actual independent audit,
complete source/artifact bindings and pretransfers, and an explicit native
slot release. Its original native240 must finish and release quietly before
owner32 starts. Every failed/partial attempt remains evidence; no replacement
windows, selective reruns or pooling with historical controls is permitted.

The unchanged owner wrapper rejects preparation status before output creation.
The original native runner has no internal ready-status assertion, so its
gate/SDK/review/pretransfer/quiet prerequisites remain enforced by the owner;
do not invoke this preparation. Local checks parsed all four scripts,
reproduced their declared substitutions and verified the original protocol
fields, source hashes, probe/import bytes and every owner32 argv. Independent
preparation review is pending. No full110 or promotion is implied.
