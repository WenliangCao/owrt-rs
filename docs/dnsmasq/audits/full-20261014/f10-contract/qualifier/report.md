# F10 PTR qualifier correction

The previous checker waived every `ptr-order-only` difference. That was too broad: C/C variability in one state does not authorize a different source, query phase, or order change caused by an intervening query. The new checker defaults to rejection.

The [observed manifest](observed-ptr-order-manifest.json) contains only 11 query tracks and 23 explicitly observed varying states from the retained exact-C controls. Each entry is bound to case, query name/type, transport, state labels and the complete ordered query sequence. Candidate sequences must equal a complete sequence observed in one C process; they cannot combine individually allowed phase orders from different C runs. The manifest is bound to the complete reference document hash. Raw ordered responses are never sorted or rewritten; sorting only classifies differences.

RRset, header, TTL, count, TC and A/AAAA-order changes remain failures. A PTR state without corresponding C/C evidence also fails. A third permutation not observed in the controls fails rather than triggering more repeats. Any future source-derived allowance requires a separate explicit contract and review; this manifest contains none.

Offline rechecking b99e against unchanged archives gives **not accepted**: 16 differences qualify, and 12 `leases-dhcp` differences lack matching state evidence. All 205 repeated PTR state families in the candidate are internally stable, but this does not excuse the 12 order differences. Full query-track results are in [b99e-recheck.json](b99e-recheck.json). The earlier b99e report is labeled superseded; its raw backup remains byte-identical.

Validation includes 15 unit tests and 12 negative controls made from the archived exact-C observations. They reject a flipped PTR order in a C-stable case, an unknown state, a changed question/transport/case, same-state repeat instability, before/A/after track splicing, unobserved three-owner permutations, forward order, header/TC/TTL/count/RRset mutations, missing cases and missing observations. The newly discovered five-line stateful PTR regression has no allowance and defaults to failure. No additional daemon workload was run for this checker change.

By default, every reference case must be present. An explicit `expected_cases` list (probe `--case`) selects a subset while retaining the original full-reference manifest hash. The semantic checker does not independently authenticate candidate ELF identity; the runner's input and `/proc/PID/exe` assertions remain required.

Reproduce the offline evidence with `derive.py --baseline-archive PRIVATE/baseline-evidence.tar.gz --candidate-archive PRIVATE/candidate-b99e-evidence.tar.gz --output NEW_DIRECTORY`. Run the unit controls with `python3 -m unittest discover -s tools/dnsmasq -p test_f10_contract_check.py -v`.

Artifacts: [summary](summary.json), [negative controls](negative-controls.json), [manifest](observed-ptr-order-manifest.json), [derivation](derive.py). Archive identities are recorded in the summary; no original raw files were changed.
