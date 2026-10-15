# Local-only preparation for the next three independent screens

No input was uploaded or executed. The fixed order is integration, bounded
local miss, then the original owned local miss. Each source is compared to its
own F control; results from earlier variants are not added together or pooled.

| Order | Exact source | Frozen plan | Native windows |
| --- | --- | --- | ---: |
| 1 | `8d572ba1348037420da6c6a36dd8623a08572f25` | [Integration](../dns/local-cache-integration-native-plan.json) | 240 |
| 2 | `c44cd116283b9e358f7cfedab13ee5eb3d9b920e` | [Bounded local miss](../dns/local-miss-stack-native-plan.json) | 240 |
| 3 | `1676fbb696bd7a5f76d3e92d2ae5bf0eee22e983` | [Owned local miss](../dns/local-address-miss-native-plan.json) | 240 |

The three plans retain the required prepared source directories under
`root/source-local-cache-integration`, `root/source-local-address-miss-stack`
and `root/source-local-address-miss`. Each side's 162 file hashes were checked
against the exact Git blobs. The existing runner `e5c6e155…fe6ff`, probe,
15 scenes, operation counts, alternating 3 PMU/5 plain pairs, checksums,
CPU placement and decision rules are unchanged. Each round is 90 stat and
150 plain windows plus four preceding build commands, for 244 commands.
The inherited prose referring to three probes does not change the executable
two-source plan; frozen plan bytes remain intact.

Byte-identical plan/runner/probe copies and minimally mapped existing analyzers
are prepared locally under private
`perf-opt-20261015/local-cache-native-inputs/<candidate>`. Analyzer changes are
limited to paths, scope text and 240/244 cardinalities; statistics are unchanged.
[The preparation receipt](local-cache-next-inputs-preparation.json) records
all identities and checks. Nothing in this preparation authorizes a launch.

Two disabled owner32 templates reuse the successful original controller
`3068cffd…b073`:

- [Integration template](run_local_cache_integration_owner_screen.py.in)
- [Bounded local-miss template](run_local_miss_stack_owner_screen.py.in)

Their measurement loops, original driver/load generator, three PMU and five
plain pairs per load, alternating controls and failure handling are unchanged.
Only candidate/source/SDK/output/declared-plan mappings are filled. Exact SDK
ELF and build-receipt hashes, qualification receipt path/hash and its actual
single- or multi-candidate schema remain pending. Missing bindings stop before
filesystem/process actions; a separate explicit stop remains at the qualification
block until its real completion, source/log/artifact and original test checks
are inserted. No previous receipt's field spelling is assumed. Templates were
parsed as Python syntax only, never run.

All three related Linux gates and SDK builds, PGO smoke3 termination, DHCP's
SDK pre-download and identity verification, an idle Oracle inventory, and the
coordinator's explicit new reservation release remain required before timing.
No remote read, build, workload, product edit or router action occurred during
this local preparation.
