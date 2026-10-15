# Exact image C versus E: user/kernel instruction and cycle attribution

Exact C is `097a9e21…`, candidate E is `8b8082b9…`. These are Oracle diagnostics, not the frozen five-pair performance acceptance and not on-device CPU measurements. The original 12 stat-only plus 4 instruction-sample windows completed first. Four separately planned cycle-sample windows followed after user cycles diverged more than instruction counts. All 20 captures completed the same 5,000 requests with zero client errors, plus the fixed one-second child drain. No capture was retried or replaced.

## Separate stat windows

All 12 stat windows used one inherited `{instructions:u,instructions:k,cycles:u,cycles:k}` group. Every raw time-enabled equals time-running, with 100% CSV running time and no scaling. Values below are per 5,000 completed operations, expressed per operation; brackets show the complete three-window range.

| Scene | Metric | C median [range] | E median [range] | E/C change |
|---|---|---:|---:|---:|
| UDP hit | instructions:u | 8,922.21 [8,883.90, 8,924.07] | 9,534.41 [9,534.40, 9,534.93] | +6.86% |
| UDP hit | instructions:k | 25,661.54 [23,811.95, 31,384.31] | 28,571.84 [26,992.83, 33,701.66] | +11.34% |
| UDP hit | cycles:u | 14,416.39 [14,290.92, 15,763.93] | 22,409.47 [22,129.45, 23,808.44] | +55.44% |
| UDP hit | cycles:k | 41,867.75 [40,446.32, 52,504.79] | 45,499.36 [43,219.91, 55,573.77] | +8.67% |
| TCP hit | instructions:u | 10,070.31 [9,793.89, 10,140.23] | 10,803.87 [10,803.67, 10,803.90] | +7.28% |
| TCP hit | instructions:k | 42,646.74 [42,287.53, 43,910.58] | 37,745.80 [37,735.20, 38,754.86] | -11.49% |
| TCP hit | cycles:u | 23,198.67 [23,035.39, 24,222.89] | 26,530.76 [26,439.94, 27,170.18] | +14.36% |
| TCP hit | cycles:k | 99,653.03 [99,301.68, 102,118.74] | 75,303.18 [73,382.15, 78,562.75] | -24.43% |

UDP E retires 6.86% more user instructions but consumes 55.44% more user cycles in the medians. Per-window user IPC is C 0.566–0.622 versus E 0.400–0.431. TCP E has more user work but less kernel work on this host; C TCP forks. These data do not establish a microarchitectural cause or explain a physical-router CPU ratio by themselves.

## User-cycle self samples

Each percentage uses the full sample-period denominator, including unknown PCs. Estimated cycles/query multiply that share by the independent stat median user cycles/query. These are cross-run estimates, not directly counted function cycles. Inlined work is charged to its emitted input section or symbol.

| Scene / side | Emitted function or input section | Self share | Estimated user cycles/query |
|---|---|---:|---:|
| UDP / C | `cache_find_by_name` | 18.38% | 2,650.4 |
| UDP / C | `answer_request` | 7.79% | 1,122.6 |
| UDP / C | `check_dns_listeners.lto_priv.0` | 7.66% | 1,103.9 |
| UDP / C | `strlen` | 6.41% | 924.6 |
| UDP / C | `set_dns_listeners.lto_priv.0` | 5.17% | 745.3 |
| UDP / C | `main` | 3.97% | 572.9 |
| UDP / C | `hostname_order` | 3.36% | 484.4 |
| UDP / C | `no_sized_symbol_or_input_section` | 2.70% | 388.9 |
| UDP / E | `dnsmasq_rs::dns::local::add_local_records_for_name` | 11.24% | 2,519.5 |
| UDP / E | `<dnsmasq_rs::dns::local::LocalAnswerer>::answer_parsed_with_query_events` | 9.08% | 2,034.1 |
| UDP / E | `<dnsmasq_rs::dns::cache::Cache>::names_for` | 6.50% | 1,456.2 |
| UDP / E | `<dnsmasq_rs::SinglePoll>::wait_for_files` | 4.73% | 1,061.0 |
| UDP / E | `<dnsmasq_rs::SinglePoll>::process_udp` | 4.19% | 938.4 |
| UDP / E | `__libc_free` | 3.51% | 785.9 |
| UDP / E | `unattributed_image` | 2.93% | 656.5 |
| UDP / E | `__libc_malloc_impl` | 2.84% | 635.6 |
| TCP / C | `memset` | 28.16% | 6,533.6 |
| TCP / C | `cache_find_by_name` | 20.75% | 4,813.4 |
| TCP / C | `check_dns_listeners.lto_priv.0` | 6.80% | 1,578.6 |
| TCP / C | `no_sized_symbol_or_input_section` | 5.75% | 1,334.1 |
| TCP / C | `answer_request` | 5.08% | 1,178.8 |
| TCP / C | `add_edns0_config` | 3.08% | 715.0 |
| TCP / C | `read_writev` | 2.89% | 669.3 |
| TCP / C | `strlen` | 2.62% | 607.7 |
| TCP / E | `<dnsmasq_rs::SinglePoll>::step_tcp_clients` | 8.41% | 2,230.4 |
| TCP / E | `dnsmasq_rs::dns::local::add_local_records_for_name` | 7.45% | 1,976.6 |
| TCP / E | `<dnsmasq_rs::dns::local::LocalAnswerer>::answer_parsed_with_query_events` | 6.96% | 1,846.7 |
| TCP / E | `<dnsmasq_rs::SinglePoll>::wait_for_files` | 6.27% | 1,662.8 |
| TCP / E | `unattributed_image` | 5.91% | 1,568.9 |
| TCP / E | `<dnsmasq_rs::dns::cache::Cache>::names_for` | 5.38% | 1,427.0 |
| TCP / E | `<dnsmasq_rs::dns::cache_engine::CacheContext>::answer_records_filtered` | 3.41% | 905.3 |
| TCP / E | `__libc_free` | 3.28% | 871.4 |

The two leading E local-answer functions together account for 20.32% of UDP cycle samples (about 4,554 estimated user cycles/query), and 14.41% of TCP samples (about 3,823). `Cache::names_for` is another 6.50% / 5.38%. This supports examining the local-answer path before another cache-wide rewrite. C `cache_find_by_name` serves a different combined local/cache interface, so similarly named functions are not assumed to have identical responsibilities.

Instruction self shares differ: E UDP `__libc_free` is 13.64%, malloc 6.41%, `decode_name` 4.48%, and `Question::parse` 3.27%; their cycle self shares are smaller than the leading local functions. C TCP `memset` accounts for 50.02% of instruction samples and 28.16% of cycle samples. One sample window per event/side/scene is diagnostic evidence, not a stable per-function performance guarantee.

## Identity, descendants and unattributed samples

C uses the exact stripped image plus its original build’s full-symbol companion `79cb9590…`. `sstrip -z` reproduces the exact C artifact. The analyzer independently rechecks all 22 allocated section layouts/bytes against the actual captured stripped ELF before admitting 332 sized functions; three zero-size functions remain unassigned. The four exact mapped libraries are hashed and use their own defined, sized dynamic symbols. E uses its exact same-build linker map. No native rebuilt C or neighboring-symbol guesses are substituted.

Both C TCP sample windows contain the root plus 56 children. Every child is admitted through an observed fork, all sample PIDs belong to the active tree, and every child has an observed exit before the fixed end. Executable MMAPs must match the inherited identity; exec and orphan-PID records are rejected. Other scenes have only the root. All eight sample exports match perf self-report sample/period totals with zero lost samples. Actual perf event attributes retain inherit=1 and exclude_kernel=1.

| Event / scene / side | Samples | Non-user PC share | Other unattributed user share |
|---|---:|---:|---:|
| instructions:u / UDP / C | 4,056 | 1.28% | 1.18% |
| instructions:u / UDP / E | 4,040 | 6.73% | 0.59% |
| instructions:u / TCP / C | 4,696 | 5.00% | 0.94% |
| instructions:u / TCP / E | 5,092 | 1.63% | 11.25% |
| cycles:u / UDP / C | 6,190 | 2.55% | 4.25% |
| cycles:u / UDP / E | 9,695 | 2.02% | 2.93% |
| cycles:u / TCP / C | 10,155 | 2.34% | 5.80% |
| cycles:u / TCP / E | 13,275 | 3.19% | 5.91% |

Some user-event samples carry K-mode PCs. Their cause has not been established. They remain explicitly unattributed in the full denominator and are never counted as kernel instructions or cycles. The other unattributed samples include vDSO PCs and exact ELF symbol gaps. The first C UDP analyzer attempt rejected non-user PCs; the analyzer was corrected to retain them and the original capture was reused. No workload was rerun.

Exact C symbol reproduction and matching source digests: [symbol receipt](image-c-symbol-receipt.json).

Plans: [instruction/stat matrix](image-c-e-profile-plan.json), [separate cycle matrix](image-c-e-cycles-plan.json). Full derived ranges, raw-count/scaling fields, fork trees, event attributes, identity proofs and evidence digests: [instruction summary](image-c-e-instruction-summary.json), [cycle summary](image-c-e-cycles-summary.json). Raw perf/config/binary evidence remains private on Oracle.
