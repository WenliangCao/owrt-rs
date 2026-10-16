# Exact image C versus immutable185: fresh stat and cycles

All 16 captures and 16 original single-window analyses completed once, in the
declared order. All 48 stat event rows are unscaled; all four samples have zero
lost samples. Author postflight passed 648 file hashes, control ACK ordering,
fixed drain, event attributes, original mapping/lineage analysis, 21 input
bindings and 179 source files. The C TCP sample had 56 descendants, all exited;
that observed count was not imposed as a validity requirement. Oracle was
quiet and explicitly handed to correctness for independent raw review.

Independent review subsequently passed in `4ffde164`: all648 raw files,
16 exact analyzer reproductions and all four perf.data exports matched.
The311 emitted ranges and27,371 samples, together with all reported numeric
fields, were independently checked. Review receipt SHA256 is
`7a2b7999091f77200dd413abc14ab3216c5946995febe39e86cb59cb66eec586`.
Correctness completed its quiet check before taking the next authorized task.

The result is a diagnostic on Oracle, not physical A53 cost or the frozen
five-pair performance acceptance. Every traffic window retains the original
1,000 excluded UDP prewarm operations, then 1,000 warmup plus 4,000 measurement
operations and a fixed 1 s drain. No instruction sampling, workload change,
failed-window replacement or historical-E counter pooling occurred.

## Counter results

Values are per completed operation, median [minimum, maximum] of the three
new stat windows. IPC is calculated per window from matching counters, then
summarized; it is not a ratio of independently selected medians.

| Transport and event | Exact C |185| Change of medians |
| --- | ---: | ---: | ---: |
| UDP user instructions |8943.18 [8852.11,9009.84]|7691.03 [7690.86,7691.13]|−14.00%|
| UDP user cycles |13464.32 [13271.17,14287.32]|17617.98 [17405.82,18113.49]|+30.85%|
| UDP kernel instructions |24777.76 [24150.29,25451.24]|27508.70 [26071.23,27566.49]|+11.02%|
| UDP kernel cycles |42033.15 [41730.53,42062.75]|42490.07 [41655.66,43785.33]|+1.09%|
| TCP user instructions |10114.12 [10034.13,10203.66]|9933.08 [9932.84,9933.18]|−1.79%|
| TCP user cycles |21835.10 [21338.48,22054.72]|24295.38 [22609.82,25014.42]|+11.27%|
| TCP kernel instructions |37914.95 [35900.64,43451.50]|39359.56 [37561.02,42104.78]|+3.81%|
| TCP kernel cycles |90075.14 [86718.45,96266.85]|76902.57 [72176.48,81029.85]|−14.62%|

Median user IPC is 0.6642→0.4365 for UDP and 0.4632→0.4088 for TCP. UDP 185 executes
fewer user instructions but takes more user cycles. Its kernel-cycle median
is close to C in these three windows. This points toward remaining user-code
costs; it does not identify a causal microarchitectural mechanism or prove
any unmeasured optimization's benefit.

## UDP self-cycle hotspots

The 185 sample contains 5,497 samples (54,970,000 total periods). Each share
below uses the entire denominator. Estimates are that share multiplied by
the new 185 UDP stat median 17,617.98 user cycles/query; they are cross-run
estimates, not measured per-function cycle counts. Names denote emitted
ranges and may include inlined work.

|185 emitted range | Share | Estimated user cycles/query |
| --- | ---: | ---: |
| `SinglePoll::process_udp` |5.530%|974.3|
| `DnsDaemon::answer_local_or_cached` |5.385%|948.7|
| `LocalAnswerer::answer_parsed_with_query_events` |5.367%|945.5|
| `SinglePoll::wait_for_files` |5.130%|903.8|
| `Hosts::name_exists` |4.748%|836.5|
| `SinglePoll::step` |4.603%|810.9|
| `[unnamed input section]` |3.747%|660.2|
| `wire::find_pseudoheader` |3.129%|551.3|

Subsequent ranges include `answer_fresh_address`3.056%, `step_udp`2.820%,
`Cache::names_for`2.802%, `query_dotted_name`2.510%,
`cached_address_is_unclaimed`2.238%, `process_admitted_udp`2.074% and
`admit_udp`2.037%. The unnamed input section remains unnamed; no nearest
symbol or inferred helper name is substituted. The vDSO user-unattributed
bucket is 2.983% and non-user-PC bucket 2.183%, both retained in the denominator.
The vDSO bucket is not individually attributed to clock functions.

Exact C's independent UDP sample contains 5,107 samples. Its leading emitted
ranges are `cache_find_by_name`18.014%, `strlen`7.578%,
`set_dns_listeners`7.402%, `answer_request`7.304%, `check_dns_listeners`5.600%,
`hostname_order`4.680%, `add_resource_record`4.190% and `main`3.936%.
User-unattributed 2.898% and non-user 2.173% remain explicit. Different emitted
range boundaries prevent treating similarly named C/Rust functions as exact
matched algorithm costs.

## TCP context and limits

C TCP's 8,172 samples place 36.637% in `memset` and 25.538% in
`cache_find_by_name`.185's 8,595 samples place 16.696% in `Cache::names_for`,
14.462% in `answer_parsed_with_query_events`, 8.389% in `step_tcp_clients`,
4.154% in `__libc_free` and 4.119% in `wait_for_files`. The 185 user-unattributed
vDSO bucket is 5.945%, and non-user PCs 1.175%; C's corresponding unattributed
totals are 2.937% and 1.371%. No function estimate uses the other side's or
another run's historic stat median.

One sample window per side/transport ranks where to inspect next, not stable
function precision or expected gains from combining prototypes. Existing
owner-clock, Rc/socket ownership and cached-local/lease qualifications can
be assessed against these ranges, but this profile does not select a new
product or replace full correctness/performance gates. Read-one/adaptive
and the rejected recvmmsg direction were not reopened.

## Reproduction and retained failure

The original plan is `ac6b2cf6`, SHA `f413ce05…444c86`; original observer and
analyzer bytes are unchanged. Before any capture, preflight found that the
host has `/usr/bin/llvm-cxxfilt-18` rather than unversioned `llvm-cxxfilt`.
That failure remains. Reviewed supplement `e6d42ac0` / `97f50393` supplies
only the original LLVM 18.1.3 demangler path to analysis argv, with its actual
binary hash. No capture or analysis window failed or was retried.

The original per-window analyzer provides counters, symbols, lineage and
unknown buckets. The archived [aggregation helper](aggregate_c185_hit_profile.py)
only applies the original C/E cross-window formulas; DNS reviewed its numeric
semantics. The [serial launcher](run_c185_hit_profile.py) and
[postflight receipt helper](postflight_c185_hit_profile.py) are byte-identical
copies of this run's private scripts, archived for provenance. They expect
the original private input filenames, not execution from this docs directory.

Raw files stay on Oracle at
`/home/ubuntu/dnsmasq-perf-20261015/loop/private/c185-hit-profile-20261016`.
Only a 70,185 B derived bundle (20 files) was copied locally, with every member
rehash checked. [Complete summary](c185-hit-stat-cycles-summary.json),
[preflight](c185-hit-stat-cycles-preflight.json),
[raw postflight](c185-hit-stat-cycles-postflight.json) and
[quiet handoff](c185-hit-stat-cycles-quiet.json) preserve the exact identities,
raw-count/scaling details, complete ranges, samples and evidence digests.
