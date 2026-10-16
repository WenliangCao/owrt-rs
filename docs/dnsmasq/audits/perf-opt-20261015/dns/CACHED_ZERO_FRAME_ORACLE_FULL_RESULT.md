# E/185 Oracle full matrix: complete, no discernible primary change

The original **110/110 windows are valid**, with no failed, omitted, repeated
or supplemental window. The unchanged analyzer completed without parse errors.
Independent audit `12ebf728` verified all **110 archives and 3,430 raw files**,
redecoded the original records, and reproduced the complete statistics without
errors. None of the 33 primary p50/p95/CPU comparisons passes the original
combined discernibility rules. This is inconclusive performance evidence,
not proof of equivalence or acceptance of the candidate.

**The Oracle UDP-hit CPU objective is not demonstrated.** E 26→185 24 us/query
is −7.692%, below W 16.667%. Median CPU ticks 13→12 differ by only one tick,
so the original requirement for a median difference greater than 8 ticks fails
despite 4/5 improving pairs. TCP-hit 34→32 us/query is likewise below W and fails precision.
Every original observation remains included, including wider latency ranges
and adverse CPU or latency changes.

## Exact scope and complete execution

The [frozen plan](CACHED_ZERO_FRAME_ORACLE_FULL.md) is `f029e303`, with launch
receipt `95bfc547`. The source is
`185db90c9cabd26c0af09765636ef15bf6d35f79`, ELF
`9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99`.
The fresh baseline is accepted E source
`4f869c885b47dcf60d56c872e5b0b3c62237beea`, ELF
`8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27`.
No prior E/F/0161, owner32, native or router samples enter these pairs.

Exact-source full qualification `3c8d46e9`, receipt SHA `d76634ea…d4be`,
preceded launch: 957 actual short tests including 17 allocation tests, all 44
families / 67 jobs, and the original boundary corpora. Approved differences and
the earlier zero-comparison corpus-directory setup failure remain in that
receipt. Tool-boundary review `f95f83a4` explicitly preserves the original
Oracle controller `1e80a915…0ecb3`, companion `7c93cfb1…8e21df` and analyzer
`10addedf…d2283`. The device-specific prefix consumer is not imported here.

All 11 scenes ran five alternating pairs in their original order and workload,
CPU2/nice10 placement and isolated network namespace. The run started at
2026-10-16 02:45:12 UTC and its last window completed at 2026-10-16 03:37:28 UTC.
The controller PID 776427 exited with empty stderr; the original temporary
runtime directory was removed only after each external archive/copy was
verified. There was no failure marker, valid-window replacement or new rule.
This Oracle run performed no router operation.

## All eleven CPU comparisons

Values are medians over the original five windows per side. Network CPU uses
actual warmup plus measurement completed operations; lifecycle CPU retains the
original whole-round RUSAGE_CHILDREN scope divided by 20 operations. All eleven
CPU precision checks fail; no CPU result is promoted using direction alone.

| Scene | E us/operation | 185 us/operation | Change | W | Same-direction pairs | Absolute median tick difference |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| udp-hit | 26.00 | 24.00 | -7.692% | 16.667% | 4/5 | 1.0000 |
| udp-miss | 78.00 | 82.00 | +5.128% | 25.641% | 4/5 | 2.0000 |
| udp-mixed | 42.00 | 42.00 | +0.000% | 19.048% | 0/5 | 0.0000 |
| tcp-hit | 34.00 | 32.00 | -5.882% | 12.500% | 5/5 | 1.0000 |
| tcp-miss | 76.00 | 76.00 | +0.000% | 7.895% | 0/5 | 0.0000 |
| dhcp-home6 | 80.00 | 76.00 | -5.000% | 30.000% | 3/5 | 1.0000 |
| dhcp | 540.00 | 524.00 | -2.963% | 5.344% | 4/5 | 4.0000 |
| startup-small | 1513.75 | 1543.20 | +1.945% | 7.627% | 4/5 | 0.0589 |
| config-small | 1602.05 | 1691.70 | +5.596% | 8.338% | 5/5 | 0.1793 |
| hup-small | 327.30 | 312.45 | -4.537% | 52.728% | 3/5 | 0.0297 |
| hup-large | 2833.35 | 2839.90 | +0.231% | 3.903% | 3/5 | 0.0131 |

The UDP-hit original CPU values are E `[26,30,26,30,26]` and 185
`[22,24,24,24,26]` us/query. UDP-miss CPU increases 78→82 (+5.128%),
configuration CPU 1602.05→1691.70 (+5.596%), and startup 1513.75→1543.20
(+1.945%); each remains indistinguishable under its original gates. Lifecycle
rounds also have fewer than 10 ticks, so they cannot pass the CPU precision gate.

## All twenty-two latency comparisons

All entries below remain indistinguishable under the unchanged full-range W,
at-least 4/5 direction and, for lifecycle scenes, 1 ms observation limit. Config
p50 is a retained adverse boundary case: +2.693% exceeds W 2.566% in 5/5 pairs,
but its absolute increase is only 0.065161 ms, below 1 ms. The original
resolution limit prevents classifying it as discernible. No p99 claim is made
below 10,000 samples.

| Scene | Metric | E median ms | 185 median ms | Change | W | Same-direction pairs |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| udp-hit | p50 | 0.035280 | 0.033320 | -5.556% | 41.897% | 4/5 |
| udp-hit | p95 | 0.062201 | 0.059400 | -4.503% | 34.746% | 3/5 |
| udp-miss | p50 | 1.173289 | 1.173930 | +0.055% | 2.427% | 4/5 |
| udp-miss | p95 | 1.216610 | 1.218050 | +0.118% | 4.113% | 4/5 |
| udp-mixed | p50 | 0.038081 | 0.036280 | -4.729% | 6.512% | 5/5 |
| udp-mixed | p95 | 1.248371 | 1.243890 | -0.359% | 1.675% | 3/5 |
| tcp-hit | p50 | 0.042961 | 0.042121 | -1.955% | 25.607% | 4/5 |
| tcp-hit | p95 | 0.075361 | 0.073041 | -3.079% | 31.157% | 5/5 |
| tcp-miss | p50 | 1.178330 | 1.187770 | +0.801% | 1.531% | 3/5 |
| tcp-miss | p95 | 1.222610 | 1.229451 | +0.560% | 2.531% | 4/5 |
| dhcp-home6 | p50 | 0.062960 | 0.062840 | -0.191% | 47.395% | 4/5 |
| dhcp-home6 | p95 | 2.082617 | 1.971256 | -5.347% | 17.693% | 4/5 |
| dhcp | p50 | 2.647782 | 2.636782 | -0.415% | 8.063% | 2/5 |
| dhcp | p95 | 3.134066 | 3.131386 | -0.086% | 4.752% | 3/5 |
| startup-small | p50 | 1.438132 | 1.465092 | +1.875% | 58.809% | 4/5 |
| startup-small | p95 | 1.524053 | 1.521212 | -0.186% | 56.684% | 1/5 |
| config-small | p50 | 2.419580 | 2.484741 | +2.693% | 2.566% | 5/5 |
| config-small | p95 | 2.491061 | 2.574421 | +3.346% | 3.477% | 5/5 |
| hup-small | p50 | 0.290162 | 0.284842 | -1.833% | 93.695% | 4/5 |
| hup-small | p95 | 0.339202 | 0.337362 | -0.542% | 114.513% | 2/5 |
| hup-large | p50 | 2.656822 | 2.654662 | -0.081% | 4.134% | 2/5 |
| hup-large | p95 | 2.755502 | 2.780463 | +0.906% | 5.742% | 3/5 |

The full result retains all DORA observations and the original ranking rule:
150-client DORA p50/p95 both remain indistinguishable under the existing
comparison; the six-client values stay descriptive. Every per-window latency, scheduled-latency and send-lag quantile,
count and CPU endpoint remains in the derived JSON and original private raw.

## Resource observations and delivery artifact

RSS median grows 60–76 KiB across the eleven scenes. Median file-backed peak
RSS increases 64 KiB in each scene; median anonymous peak changes −4 to +8 KiB.
These are measured observations, not an attribution to the retained reply
buffer or an invented memory allowance. All parent/tree FD medians are unchanged.
The seven network scenes retain one process and one thread in every observed
range; lifecycle ready snapshots also retain one thread. Lifecycle resource
values are readiness snapshots, not transient peaks.

The table reports each side's median across its five windows. RSS is each
window's median, while anonymous/file values are its peak; all complete ranges
remain in the result and independent audit.

| Scene | RSS E→185 KiB | Anonymous peak E→185 KiB | File peak E→185 KiB | Parent/tree FD E→185 |
| --- | --- | --- | --- | --- |
| udp-hit | 2388→2452 | 520→520 | 1868→1932 | 12→12 / 12→12 |
| udp-miss | 2434→2498 | 668→676 | 1804→1868 | 13→13 / 13→13 |
| udp-mixed | 2468→2534 | 612→608 | 1868→1932 | 12→12 / 12→12 |
| tcp-hit | 2584→2648 | 716→716 | 1868→1932 | 20→20 / 20→20 |
| tcp-miss | 3526→3602 | 2124→2124 | 1804→1868 | 28→28 / 28→28 |
| dhcp-home6 | 2288→2356 | 356→360 | 1932→1996 | 18→18 / 18→18 |
| dhcp | 2748→2814 | 816→820 | 1932→1996 | 18→18 / 18→18 |
| startup-small | 2212→2272 | 344→340 | 1868→1932 | 19→19 / 19→19 |
| config-small | 2212→2272 | 344→340 | 1868→1932 | 19→19 / 19→19 |
| hup-small | 2280→2340 | 352→352 | 1932→1996 | 19→19 / 19→19 |
| hup-large | 3096→3164 | 1172→1172 | 1932→1996 | 19→19 / 19→19 |

Oracle PSS and USS were measured directly by the original probe and rechecked
independently, not inferred from RSS. For UDP hit both peak medians are
2380→2444KiB (+64 KiB); across the seven network scenes their peak median growth
is 60–72 KiB. Those values and ranges are retained separately. They make no
physical-router memory claim.

Candidate ELF is 2,145,051 bytes, +8,192 versus E 2,136,859; unchanged SDK size
and static hardening checks pass. The original SDK package was downloaded
before timing and retained privately read-only: `dnsmasq-2.93-r4.apk`,
1,167,095 bytes, SHA256
`5bb29803bceaf70eecc9a88d582e67a4440c53aa8ec498d3990b06eab82fe032`.
It was not installed or sent to the router. Resource growth remains subject to
the existing full resource review; this report introduces no new numeric gate.

## Postflight and independent evidence

Author postflight verified all 110 archive SHA values, safe unique tar members,
all 3,430 retained raw-file hashes, both SDK ELF/map/build triples, 358 source
inputs, seven original tool sources and nine measurement inputs. No research
process remained; SDK/native/cargo locks were obtainable. The original analyzer
returned complete 110 / valid 110 with no parse failure. Only a 92,906-byte small
derived package was transferred while the independent router matrix continued;
complete raw archives/runs remain private on Oracle.

The coordinator then explicitly handed the quiet Oracle slot to loop for the
unchanged prepared auditor. Independent audit `12ebf728` passed all archives,
raw records and original 33 comparisons, with no errors, improvements or
regressions. Only after that audit could the separately authorized next profile
start. No bulk raw transfer or prospective diagnostic overlaps this matrix.

- Original summary SHA256: `df085ab812892231f409920ddf9b54c0f3c31a49593825432edb0d428b888296`.
- Author postflight SHA256: `08e151a82d4176c4e7e2bbaf607ea286d4cb615e54aa208eff287f957a7cff58`.
- Independent audit SHA256: `fc72a89a96212b68d7ae7c4c9c8a5a22864b3a2b5daa15e15fb5d86da234c0b3`.

[The complete derived result](cached-zero-frame-oracle-full-result.json) preserves
the original summary fields unchanged plus evidence bindings and independently
rederived resources. [The independent audit](../loop/cached-zero-frame-oracle-independent.json)
retains all raw/statistical checks. The physical-router matrix remains separate;
this Oracle result alone neither demonstrates its CPU target nor promotes or
deploys the candidate.
