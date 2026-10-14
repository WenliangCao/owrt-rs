# Oracle supplementary measurements — frozen before the first pair

This is an Oracle-only comparison after the router safety gate ended the device
pilot. It cannot establish AX3000T performance or explain the device's high host
CPU observations. No product code, physical router, package or configuration is
changed. All pairs execute serially in one fresh loopback-only network namespace.

Exact image C ELF: `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
Final SDK Rust ELF: `50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c`.
C uses its image musl loader and four image libraries, copied to the private
input directory and verified against the existing image manifest. C `/proc/PID/exe`
therefore identifies `libc.so`, not dnsmasq; `/proc/PID/maps`, command line and
mapped file hashes must prove the C ELF and dependencies. Both versions use the
same shell-wrapper-to-exec launch layer. Rust is the unchanged static SDK binary.

The already calibrated static measurement tools remain unchanged. The runner
records configuration, binary/tool/library hashes and hardware/kernel details.
All files are on a new private tmpfs mounted at a new `/tmp` path; it is never a
product or Cargo target directory. Lifecycle inputs require `/tmp` realpaths.

Five pairs for every scenario, ordered C/R, R/C, C/R, R/C, C/R. No simultaneous
benchmarks, saturation, compilation, tracing or packet capture during windows.

| Scenario | Fixed input |
|---|---|
| UDP hit / miss / mixed | 200 queries/s, 32 clients, 800 names, cache 1000, A/AAAA 70/30; mixed 80% repeated and 20% unique |
| TCP hit / miss | 200 queries/s, 8 clients, 100 answers per physical connection |
| DNS upstream | Loopback UDP/TCP, fixed 1 ms nonblocking delay, positive TTL 120 s |
| DHCP | 100 transactions/s, 150 synthetic clients, 12 h leases; initial DORA during warmup, measured REQUEST/ACK only |
| Startup / config restart / HUP | 8 synthetic hosts including the EOF marker, 6 retained leases |
| Larger HUP | 1000 hosts including the EOF marker, 150 retained leases |

DNS and DHCP: 5 s warmup, **10 s measured** (device protocol was 20 s). Hit and
mixed cases first use a separate 5 s UDP parent-cache prewarm. This prevents C's
TCP child-only cache from being mistaken for parent-cache warming. Upstream
phase counts determine actual hit/miss fractions. Lifecycle: **10 repetitions**
per round, at least 1 s per repetition (device proposal was 20). These shorter
supplementary windows reduce Oracle work; they do not amend device results.

The raw latency, scheduling lag, semantic checks, scheduled/sent/completed/error
counts, socket counts, resource samples and child exit statuses are preserved.
A failed window stays failed; subsequent pairs do not erase it. Every successful
measured packet must be semantically valid. No skipped sends, wrong replies,
timeouts, transport errors or upstream queue drops are allowed in a valid window.

CPU fields are reported with explicit scope: service `/proc` tick delta over the
warmup+measurement window, after TCP children have reaped, divided by warmup plus
measured completions; helper `wait4` usage is separate. Full-service `wait4` CPU
also includes setup/prewarm/shutdown and must not be substituted for that window.
Less than 10 service ticks is too coarse for CPU ranking. RSS, anonymous RSS,
PSS/private mappings when available, and FD peaks are separate; tree RSS is not
private memory. Per-round p50/p95 and ranges are reported; p99 requires at least
10000 successful observations per round, which these low-rate windows lack.
