# Original OpenWrt vs latest Rust

The primary comparison is original OpenWrt versus current Rust. Optimization
trials may additionally retain a frozen Rust baseline to explain each change.
Both sides must use the same OpenWrt image, configuration, kernel, drivers and
execution plane. No generated binaries, images, private configuration or raw
device logs belong in Git.

## Build and validate

Build on Linux with the pinned Rust toolchain and the image's OpenWrt SDK:

```sh
make check-benchmark
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$STAGING_DIR/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
cargo build --locked --release --manifest-path tools/benchmark/Cargo.toml --target aarch64-unknown-linux-musl
"$CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER" -Os -static -Wall -Wextra -Werror \
  tools/benchmark/ns_exec.c -o /path/to/bundle/ns-exec
cp tools/benchmark/target/aarch64-unknown-linux-musl/release/owrt-benchmark /path/to/bundle/
sudo python3 tools/benchmark/selftest.py /path/to/bundle
```

The bundle also needs the nine exact binaries being deployed: `uci-rs`,
`reload_config_rs`, `fw4-rs`, `logd-rs`, `httpd-rs`, `rpcd-rs`, `procd-rs`,
`ubusd-rs` and `netifd-rs`. Use the canonical APK binaries for the packaged six;
record the exact source/build provenance of the other three.

## Component comparisons

```sh
sudo sh tools/benchmark/isolated.sh ROOTFS BUNDLE ubusd c  PRIVATE_OUT/c  10000
sudo sh tools/benchmark/isolated.sh ROOTFS BUNDLE ubusd rs PRIVATE_OUT/rs 10000
```

`ROOTFS` is the pristine extracted image on the build host, or `/rom` on the
router. Physical execution needs the project's recovery gate. Build-host runs
validate the harness; they are not router performance results. Every run records
its actual kernel, CPU information, boot identity and executable hashes.

Run all nine component names with fresh output directories. Use four runs per
implementation in the order **C, Rust, Rust, C, Rust, C, C, Rust**. Copy each
completed router run to private local storage before deleting that run's exact
temporary directory, to avoid accumulating raw samples in router RAM.
`run_components.py PRIVATE_OUT --interface enX --host-mode rust` automates
this sequence, verifies component hashes, and checks that the host boot,
configuration and running processes remain unchanged. Run it after the
whole-system windows; concurrent benchmark loads would invalidate comparisons.
`--components logd` selects one component with the same eight-run sequence in
a new output directory. Preserve excluded attempts and the replacement's host
verification before incorporating a corrected run into the final dataset.

Every run has its own mount, PID and network namespace. The image mount is read
only; config/runtime state is on private tmpfs; `/proc/kmsg` is masked; no
watchdog device is exposed. A small PID 1 wrapper destroys all descendants even
if the launcher dies, including children that call `setsid()`. Host processes
are never killed by a name pattern. The tested procd runs in supervisor mode as
a non-PID-1 process; actual PID 1 is measured in the whole-system comparison.

Only the named component changes. Dependencies, including ubusd, uci and rpcd,
remain original unless they are themselves the subject. The synthetic network
has loopback, one empty bridge and a static dual-stack LAN; wireless is disabled.
UCI write tests have separate config and delta directories. Reload tests verify
their generated MD5 baseline against the original before timing no-ops. Firewall
generation/checks operate only inside the isolated network namespace.

| Component | Workloads |
|---|---|
| ubusd | Persistent-client lookup, lookup of 64 objects, successful invoke |
| rpcd | UCI config listing/get, file stat, session access |
| procd | List 32 services, system info |
| netifd | Interface dump, bridge and LAN status, empty wireless status |
| logd | 128-byte-class syslog datagrams with final-delivery check; 100-line reads |
| uci | Network/64-section export; scratch set + commit + verified get |
| fw4 | Byte-validated print; kernel nft check |
| reload-config | Prepared first/unchanged/single/multi/comment-only configuration and event validation |
| httpd | 16 KiB static file, CGI, authenticated JSON-RPC |

R85 HTTPD optimization uses `run_httpd.py CANDIDATE PRIVATE_OUT --interface enX`:
the original image, frozen R84 binary and candidate are measured in a balanced
12-run sequence (four per side). `--repeats 2` is an exploratory six-run trial.
The recovery/health gate runs before uploading into a new temporary directory;
the production binaries/configuration remain active and are checked afterwards.
Explicitly authorized Wi-Fi management uses `--access wifi --interface enX`;
it still verifies the active stack, configuration, namespace launcher and host
health. Workload traffic stays on isolated loopback, and results are downloaded
after each measurement. Wi-Fi is also authorized for deployment and cold stack
switching; offline backups, identities, rollback and client health remain required.
`--sides stock candidate` compares only the original and the candidate. Preserve
failed frozen-R84 trials separately; they cannot become successful baselines by
dropping failed clients or averaging only their successful requests.
`--matrix` adds 512-byte, 16-KiB `.dat`/`.css`, image CSS, 64-KiB and 1-MiB files
at one and four clients, plus four-client CGI and JSON-RPC. The original native
client binary stays unchanged. Four-client results retain all latency samples
and one outer CPU interval, including the separately recorded 20 warm-ups per
client; divide that CPU by measured plus warm-up operations. Outer throughput
includes warm-up/startup and has `/proc/uptime` clock resolution. Never sum the
overlapping daemon CPU intervals inside individual client files. The matrix's
16-KiB `.dat` c1 file aliases the existing static measurement, not another run.

`run_candidate.py --component procd --matrix` retains list32 and system.info,
adds four-client versions, then lists 128 services and queries one service by
name at one and four clients. The generated 32/128-service expectations are
checksummed across subjects; every service's data is validated. The base modes
and frozen client binary remain available for the original R84 workloads.

`run_candidate.py --component netifd --matrix` retains the four base queries,
adds four-client versions and all-device status, then creates 30 additional
static interfaces on the isolated bridge and measures the 32-interface dump
and one named interface at one and four clients. Every interface's protocol,
UP state and IPv4 address is checked by the frozen client. Separate checks
before and after each phase require the exact ordered interface and ubus
object sets; fixture hashes must agree across subjects. Wireless remains the
empty configuration, so its timing does not claim radio lifecycle coverage.
Each phase waits for all expected `ifup` callbacks, no remaining child process,
and stable reaped-child CPU counters before measuring. Every read workload
must retain zero child CPU growth. The exact router kernel lacks the proc
`task/PID/children` interface. R86 checks each process status file's `PPid`
instead, rejecting live or zombie children and read failures. Each phase records
that evidence; the analyzer excludes older matrices without it from final
acceptance. Early N00/N01 lacked the earlier callback/CPU gate too. The old N05
and first R86 matrix are retained as diagnostics; R86 repeats all fourteen
workloads with the complete gate and unchanged component binaries.

`run_candidate.py --component ubusd --matrix` retains exact lookup, lookup of
64 objects and invoke, adds four-client versions, then prefix lookup of 64
objects and lookup of 128 objects at one and four clients. Each provider phase
checks the complete ordered object path set before and after measurement.
The frozen timing client still checks only that bench.target exists on each
lookup; complete signatures, ACLs, descriptors and queue boundaries are checked
separately by the functional gates. Four-client CPU uses one outer interval.

`components/httpd/examples/profile.rs` directly profiles parser/file-handler
stages, with allocation counters disabled for timing. Its `_reused` cases keep
the output allocation across requests; the other cases include a new output
allocation per request. `trace_httpd.py --clients 4` counts syscalls under
concurrency on the Linux build host; `--bytes` changes the static fixture size.
Neither instrumented timing is an end-to-end router performance result.

The CGI connection regression has a separate long-running mode, using the
same namespace, configuration and frozen client. N is **per client** here:

```sh
sudo env OWRT_HTTPD_CGI_STRESS=1 sh tools/benchmark/isolated.sh \
  ROOTFS BUNDLE httpd rs PRIVATE_NEW_OUT 30000
```

It requires four clients × 30,000 validated requests plus 20 warm-ups each.
One failed client invalidates the run. Preserve failed R84 attempts and check
the subject/client hashes and `COMPLETE` marker before accepting a fix.
Do not combine this mode with `OWRT_HTTPD_MATRIX=1` or substitute it for the
16-workload performance matrix.

For held-connection memory, build the current client as a **separate diagnostic
binary** named `memory-probe`; keep the frozen R84 timing binary in place:

```sh
python3 tools/benchmark/run_httpd.py CANDIDATE NEW_PRIVATE_OUT \
  --interface enX --access wifi --sides stock candidate --memory-probe MEMORY_PROBE
python3 tools/benchmark/analyze_httpd_memory.py NEW_PRIVATE_OUT --output DERIVED.json
```

Each fresh daemon serves two byte-validated 16-KiB responses to each of 64 held
connections. The client verifies the actual open fd count and process identity,
then requires fd/thread counts to return to baseline after closing. Four runs
per side are the default. This measures `/proc/status` RSS and anonymous RSS;
it does not claim PSS/USS, peak global RAM, or a latency result. The normal host
health/configuration gates still apply. On the build host the corresponding
isolated mode is `OWRT_HTTPD_MEMORY=1`, with `memory-probe` in BUNDLE.

## Whole-system comparisons

Physical cold switching uses `tools/r84_stack_switch.sh` and the detached Mac
`tools/r84_window.py`. The latter checks the selected client interface, all
nine identities, DHCP (or explicitly selected static addressing), DNS, IPv4/IPv6
HTTPS, both AP bridges and the watchdog. It requires 180 seconds of continuous
health and a final observation before confirming Rust. An unconfirmed Rust boot
restores all nine originals at 900 seconds; **a failure before the canary starts
still requires physical failsafe recovery**.

Prepare the release bundle and its checksum manifests, verify offline backups,
and confirm that the recovery procedure is available. A LAN cable is not a
deployment prerequisite under the current user authorization. Install
the APKs with `--no-scripts --no-network --allow-untrusted` only after verifying
the canonical artifact checksums. A controlled reboot activates the whole stack
together. Test installation, staging and rollback first with:

```sh
sudo sh tools/r84_switch_selftest.sh ROOTFS DEPLOYMENT_BUNDLE PRIVATE_OUT
```

Use four cold-boot windows: **Rust, stock, stock, Rust**, with identical settings
and workload counts in each. This validates the deployment first, supplies two
fresh original boots and two Rust boots, balances time order, and ends on Rust.
Warm/test HTTPS consistently before each live workload:

```sh
python3 tools/benchmark/http_client.py https://192.168.1.1/luci-static/bootstrap/cascade.css \
  --insecure --tls12 --expect-bytes PRIVATE_EXPECTED_CSS -n 1000 -c 4
# Repeat separately with --fresh-connection --rate 20. The existing firewall
# limits new TCP SYNs to 25/s (burst 50), including LAN input. Pacing is shared
# across clients and excluded from latency; its throughput is rate-limited.
# Record server CPU snapshots and the negotiated TLS version/cipher.
```

Then run on the router, collecting outputs privately:

```sh
sh /root/r84/tools/benchmark/live.sh rust  /tmp/r84-rust-1 10000 5 120
sh /root/r84/tools/benchmark/live.sh stock /tmp/r84-stock-1 10000 5 120
```

Run the commands in their corresponding verified boot, never both modes in one
boot. The script refuses incorrect running hashes and writes `COMPLETE` only
after all requests, configuration stability and final process identities pass.
Its temporary authenticated RPC session is explicitly destroyed at exit.
The session has both ubus `uci.get` permission and UCI `network.read` permission.

`run_window.py MODE PRIVATE_WINDOW --interface enX` collects the four TLS cases
and the live workload after `r84_window.py` has written `health.json`. TLS CPU
brackets include warm-up (counted separately) and SSH sampling overhead. It
downloads all live output, verifies every file checksum, and only then removes
its exact temporary router directory. A failed attempt must be preserved
separately before `--resume-live` may reuse successful TLS results in the same
boot; completed windows are never overwritten.
The two implementations may prefer different TLS 1.2 ciphers. The normal
four-window result preserves each implementation's negotiation. After the
primary workload has finished in `stock-2` and `rust-2`, the collector also
repeats the four TLS cases with `--cipher ECDHE-ECDSA-AES256-GCM-SHA384`.
This supplemental comparison has one boot per implementation and cannot
change the preceding idle/resource samples.

Five rounds include serial HTTP/ubus/one-shot requests and a four-client mixed
workload spanning procd, netifd, rpcd, ubusd and HTTP. The mixed workload has one
outer CPU interval; **do not sum the overlapping per-client CPU intervals**.
Idle resource snapshots are taken for 120 seconds before and after load. Record
client-visible recovery time and kernel boot events for every cold boot.

## Interpretation

For HTTPD RPC stage profiling on the Linux build host, build the HTTPD `profile`
example into the experimental bundle and run:

```sh
sudo env OWRT_HTTPD_RPC_PROFILE=1 sh tools/benchmark/isolated.sh \
  ROOTFS BUNDLE httpd rs NEW_PRIVATE_OUTPUT 20000
```

This measures request-body collection, JSON parsing, and the actual bridge with
the image's original ubusd/rpcd. A real authorized UCI result is checked before
measurement. Timing and allocation counting run separately; these stage timings
are diagnostic and cannot replace the frozen client's HTTP measurements. Run
paired repetitions without other load on the host. This mode is separate from
the full matrix and CGI stress, and uses the same physical-device recovery gate
if run on a router.

After the four windows and 72 component runs complete, derive allowlisted
results (raw bodies, configurations, identifiers and tokens remain private):

```sh
python3 tools/benchmark/analyze.py private/r84 \
  --manifest work/r84/deployment/manifest.json --output /path/to/report/results.json
# A separate plotting environment needs matplotlib; analysis itself uses stdlib.
python3 tools/benchmark/render.py /path/to/report/results.json /path/to/report
# On the Linux build host, inventory the exact extracted image with readelf:
python3 tools/benchmark/storage_inventory.py ROOTFS DEPLOYMENT_MANIFEST.json
```

The analyzer requires all completion markers, sample counts, matching binary
hashes, stable configuration/execution-plane hashes and final Rust health.
`--partial` supports private progress inspection; the renderer rejects it.

R86 extends the isolated matrix to 74 workloads and uses the fixed candidate
collector order **stock, candidate, candidate, stock, stock, candidate,
candidate, stock**. Its four whole-system windows keep the preceding protocol.
Derive the R86 component matrices, held-connection memory, system windows and
separate deployment attestation together with:

```sh
python3 tools/benchmark/analyze_r86.py private/r86 \
  --manifest work/r86/deployment-final2/manifest.json \
  --archive work/r86/deployment-final2.tar.gz \
  --output reports/ax3000t-stock-openwrt-25.12.5/R86_parts
python3 tools/benchmark/render.py \
  reports/ax3000t-stock-openwrt-25.12.5/R86_parts/results.json \
  reports/ax3000t-stock-openwrt-25.12.5/R86_parts/rendered
```

The R86 entry point binds both implementations and the measurement tools to
the prepared release, rechecks all four downloaded live archives, and requires
the deployment driver's final completion event. It preserves the hash-pinned
preparation manifest. Its attestation records the completed historical run;
the analysis itself does not query the device or establish current live health.

- Every timed operation must succeed; CLI output is byte-checked, RPC replies
  have status/body checks, and a lost/replaced daemon invalidates the run. The
  native client reuses its ubus connection and resolves objects before timing.
- The isolated logd sees an empty FIFO held open at both ends in place of the
  global kernel log. A `/dev/null` substitute is perpetually readable to
  `poll()` while the original's epoll rejects it, unfairly spinning only the
  Rust daemon. Three seconds of pre-load idle evidence must reject that
  condition. R84 preserves and excludes all eight original logd attempts;
  only that component is repeated with the FIFO. Other components do not read
  the masked kernel log in these workloads; whole-system windows use the real
  kernel log and are unaffected.
- Latencies cover the actual request/response or command execution. Validation
  is outside each latency interval; overall throughput includes validation.
  Warm-up is excluded. Keep raw nanosecond samples and summarize per-run means,
  p50/p95/p99, throughput, and dispersion across runs/boots.
- Daemon CPU is the process's own counter delta. One-shot CPU includes waited
  child processes. Linux `AT_CLKTCK` supplies the counter resolution; values
  below one tick are not evidence of zero CPU cost. Include client CPU so a
  client bottleneck is visible.
- The native HTTP client sends each request as one buffer and refreshes Linux
  `TCP_QUICKACK` after reads. The original uhttpd does not enable TCP_NODELAY;
  loopback's large MSS otherwise produces roughly 50 ms Nagle/delayed-ACK
  stalls absent from the measured real-LAN path. This is a per-client socket
  setting on both sides, not a router-wide TCP change. Preserve diagnostic
  runs separately and do not combine measurements from different client
  revisions. Each run records the benchmark executable's hash.
- This router does not expose `smaps`/`smaps_rollup`. Report `VmRSS`, `RssAnon`,
  `RssFile`, descriptors and threads, plus system `MemAvailable`; do not label
  them PSS or USS. Summed RSS double-counts shared mappings. One-shot peak RSS
  is not measured by this harness.
  Integrity checks read full executable files and the Rust reference bundle,
  warming more file cache than requests alone. Keep global `Cached`, `Mapped`,
  `AnonPages` and slab statistics alongside `MemAvailable`; do not interpret
  smaller summed RSS as equivalent whole-system physical-memory savings.
- CLI/daemon ELF sizes do not include the original system's shared libraries,
  ucode interpreter, templates or plugins. Inventory those separately. Since
  originals remain available for recovery, added deployment storage differs
  from the size of a hypothetical firmware that removes originals.
- Kernel forwarding and hardware offload remain unchanged. These measurements
  quantify control-plane overhead and end-to-end management requests; they do
  not establish a routing-throughput speedup.

R92 retains the frozen benchmark and explicitly selects the R89 bundle with
`run_candidate.py --baseline-bundle /root/r89-before-r90 --baseline-label r89`.
`--cpus 0` applies the same affinity to each isolated subject and its clients;
these follow-up runs are kept separate from the normal two-CPU matrix.

Additional historical ELF files can join the same complete random blocks with
`--extra-baseline r94=PATH --extra-baseline-evidence r94=PROVENANCE.json`.
The provenance JSON must contain the ELF's `subject_sha256`; describe missing
source/build records honestly instead of inventing a canonical manifest.
This requires `--bench`, `--guard`, `--schedule random-blocks` and a fixed
`--seed`. With one extra baseline, `--repeats 3` means twelve windows, one of
each side per block. Uploads use separate temporary bundles; historical
bundles and production processes remain untouched. Resume verifies the same
ELF, provenance, tools and settings. Analysis rejects missing/duplicate sides
or changed dependencies and retains each historical comparison.

Procd accepts `--procd-workloads` and `--procd-warmup` with `--matrix`.
The eight existing query lanes remain the default. Explicitly include
`service_list_instance_fields` for a full verbose query over 32 fielded
declarations plus a service with running, exited and declared instances.
Fixture updates, readiness polling and deletion occur outside query timing.
The fixed harness determines lane order; the subset argument selects coverage.
CPU clocks cover the subject, exact C ubusd and native callers; an unmonitored
live service child is missing data, not zero CPU. Keep the separate lifecycle,
notification and recovery probes as correctness gates.

HTTP diagnostics use a separately built `http-diagnostics` executable from
this directory. It must never replace the frozen `owrt-benchmark`. In an
isolated run, `OWRT_HTTPD_DIAG=paced` selects four persistent clients;
`OWRT_HTTPD_DIAG_GAP_MS` selects the inter-request delay. Linux build hosts can
also set `OWRT_HTTPD_NETEM_MS` to apply a real one-way delay on the private
namespace's loopback only. Request gaps on the router do not measure RTT.
`OWRT_HTTPD_DIAG=memory OWRT_HTTPD_DIAG_ROUNDS=40` repeatedly holds and closes
64 clients and requires descriptors and threads to return each time.

`OWRT_BENCH_TRACE=1` attaches a separately identified static `strace` to ubusd,
procd or httpd; traced results are diagnostic only. `analyze_candidate.py`
rejects them. `analyze_diagnostics.py` verifies the raw HTTP series and exports
latency/CPU for untraced diagnostics, clone counts for traced diagnostics, and
RSS drift after repeated closes. Sampled thread births are lower bounds.

`file_residency.c` uses `mmap(PROT_NONE)` and `mincore`; `file_pages.sh` records
active executable, mapping and retained-bundle pages after the usual identity
gate, without faulting file contents or dropping caches. Deduplicate by
device/inode within groups and retain the limitation that overlay aliases may
share physical pages. The result is neither exclusive RSS nor removable RAM.

## UCI independent process matrix

`run_candidate.py --component uci --matrix` keeps `export_network`,
`export_64`, `set_commit_get` and adds `get_network`, `export_multi` (four
64-section packages), `show_long` (64 sections with 125-byte strings and
8 × 128-byte list values), `delta_64` (32 deltas), and `batch_read16`.
The actual command count is `--iterations / 20`, with five warm-ups.
Every timed execution validates exit, stdout bytes and empty stderr through
`exec-strict`. Each namespace starts with fresh private tmpfs files. Commit
performs a real change each iteration; a separate post-run exact-C byte/mode
and empty-delta check verifies persistence. It is not a flash/fsync benchmark.

Use the existing `random-blocks` schedule and original ELF provenance for
four-side comparisons. `--exec-resource-probe <SDK-built exec_resource.c>`
adds three separate `wait4` samples per lane, outside timing. The helper's
`maxrss_kib` is the peak of the command or a reaped descendant, not concurrent
sum RSS; `set_commit_get` includes its shell and three UCI processes. Resource
samples write stdout to a private file, whereas timed runs capture a pipe.
Both include exec-to-exit; resource samples also include the small launcher
fork-to-exec interval. Rust allocation instrumentation is separately available
in `profile_uci_allocations.py`; requested live bytes are not RSS.

The analyzer exposes `command_tree_cpu_us_per_op` from the benchmark's
`getrusage(RUSAGE_CHILDREN)` snapshots. It excludes warm-up and caller CPU,
includes descendants reaped by the command, and retains legacy tick fields
separately. Microsecond encoding is not a claim of microsecond accuracy.
A short-lived acceptance result requires both this field and the caller CPU
clock; an empty after-exit resident list cannot establish zero memory.


## Reload-config prepared process matrix

`run_candidate.py --component reload-config --matrix --reload-packages 24`
runs `first_baseline`, `unchanged_config`, `single_change`, `multi_change`,
and `comment_only`. Select screening lanes with `--reload-workloads` and
warm-up count with `--reload-warmup` (default 5). Measured invocations per lane
remain `max(--iterations / 20, 1)`. Package counts 4, 24, 64 and 128 support
bounded scale screening; the default 4 reproduces the small common corpus.
Use the existing four-side random-block schedule and provenance flags.

Every invocation restores fixed config bytes and the independent exact-image
old baseline outside timing. First baseline always starts absent. Single
change modifies `network`; multi change modifies `firewall`, `network`, and
`r84fixture`, in old-baseline order. Comment-only adds whitespace/comments
while preserving the entire normalized baseline. Reference baselines are
created by the exact-image script, UCI and BusyBox before collection, with no
existing baseline and hence no reference events. Each timed exec must exit
successfully with empty stdout/stderr, match every baseline byte and match
all framed raw package bytes, order, multiplicity and receiver status. An
untimed repeat must preserve the complete baseline and emit no events. All
invocations, including warm-ups and diagnostics, retain these artifacts and
a started/completed journal; failed windows remain failures.

The namespace always uses the exact C ubusd, a trigger-free `service.event`
receiver, and a private exact-image logd at `/dev/log`. Receiving the event
means successful service acceptance, not completion of any downstream reload.
No production socket, configuration, saved delta or override directory is
used. The current Rust implementation normalizes UCI and hashes in-process;
older sides may spawn UCI, md5sum and ubus, and those children are included.

`reload-exec` sums per-invocation `getrusage(RUSAGE_CHILDREN)` deltas across
only the measured exec-to-exit windows, including baseline commit and reply
completion. Caller, ubusd, receiver and logd CPU clocks are listed separately.
Reset, complete checking, repeat and resource runs are excluded from latency,
throughput and command CPU. `prepare_us_per_op`, `validation_us_per_op` and
`envelope_s` expose those excluded costs. Throughput is successful operations
divided by the sum of their exec durations; it excludes reset/check wall time.
Raw before/after counters remain available for each measured operation. These
are microsecond exports, not a microsecond accuracy claim. Dependency clocks
cover the immediate exec interval; asynchronous trailing syslog work may run
later. Separate dependency envelope clocks include all warm-up/reset/repeat
and diagnostic work, and must not be used as per-operation runtime CPU.

`--exec-resource-probe` adds three separate wait4 lifecycle samples per lane.
`--exec-task-probe` adds one separately traced task-lifecycle sample per lane
using `exec_task_counts.c`. Both reset and validate the same workload. The
ptrace sample reports process/task births and complete reaping; its latency,
CPU and memory must never be treated as normal performance. wait4 maxrss is
a peak among the command/reaped descendants, not their concurrent RSS sum.
The receiver and logd remain available for separate resident observations.
Config baselines live in private tmpfs; sync and atomic rename remain active,
so these measurements do not estimate flash persistence latency.
