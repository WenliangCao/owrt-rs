# Original OpenWrt vs latest Rust

This benchmark compares implementations, never two Rust revisions. Both sides
must use the same OpenWrt image, configuration, kernel, drivers and execution
plane. No generated binaries, images, private configuration or raw device logs
belong in Git.

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
| reload-config | Unchanged configuration walk with original uci |
| httpd | 16 KiB static file, CGI, authenticated JSON-RPC |

## Whole-system comparisons

Physical cold switching uses `tools/r84_stack_switch.sh` and the detached Mac
`tools/r84_window.py`. The latter checks the actual LAN interface, cable, all
nine identities, DHCP (or explicitly selected static addressing), DNS, IPv4/IPv6
HTTPS, both AP bridges and the watchdog. It requires 180 seconds of continuous
health and a final observation before confirming Rust. An unconfirmed Rust boot
restores all nine originals at 900 seconds; **a failure before the canary starts
still requires physical failsafe recovery**.

Prepare the release bundle and its checksum manifests, verify offline backups,
and verify the human recovery conditions before any device mutation. Install
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
# Repeat separately with --fresh-connection, and record server CPU snapshots
# around the client process. Also record negotiated TLS version/cipher.
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

Five rounds include serial HTTP/ubus/one-shot requests and a four-client mixed
workload spanning procd, netifd, rpcd, ubusd and HTTP. The mixed workload has one
outer CPU interval; **do not sum the overlapping per-client CPU intervals**.
Idle resource snapshots are taken for 120 seconds before and after load. Record
client-visible recovery time and kernel boot events for every cold boot.

## Interpretation

- Every timed operation must succeed; CLI output is byte-checked, RPC replies
  have status/body checks, and a lost/replaced daemon invalidates the run. The
  native client reuses its ubus connection and resolves objects before timing.
- Latencies cover the actual request/response or command execution. Validation
  is outside each latency interval; overall throughput includes validation.
  Warm-up is excluded. Keep raw nanosecond samples and summarize per-run means,
  p50/p95/p99, throughput, and dispersion across runs/boots.
- Daemon CPU is the process's own counter delta. One-shot CPU includes waited
  child processes. Linux `AT_CLKTCK` supplies the counter resolution; values
  below one tick are not evidence of zero CPU cost. Include client CPU so a
  client bottleneck is visible.
- This router does not expose `smaps`/`smaps_rollup`. Report `VmRSS`, `RssAnon`,
  `RssFile`, descriptors and threads, plus system `MemAvailable`; do not label
  them PSS or USS. Summed RSS double-counts shared mappings. One-shot peak RSS
  is not measured by this harness.
- CLI/daemon ELF sizes do not include the original system's shared libraries,
  ucode interpreter, templates or plugins. Inventory those separately. Since
  originals remain available for recovery, added deployment storage differs
  from the size of a hypothetical firmware that removes originals.
- Kernel forwarding and hardware offload remain unchanged. These measurements
  quantify control-plane overhead and end-to-end management requests; they do
  not establish a routing-throughput speedup.
