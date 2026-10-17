# Core supplementary gates: local inventory, 2026-10-17

Preparation only. No Oracle/router access or build was performed. Do not execute
the old r95_device_smoke.py (stock-only production, /rom and /root/r84) or the
hardcoded tools/r134/ubusd_gates.sh. No new runner is needed: reuse each original
--namespace entry with the current stock root, current ns-exec and a new output.

Required layout (all paths absolute on the Linux test host):

    TOOLS/isolated.sh                  current tools/benchmark/isolated.sh
    TOOLS/r98_ubusd_events.sh          unchanged current source
    TOOLS/ubusd_fd_boundary.sh        tools/r134/ubusd_fd_boundary.sh
    TOOLS/r131_ubusd_event_stress.sh   unchanged current source
    TOOLS/r95_reload_config_probe.sh  unchanged current source

Wire bundle:
    ns-exec                          reuse Oracle-prepared launcher
    owrt-benchmark                    reuse Oracle EXAMPLES/wireprobe
    ubusd-rs                         exact integrated candidate (or v021 in separate run)
    before-rs                        reconstructed R131 control, NEVER v021 read-ahead

Stress bundle:
    ns-exec                          reuse Oracle-prepared launcher
    owrt-benchmark                    reuse ordinary benchmark, requires exec-cpu-as
    ubusd-rs                         exact integrated candidate (or v021 in separate run)
    event-benchmark                   r131-event-stress-libubus dynamic helper
    # No wireprobe under owrt-benchmark in this bundle.

Reload bundle:
    ns-exec                          reuse Oracle-prepared launcher
    owrt-benchmark                    ordinary benchmark
    reload_config_rs                 exact integrated candidate (or v021)
    event-benchmark                   same prepared benchmark, reload-fault-service mode
    guard                            SDK-built tools/testsrc/r95_guard.c
    # before-rs is OPTIONAL historical expected-failure control, not v021.
    # The current mandatory R95 corpus runs without it.

The stock rootfs supplies the real C /sbin/ubusd, /bin/ubus, /sbin/uci,
BusyBox flock, and matching dynamic libraries. No host-native library substitution.

Original entry shape; OUT and WORK must be separately created fresh empty dirs:

    sudo -n GUARD 120 BUNDLE/ns-exec /bin/sh TOOLS/SCRIPT \
      --namespace STOCK_ROOTFS BUNDLE COMPONENT IMPL OUT N WORK TOOLS/SCRIPT

SCRIPT must be next to isolated.sh: it forwards --namespace to that sibling,
which mounts readonly stock/bundle, private etc/dev/tmp and then runs the script
as /tmp/workload.sh. Calling a custom script like isolated.sh's ordinary public
ROOTFS/BUNDLE form is incorrect: the custom scripts only accept --namespace
or the internal --workload entry.

Fixed gate selections:
- R98: SCRIPT=r98_ubusd_events.sh COMPONENT=ubusd IMPL=rs N=1.
  Internally C / before-rs / candidate; seven transcripts: object_events, events,
  monitor, release, utf8, monitor_lookup, method_acl. All three byte-equal.
- R134 FD: SCRIPT=ubusd_fd_boundary.sh COMPONENT=ubusd IMPL=rs N=1.
  C and R131 use fd_boundary; current read-ahead candidate uses
  fd_boundary_read_ahead. Three sender-framed cases must equal C; three handcrafted
  cases must satisfy the explicit read-ahead contract. All six require single
  delivery/witnesses, empty registry and FD return to baseline.
- R131 stress: SCRIPT=r131_ubusd_event_stress.sh COMPONENT=ubusd IMPL=c or rs N=2000.
  Each script starts four fresh daemons. grouped/interleaved/monitor have
  2000+20 events; slow has exactly192 (no warmup), 2048B payload,8 handlers.
  Caller CPU0, daemon CPU1, argv0=/sbin/ubusd. Requires both CPUs available.
  Byte/target/per-owner order/sequence checks, monitor delivery, strict nonzero
  bounded drop subset, one complete8-frame recovery event, removed handlers and
  FD baseline. No exact cross-implementation dropped-frame-count equality.
  The old R134 Oracle-only correctness preview uses100 normals/192slow; that is
  distinct from the original2000-event workload and must not be silently relabelled.
- R95 reload: SCRIPT=r95_reload_config_probe.sh COMPONENT=reload-config IMPL=rs N=1.
  N is unused by its correctness script.10 mandatory cases:
  config/delta/override timeout+cancel (6), remote6/7 statuses, dropped reply timeout,
  delivery cancellation, run-lock cancellation. Each retains full MD5 baseline,
  ordered alpha/beta event/raw bytes, recovery and silent repeat.
  Inner guards are1s optional old negative /3s bounded candidate operations;
  local request deadlines100/1000/10000ms are unchanged.
  Optional before-rs reproduces the old config-lock hang and MUST exit124;
  do not insert current v021 into that failing-version slot.

Controls/helper recovery:
- R131 runtime source: 4e45d2ecc41d8548916c2f92f30c7ac4d2bb65dc.
  Durable tag archive/ubusd/r131-event-batch ->18df115deac2e6b6e70155589e0baf35d8d45309.
  The latter adds120 test-only lines to client.rs; prefer exact4e45 runtime input.
  Required old source parts: components/ubusd + components/ubus, their Cargo files,
  rust-toolchain.toml, pinned packaging/openwrt/owrt-ubusd/Makefile.
  Historical ELF c5bcf6e7c6f2ed565140e183ba3aa97c1ef60274bbde8398771ac13680da839a.
  Source is recoverable; old ELF is absent locally. A rebuild is a new artifact
  until its actual hash matches the historical ELF. Do not assume a new path or
  current shared-platform recipe reproduces its old bytes.
  The pinned recipe uses /tmp/owrt-build/owrt-ubusd, Rust1.98.1, aarch64-musl,
  opt3/fatLTO/CGU1/panic=abort, bfd/4096/now/relro/pack-relative-relocs.
  tools/r134/build.sh is a retained build template, but its /tmp/owrt-build/r134
  path is different; it is NOT proof of historical byte reproduction.
  Reconstructed control must remain distinct from v021 and must pass the original
  C-exact six-FD transcript before it is admitted as before-rs.
- R131 stress helper source unchanged:
  tools/benchmark/r131_event_stress_libubus.c
  SHA d2a1e7a37ef4cc901537b75b35deb602a3d7ae8c25d8af86ca68b9e37ee58c64.
  Exact builder:
      sh tools/benchmark/build-r131-event-stress-libubus.sh \
        SDK MATCHED_COMPONENT_SOURCES NEW_HELPER_OUT
  MATCHED_COMPONENT_SOURCES contains exact ubus24864e78 and libubox source dirs.
  Builder calls build-register-libubus.sh to make imports/link-only; these rebuilt
  .so files are LINK INPUTS ONLY. At runtime use original stock image libraries.
  Result NEW_HELPER_OUT/r131-event-stress-libubus; historical SHA
  1705d989c64640353e556d0cc307899504b08e7b8ccbbcc8963f6821680b3499.
  Bind actual source/compiler/binary hashes and verify unchanged expected output.
- Lifetime guard if not already available:
      "$SDK/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc" \
        -Os -static -Wall -Wextra -Werror tools/testsrc/r95_guard.c -o NEW_OUT/guard
  Historical SHA58b96cc6307dc7d3810003fcc557f361901630227ae32100575b0da342a65d6d
  is a comparison identity, not a claim this unexecuted command reproduced it.
  This accepts SECONDS COMMAND and is distinct from the DNS production-health guard.
- wireprobe already in Oracle's11 examples: ensure it exposes both fd_boundary and
  fd_boundary_read_ahead. Current source has both; do not rebuild an extra copy.
- Ordinary benchmark already prepared: source includes exec-cpu-as and
  reload-fault-service; reuse its exact artifact for stress and reload roles.

Retained receipts (Git, available):
    docs/reviews/r131-correctness-supplement.json
    docs/reviews/r131-router-correctness-plan.json
    docs/reviews/r131-stress-plan.json
    docs/reviews/R131_EVENT_STRESS_HELPER.md
    docs/reviews/reload-config-20260928-functional-validation.json
    docs/reviews/r142-correctness-results.json  (later R131 FD control reuse)
    manifests/ax3000t-stock-openwrt-25.12.5/source-baseline.json

Locally checked absent in BOTH core and main worktrees:
    private/r131-event-batch/maps/r131
    private/r131-event-batch/correctness/correctness-01
    private/r131-completion/stress/r131-event-stress-libubus
    private/r113-fd-boundary/wireprobe
    private/r95/guard
    private/r134
Remote availability was NOT checked. Archive pointers are history, not live files.

Preparation still needed before scheduling these extras:
1. R131 exact-source C-exact control and its actual identity/qualification.
2. Stress helper + exact stock runtime libraries/headers,2-CPU affinity availability.
3. r95 lifetimeguard (reuse if the device preparation owner already built it).
4. Per-gate bundles and copied sibling scripts, unique OUT/WORK and hashes.
Reuse ns-exec/benchmark/wireprobe/r36 already prepared by Oracle; no R92 rerun or
new test framework implied. R75_FAKE_WATCHDOG preparation remains parent-owned.
