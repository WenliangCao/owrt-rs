# FIX3 performance and resource evidence

This directory contains audit-only drivers and derived results. Product source was not modified. Raw process snapshots, per-request timings, exact-image overlays and test files remain on Oracle under `/home/ubuntu/dnsmasq-audit-fix3-20261013/private/`.

## Artifact binding

- main release SHA256: `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`
- fix release SHA256: `524c327f79080c789f7cdce74125c2af52f6e9c97175414a874ac6e31c9f9c2a`
- exact-image C SHA256: `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`
- source main: `be531cee49e366bb5044443d473944dbea45b87e`
- source fix: `e3a37f55b2939ee2a0c229b0ac96a2a9c407b8aa`
- native load generator SHA256: `959fcdbf1fb2cd9ac682ed51ef35ba1811f4f744d743c09fa71a8f598460c8f1`
- native upstream SHA256: `ee5259b721a7f0f45acd769b791b5c004620f14c0af2fc067f8548bd7878da35`

Build receipts and source bindings are retained by the build audit. DNS measurement plans include build receipts, executable hashes, helper hashes, complete commands and execution order. Native load generator, upstream, daemon and controller use separate Oracle CPUs (2, 1, 0, 3 respectively). Timing starts after all other agents' builds and functional workloads stop. Each DNS window uses a fresh network/PID/mount namespace and an overlay of the exact OpenWrt root filesystem.

## Reproduce

Copy the Python files in this directory to `$R/performance`, where `R=/home/ubuntu/dnsmasq-audit-fix3-20261013`. The source trees are `source-main` and `source-fix`, and fresh release binaries are `private/release-main/dnsmasq-rs` and `private/release-fix/dnsmasq-rs`. Drivers intentionally reject existing output directories and do not retry failed windows; use a fresh isolated audit root if reproducing.

```sh
python3 "$R/performance/paired_dns.py" prepare
sudo -n python3 "$R/performance/paired_dns.py" run
python3 "$R/performance/paired_raw_records.py" prepare
sudo -n python3 "$R/performance/paired_raw_records.py" run
python3 "$R/performance/confirm_raw_records.py" prepare
sudo -n python3 "$R/performance/confirm_raw_records.py" run
python3 "$R/performance/verify_counters.py"
sudo -n sh "$R/source-fix/tools/dnsmasq/run_isolated.sh" \
  python3 "$R/performance/hosts_memory.py"
```

The hard-coded root is deliberate provenance, and must be changed in all affected drivers before preparing a repeat in a fresh isolated directory. Do not remove or overwrite this audit's output to reuse its names. The CNAME wrapper only changes synthetic workload selection: 2048 distinct cached CNAME owners point to one shared cached A terminal, within 4096 cache slots. Every bank owner is checked before load with upstream responses disabled; the upstream process remains running and counts attempted requests. The dns-rr wrapper adds valid, unrelated custom records and otherwise keeps the stock M6a workload unchanged.

The native TCP load generator reconnects after every 100 queries. CPU therefore includes normal connection creation and teardown, not only lookup instructions. Compare main and fix within the same profile and rate; do not subtract the ordinary 3000 QPS TCP profile from the 1000 QPS raw-record profile. The initial 10%/relative-range/all-pairs screen is an audit heuristic, not a user-approved tolerance and not proof that smaller costs are absent.

The first long-lived SSH connection was reset by the network while the Oracle controller was still running. Its shell, controller and active window remained alive; the redirected Oracle log continued without interruption. No window was restarted. `dns-run.json` records all 36 windows exiting 0 and the completed controller. Later driver connections used SSH keepalive. The SSH transport exit 255 is not a daemon or benchmark-window exit.

## Memory result

`hosts-memory.json` reproduces one valid host plus 48 MiB of ordinary short comments. Main startup peak RSS was 50,476 KiB; fix was 1,968 KiB and exact-image C was 1,128 KiB. With a 32 MiB address-space limit, main stayed alive but lost the valid A record both at startup and following SIGHUP (REFUSED instead of the A answer); fix and C retained correct answers in both cases. This confirms the whole-file-read repair. These are per-process memory measurements, not CPU timing claims; the memory experiment was allowed to overlap builds.

## Limits

These are Oracle aarch64 scoped screens, not physical-router throughput, saturation or long-duration leak qualification. Root filesystem compatibility is exact-image, but release ELF cost does not substitute for a separate SDK-package performance qualification. Other agents stopped their Oracle builds and tests before measurement, and the three drivers require an empty competing-workload scan; this does not exclude hypervisor-neighbor noise. Short windows retain every scheduled skip, correctness error and outlier; no window is silently discarded. Pure CNAME and large dns-rr configurations are synthetic directed workloads, not an estimate of their fraction in a deployed router's traffic.
