# Service management evidence

The synthetic service fixture executes the unchanged exact-image `dnsmasq`
init script, `procd`, `ujail`, `ubusd`, and `netifd` under private network,
mount, and PID namespaces. Both image C and the source-verified Rust ELF
passed all nine management steps in [summary.json](summary.json).
No physical router or product code was modified. No procfs mount was added
to the jail, and stop verification did not send an extra manual TERM.

The summary retains exact artifact hashes, raw evidence paths and hashes,
per-step observations, and the exact oracle reproduction command. Raw logs,
configs, firmware, and executables remain outside Git.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/audit_integration_service.py \
  --image-root "$EXACT_ROOTFS" --rust-binary "$VERIFIED_RUST_ELF" \
  --implementation c --output "$FRESH_PRIVATE_C"
# Repeat with --implementation rust and a fresh private output directory.
```

Two recovery limits were reproduced for both implementations: a daemon
stopped for six seconds leaves procd reporting `running=true` while DNS
times out; the sixth rapid fatal exit disables respawn and leaves no daemon.
Neither mechanism chooses or reinstalls the C binary. These are inherited
supervision limits, not a Rust-specific regression. The source connection is
`dnsmasq.init:1270` (respawn only) and matching procd
`service/instance.c:843-884` (retry cutoff).

Boot coverage is intentionally narrow: the `boot` hook before netifd serves
DNS without DHCP ranges, then an explicit `service.event` interface update
causes the init script to generate those ranges. The bridge is fixture-created.
This is not a full OpenWrt PID-1 boot or verification of the complete netifd
notification path. APK lifecycle, DHCP DORA, genuine OOM, router kernel,
hardware and Wi-Fi are outside this subset.

Discarded setup attempts are listed in the summary: an incorrect UCI scalar
and the wrong event-injection API caused equal C/Rust failures. Corrected,
fresh final runs passed; those setup failures are not product findings.
