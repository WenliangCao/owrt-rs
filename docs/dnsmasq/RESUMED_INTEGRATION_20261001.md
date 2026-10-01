# Resumed integration snapshot — 2026-10-01

Frozen source `8c34170` combines retained TCP listeners, shared-capacity
admission, transient UDP send retries and hosts-derived DHCP reservations.
Its native Linux aarch64 release build passes; the same committed source
passes native and aarch64-musl all-target Clippy with warnings denied.

Already-built test harnesses run inside separate private network/mount/PID
namespaces, with one test thread. The library passes **381 tests**, with
**15 ignored**; main passes **6 tests**, with none ignored. The existing
DHCP-to-DNS actual-service differential passes **34/34** ordered observations,
including immediate post-ACK visibility and first-query restoration. No
polling allowance was introduced to hide a delayed publication.

This is a coherent integration check after the separate component gates.
The earlier resource61, TCP recovery17/capacity31, retry helper53 and DHCP
hosts-address27 gates remain attached to their own documented frozen binaries;
their counts are not added to the library count or silently relabelled as runs
of this ELF. See `DNS_TCP_ACCEPT_FAILURE_PHASE.md`, `DNS_TCP_CAPACITY_PHASE.md`,
`DNS_SEND_RETRY_PHASE.md` and `DHCP_HOST_ADDRESS_PHASE.md`.

An initial test runner assumed Cargo emitted only main and library test
artifacts. Seven existing probe-bin harnesses also appeared, so it stopped
before executing tests. The corrected runner selects the two named targets;
`artifact-enumeration-failure.json` retains the initial failure. All targets
were still compiled and checked by Clippy. No probe harness was counted as a
runtime test. A preexisting formatting-only change in `daemon_poll_tests.rs`
is preserved with this report; full working-tree `cargo fmt --check` passes.
That formatting does not relabel the frozen source archive.

Identities:

- Source archive SHA-256:
  `ab6af55419e4b1a4e8c8a1b4b03bd219661b108836484e68b32e3691703adfab`.
- Native Rust ELF SHA-256:
  `ee92c7e2bc43e774a3a63ecfa360e90c1f3fc46a0e9c8144f27ae1d1100d8a0f`.
- Exact native C ELF SHA-256:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.

Derived counters and individual evidence hashes are in
`RESUMED_INTEGRATION_20261001.json`. Complete source, commands, test/build logs
and raw DHCP/DNS evidence stay under ignored
`private/dnsmasq-rewrite/resume-integration-20261001/`; the build-host original
is `/home/ubuntu/dns-resume-integration-20261001`.

This is not a new SDK package or target-image execution result. Full TCP cache
inheritance/writeback, background retry accounting, complete DNS/DHCP/TFTP and
OpenWrt contracts, size/performance acceptance and router validation remain
separate. Ignored tests and unexecuted contracts remain unqualified.
