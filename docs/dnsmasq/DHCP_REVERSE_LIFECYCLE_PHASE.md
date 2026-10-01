# Restored and reloaded lease names from static hosts

Startup and HUP now apply the static reverse-host fallback in
`lease_update_from_configs`. The old Rust updater handled configured
`dhcp-host` names only; the paired corpus reported **70/87 checks passing**
with **17 failures**. The corrected implementation passes **87/87**, and its
14 complete observation snapshots are byte-identical to the independently
frozen C observations.

The exact contract is `lease.c:254–274`, `dhcp.c:1092–1119` and
`dnsmasq.c:1834–1850`. A matching configured name wins only when its optional
address agrees with the lease. Otherwise the updater tries the current static
IPv4 reverse name, applies domain/hostname policy and marks an accepted name
authoritative. Missing, removed, wrong-domain or illegal names preserve the
old lease name. DNS-disabled startup/HUP never invokes the static-host lookup.
The existing lifecycle then writes the lease file and publishes DNS.

The updater snapshots lease addresses in existing traversal order and applies
one selected name at a time. It does not retain a cloned name for every lease.
A resolver error preserves names that could not be resolved, still permits
independent valid configured-name updates and is returned as
`MaintenanceReport.name_error`; main reports that error separately from file
or DNS-publication errors. This internal failure has a regression test,
including a successful subsequent reload. No throughput/resource gain is
claimed from the implementation mechanism.

The [C baseline](DHCP_REVERSE_LIFECYCLE_BASELINE.md) contains 10 scenarios,
14 startup/HUP snapshots and 108 DNS responses, with no DHCP packets sent.
The comparison uses infinite restored leases, equal local/DHCP TTLs, identical
configuration and the same native ubusd/ubus CLI. Full lease rows, the first
post-barrier file state, DNS semantics (including TTL/flags/record order),
clean shutdown and process reaping remain checked. Neither `port=0` snapshot
is counted as a DNS pass.

The shared completion marker is now Linux `IN_CLOSE_NOWRITE` on the same empty
DHCP hosts file, followed by a synchronous real UBus metrics request. It avoids
depending on Rust having C's informational read log. Both daemons close that
source inside their reload handler; the metrics reply follows handler
completion. Re-running C with this observer produced exactly the original
`c-observations.json` SHA-256:
`becefb0e67a0218958c813f22c7d7a2585d4a8b15b99c74b8b85a7167442c25d`.
No expected values were generated from Rust.

Ignored evidence under `private/dnsmasq-rewrite/boot-config-20261001/`:

| Evidence | Result |
| --- | --- |
| `reverse-lifecycle-c-marker-01` | **72/72** C checks; original observation hash unchanged |
| `reverse-lifecycle-before-01` | **70 passes / 17 failures**, all 14 snapshots completed; retained |
| `reverse-lifecycle-after-01`, `-after-02` | Initial implementation **87/87** |
| `reverse-lifecycle-calibration-01` | Corrupt one independently frozen C expectation: **86 passes / 1 failure**, exit 1; actual observation hash unchanged |
| `reverse-lifecycle-final` | Final frozen ELF **87/87**, 14/14 paired snapshots, 0 unexecuted; observation hash equals C |
| `reverse-lifecycle-ack-regression` | Existing ACK/INFORM reverse-name gate **28/28** on the final ELF |
| `reverse-lifecycle-freeze-05/linux-dhcp-tests.log` | **117/117** related Linux tests, including all isolated socket tests |
| `reverse-lifecycle-freeze-05/{clippy,musl-clippy}.log` | Frozen native and aarch64-musl all-target clippy passed, warnings denied |

Earlier snapshots retained the then-committed DNS clippy failures; they were
not reported as passing. The final snapshot includes the later corrected
committed baseline. A new regression initially used a private `DnsConfig`
field through struct update syntax; that test compile failure is retained and
was corrected by using the public parser. Failed logs and every source freeze
remain private; no failed window was discarded.

Reference native C ELF SHA-256:
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Final Rust main ELF SHA-256:
`a9c1f5f24d1d8915936daf2dbea1ffebe3c5364c1441c25d7ed66d711f1d0e53`.
Source-manifest SHA-256:
`f6906e0247057df3fe379c385d1fe0f10b016e5e55bf0d37084d367634794073`.
`source-base.json` records committed base `377c8a1` plus this phase's DHCP
provider/main-report overlays, excluding unrelated concurrent edits.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dhcp_reverse_lifecycle_diff.py \
  --reference-build "$EXACT_C_BUILD" --rust-binary "$FROZEN_RUST_ELF" \
  --compare-baseline private/reverse-lifecycle-c-marker-01 \
  --out private/reverse-lifecycle-pair
```

Omit `--rust-binary` / `--compare-baseline` for a fresh C-only baseline.
Use `--inject-error` with a fresh output folder to calibrate failure counting.

## Empty short-name correctness boundary

Source inspection shows that C's `legal_hostname` can accept a leading dot,
then `strip_hostname` yields a non-NULL empty name. Its lease writer emits
that value without a token, so the serialized row cannot be reliably restored.
This C boundary was not executed and is not counted as a C pass.

Rust deliberately rejects an empty short name from reverse lookup, preserving
the existing/client name. The regression covers an empty raw name, a lone dot
and a leading-dot name with matching suffix. It checks an actual persisted
file against the independently specified C lease-row format, closes the
provider, reopens the file through normal restoration, and verifies name,
address identity and infinite expiry. This documented difference preserves
recoverable lease data; it is not hidden by dropping a failing C comparison.

These results close the stated startup/HUP fallback and ordinary ACK/INFORM
scope. Address derivation for a `dhcp-host` rule lacking an explicit address,
other pending configuration modes, resource-pressure coverage, performance
measurements and target-router acceptance remain separate work.
