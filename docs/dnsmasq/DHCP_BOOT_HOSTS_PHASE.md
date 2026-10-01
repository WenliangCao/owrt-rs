# DHCP boot next-server names

Ordinary untagged `dhcp-boot` now resolves its third field from the DNS parent's
current static hosts generation for every successful DHCP/BOOTP response. This
closes the hosts-name gap in `DHCP_BOOT_CONFIG_PHASE.md`; tagged/PXE/relay boot
selection remains outside this stage. No performance or production acceptance
is claimed.

The exact C contract is `option.c:4347–4393`, `rfc2131.c:2678–2703` and
`cache.c:1725–1744`. The parser preserves the raw hostname; lookup is
case-insensitive but does not strip its trailing dot. `a_record_from_hosts`
accepts only IPv4 `F_HOSTS` records, including configured `host-record` entries.
It does not follow CNAMEs, ask the system resolver, use forwarded cache records
or substitute DHCP-derived DNS names. Missing names return zero and emit one
warning per lookup. A real static zero address returns zero without that warning.
With DNS port zero, C does not initialize/read the hosts cache and lookup returns
zero with the same warning.

The runtime now has a small fallible next-server lookup hook after lease state
is committed. Main connects it to `ParentDns.local.hosts.lookup` under the
existing DNS mutex. This uses the same round-robin state and HUP generation as
UDP DNS. It does not clone a stale hosts snapshot or change lease ownership.
A poisoned lock or unattached resolver is an explicit runtime error; the
committed outcome remains available and no reply is sent. This internal failure
has no C mutex analogue and is not silently reclassified as a missing hostname.
The new unit regression verifies that failure boundary.

`tools/dnsmasq/dhcp_boot_hosts_diff.py` runs exact C first and then Rust using
identical configuration, synthetic inputs and loopback-only namespace. It
compares all DHCP/BOOTP and interleaved DNS response bytes, their ordered events,
and missing-host warning counts. Reload waits for an independent marker name to
prove the new generation is visible before the next boot query. The disabled-DNS
case supplies a FIFO as `addn-hosts`; successful startup/reply proves it was not
opened for reading. No boot file is served or fetched.

| Coverage | Result |
| --- | --- |
| Single / multiple host-record addresses, case-insensitive lookup | Matches C, including initial insertion-induced address order |
| BOOTP, OFFER and SELECTING ACK sharing UDP DNS rotation | Exact ordered response match |
| `no-round-robin` | Fixed address and DNS order match |
| IPv6-only, absent, trailing-dot and CNAME names | Zero next-server and warning counts match |
| Existing DHCP DNS name | DNS answer exists; boot lookup still returns zero |
| Zero-valued static IPv4 | Zero next-server without missing-host warning |
| HUP replacing hosts file | Next response uses the new address |
| DNS port zero with ordinary hosts and FIFO path | Zero response, correct warnings, no hosts-file read |

Final evidence is below ignored
`private/dnsmasq-rewrite/boot-config-20261001/`:

- `hosts-c-baseline-01`: retained fixture failure; a duplicate static IP caused
  one C startup failure, so only 36/39 events executed. The duplicate directive
  was removed; this run is not a pass.
- `hosts-c-baseline-02`: first successful C-only 11-scenario / 39-event freeze.
- `hosts-c-baseline-03`: added real zero-address and warning observations;
  final **12 scenarios / 41 ordered events + 12 warning counts**.
- `hosts-pair-01`: **53/53** observations matched, zero unexecuted. All 24 C/Rust
  processes exited zero and were reaped.
- `hosts-calibration-01`: one injected wrong next-server produces **52 matches,
  1 mismatch, exit 1**. Fixed static-host and DHCP-name exclusion also have
  independent C assertions.
- `hosts-boot-regression-01`: ordinary boot fields / overload / cookies /
  `dhcp-no-override` retain **54/54** exact response matches on the new ELF.
- `hosts-dhcp-unit-final.log`: **106** related unit tests passed.
- `hosts-musl-clippy-03.log`: all-target musl clippy passed with warnings denied.
- `hosts-freeze-01`: source archive/manifest, exact Linux release ELF and build
  log. A transient unit compile failure from a nonexistent test-only `Default`
  constructor is retained in `hosts-dhcp-unit-01.log`; the fixture was corrected.

Reference native C ELF SHA-256:
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Rust Linux main ELF SHA-256:
`0363c92bf6d8300d5d15e5fa1a0d83ba824703e06cb8d0e78ba2b5cfb5606c86`.
Frozen source-manifest SHA-256:
`f111c122522724bb983ff037ad1c5103d726c3800152490f647c04f48a365738`.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dhcp_boot_hosts_diff.py \
  --c "$EXACT_C_ELF" --rust "$FROZEN_RUST_ELF" \
  --output private/dhcp-boot-hosts-rerun
```

These are host-side functional observations against the pinned native C build.
Target-image dependency/runtime and physical-router acceptance remain separate.
The earlier serializer and BOOTP lease/DNS regression evidence remains valid;
this stage changes hostname selection wiring, not their serializers or state
transitions. It establishes the stated coverage, not complete dnsmasq equivalence.
