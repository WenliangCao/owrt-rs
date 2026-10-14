# Frozen correctness gates — 2026-10-15

Frozen before optimization at `51b039597af13f9c9cf07c9f80e388e25cd8ae5d`.
[frozen-inputs.json](frozen-inputs.json) hashes the baseline product, existing tests,
all existing DNS tools and the two explicit compatibility contracts. Baseline
product hashes identify the starting point; candidate product hashes may differ.
Test fixtures, expected values, comparator logic and approved PTR contract must
remain byte-identical. Every eligible candidate receives its own fresh output,
source commit, ELF SHA and result. No prior candidate's pass transfers.

A failure, missing case, incomplete run or changed C comparison invalidates that
candidate. Its performance cannot qualify. Repeating a harness failure requires
a new output and retention of the first attempt; do not overwrite observations.
The reviewer does not optimize product code or operate `openwrt`.

## Pinned external inputs

| Input | Identity |
| --- | --- |
| Precise OpenWrt image | SHA256 `a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea` |
| Image C dnsmasq 2.93 | SHA256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| Deployed v0.2.0 expected ELF | SHA256 `50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c`; the coordinator separately verifies the router file and running image |
| F10 original C JSON | SHA256 `4021e120f447aa54e7fad49146837c01fd8752f7e9184b67e42f31ba79bcae94` |
| F10 approved manifest | SHA256 `57da7fe59de8de504cb77f5982b8e15a3d599a083b1387e1a7451936f64a8f78` |
| SDK archive | SHA256 `ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25` |
| Rust | `1.98.1`, existing opt3/LTO/feature-off/static-PIE recipe; flags are not an optimization |

C must execute with its image interpreter and libraries. Their identities stay
those in `docs/dnsmasq/audits/tcp-upstream-20261014/summary.json`. Matching upstream
C source and UBus helper assets come from the canonical family identity. They
must be restored from verified local archives if no longer on Oracle.

## Required executions for each finalist

1. **All existing Rust tests and allocation failures.** Compile with `--locked`,
   then run serially inside real new network/mount/PID namespaces with a private
   temporary directory. The ordinary baseline contains 808 lib + 81 bin + 16
   `hosts_allocations` tests, all with zero failures; report actual candidate
   counts. The existing `oracle_build.sh tests` selects lib/bin only, so is not
   sufficient by itself. Compile all test targets or add an explicit
   `--test hosts_allocations` build. The 23 ignored tests are not passes: run the
   15 namespace tests explicitly; run the four C config tests with an exact-image
   C launcher; run the four frozen-clock tests through their existing differential
   harnesses and original corpora. Their complete names/reasons are inventoried
   in the freeze. Add no new ignore or allocation-failure exemption.
2. **Canonical existing C differential regression.** Execute all 44 families in
   `m5_final_families.draft.json` via `audit_20261011_families.py`: 68 registered
   steps, 67 executions after the existing runner's procedural archive-wait
   exclusion. The runner retains all 190 endpoint semantic requirements; no
   semantic check or case is dropped. The original fixtures, checks and exact
   inventories remain authoritative. Run in independent family directories;
   count every returned case and failure from fresh result files.
3. **Actual daemon protocol boundary regression.** Run
   `audit_20261011_dns.py`, then `check_full_audit_dns.py --rust-sha256 SHA`.
   Require 368 pairs, 366 byte-identical answers and precisely the two existing
   C-invalid forward-compression-pointer cases with the existing independent
   structural checks. Require eight healthy daemon lifecycles and all five
   negative controls rejected. Do not reinterpret these old differences.
4. **F10 contract.** Run all 13 cases, 704 DNS observations using
   `f10_contract_probe.py --implementation rust --require-contract`, the original
   C reference and approved manifest. No `--case`, no newly generated qualifier,
   no sorting records or removing fields. Re-decode all recorded wires; require
   zero unqualified failures, all actual process hashes equal candidate SHA,
   complete fixtures and strict DHCP decoded result. Preserve the raw
   `matches_c`/difference list even when an existing narrowly scoped PTR order
   contract applies. Run the 24 checker unit controls unchanged.
5. **TCP upstream parity.** Reproduce the three groups from the 2026-10-14
   receipt: 9 full matrix cases at 25 s/cache 0/recover 2 s; `v4-warm-drop` and
   `v6-warm-drop` at 2 s/cache 0/recover 10 s; the same two at 25 s/cache
   1000/recover 10 s. Keep IPv4/IPv4/IPv6/IPv6 resolver order. This is 13
   conditions/50 query pairs (37 TCP, 13 UDP), including one expected 2 s TCP
   timeout per implementation. Require existing comparator zero differences,
   daemon health/cleanup and exact executable identities; run all seven existing
   tool tests. These are correctness deadlines, not host speed rankings.
6. **Independent code review.** Review source diff and callers, ordering,
   partial failure, resource bounds, snapshots/reload and allocation failure.
   An unchanged unit result does not waive a demonstrated semantic defect.

The canonical family runner already includes the full cache family, so the
previous final SDK's 110-case cache subset is not used as a substitute. Historical
fixed raw-terminal regressions outside the canonical registry are also replayed
from their recorded invocations when the affected DNS answer path changes; they
may strengthen this frozen minimum but cannot alter any expectation.

## Executable command forms

These commands run on Oracle only; all variables below identify private,
task-owned inputs/outputs. `source` is an immutable Git snapshot. The root agent
allocates counting/correctness work and exclusively schedules timed experiments.

```sh
# Build no more than the agreed jobs; copy test executables while holding the
# shared build lock. The complete Cargo command includes integration tests.
CARGO_INCREMENTAL=0 cargo +1.98.1 test --locked --offline \
  --manifest-path "$source/components/dnsmasq/Cargo.toml" --no-run
sudo -n env PATH="$PATH" CARGO_HOME=/home/ubuntu/.cargo \
  RUSTUP_HOME=/home/ubuntu/.rustup RUSTUP_TOOLCHAIN=1.98.1 \
  CARGO_INCREMENTAL=0 TMPDIR="$run_tmp" \
  sh "$source/tools/dnsmasq/run_isolated.sh" \
  cargo test --locked --offline \
    --manifest-path "$source/components/dnsmasq/Cargo.toml" -- --test-threads=1

# Need the same-build map for canonical allocator fault-injection families.
ORACLE_BUILD_LINK_MAP=1 sh "$source/tools/dnsmasq/oracle_build.sh" \
  "$source" "$fresh_release_output" release
sudo -n python3 "$source/tools/dnsmasq/audit_20261011_families.py" \
  --source "$source" --elf "$elf" --link-map "$link_map" \
  --commit "$commit" --base-identity "$base_identity" --out "$families_out"

sudo -n sh "$source/tools/dnsmasq/run_isolated.sh" \
  python3 "$source/tools/dnsmasq/f10_contract_probe.py" \
    --image-root "$image_root" --rust "$elf" --implementation rust \
    --expected-sha256 "$elf_sha" --reference "$f10_reference" \
    --ptr-order-manifest "$source/docs/dnsmasq/audits/full-20261014/f10-contract/qualifier/approved/manifest.json" \
    --require-contract --output "$f10_out"
python3 "$source/tools/dnsmasq/f10_contract_check.py" \
  --reference "$f10_reference" --actual "$f10_out/result.json" \
  --allow-manifest "$source/docs/dnsmasq/audits/full-20261014/f10-contract/qualifier/approved/manifest.json" \
  --output "$f10_recheck"

# Run three fresh outputs with the option groups specified above.
sudo -n sh "$source/tools/dnsmasq/run_isolated.sh" \
  python3 "$source/tools/dnsmasq/tcp_upstream_parity.py" \
    --reference "$image_root/usr/sbin/dnsmasq" --rust "$elf" \
    --image-root "$image_root" --client-timeout 25 --udp-timeout 5 \
    --recover-after 2 --cache-size 0 \
    --resolver-order v4a v4b v6a v6b --output "$tcp_out"
python3 -m unittest discover -s "$source/tools/dnsmasq" -p test_f10_contract_check.py -v
python3 -m unittest discover -s "$source/tools/dnsmasq" -p test_tcp_upstream_parity.py -v
```

No tests have passed merely because they are listed here. Actual runs, restored
asset paths and counts are appended to the experiment ledger separately.

## Oracle prerequisite locations observed read-only

- SDK: `/home/ubuntu/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64`.
- SDK linker: its `staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc`.
- Existing helper's shared cache: `/home/ubuntu/dnsmasq-cargo-target`; its
  `.dnsmasq-build.lock` must cover build and immutable artifact copying.
- Retained image bases: `/home/ubuntu/dnsmasq-image-bases/`; three bases' C ELF
  hashes matched the pinned C SHA. The coordinator chooses one complete base.
- Native host: AArch64 Linux; cargo/rustup, gcc, nft, ip, perf are present.
- On initial read-only inspection, `/` had 142 GiB free and `/dev/shm` 12 GiB
  free. This reviewer removed nothing and touched no Docker state.
