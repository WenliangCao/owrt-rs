# TLS dependency review, 2026-10-22

The review follows Microsoft rules M-STATIC-VERIFICATION, M-UNSOUND,
M-PUBLIC-DEBUG and M-HOTPATH. The official RustSec database was inspected at
[`640bf5a9f06e66d8721e8772766531fe77c8630d`](https://github.com/RustSec/advisory-db/tree/640bf5a9f06e66d8721e8772766531fe77c8630d)
(2026-10-22). This was a manual comparison of lockfile package versions and
advisory conditions; **cargo-audit was not run**.

Only two HTTP lockfile packages changed: rustls **0.23.43 → 0.23.46** and
rustls-webpki **0.103.15 → 0.103.16**. The rustls manifest minimum is now
0.23.46. Features remain `ring`, `std`, `tls12`, with defaults disabled.
The application remains a TLS server using `with_no_client_auth()`.
See the official [rustls release](https://github.com/rustls/rustls/releases/tag/v%2F0.23.46)
and [webpki release](https://github.com/rustls/webpki/releases/tag/v%2F0.103.16).

| Advisory | Previous dependency and application applicability | Resolution |
| --- | --- | --- |
| [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html) | 0.23.43 affected. Common TLS 1.3 deframing accepted handshake messages across key changes; the shared server path is relevant. | Patched in 0.23.46; upstream fix [#3265](https://github.com/rustls/rustls/pull/3265) reviewed. |
| [RUSTSEC-2026-0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html) | Version affected, but Brotli is disabled and the server does not request client certificates. | Patched dependency. |
| [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html) | Version affected; requires client session value Debug use. This daemon has no client session store. | Patched dependency. |
| [RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html) | Version affected; client key-share prediction is outside this server's role. | Patched dependency. |
| [RUSTSEC-2026-0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html) | 0.23.43 is explicitly unaffected; this is also a client ECH path. | 0.23.46 remains patched. |
| [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) | webpki 0.103.15 affected; this server performs no client-certificate chain verification. | Minimal transitive patch to 0.103.16. |

The 15 application/platform/benchmark lockfiles contain 30 distinct registry package names (33 name/version
pairs). Nineteen advisories name those packages. The remaining thirteen are
already patched, explicitly outside the locked version, or withdrawn;
[the complete disposition](RUST_TLS_ADVISORIES_20261022.json) records each.
No active version match remains in that database snapshot after these patches.
This does not claim absence of unknown vulnerabilities.
The subsequently added standalone fuzz lock is covered separately by
[its compile, dependency and advisory check](RUST_FUZZ_CHECK_20261022.json).

Validation on `ssh oracle`, using `mbx` and Rust 1.98.1:

- HTTP all-target tests: 72 daemon tests plus 49 imported-module example test
  invocations passed; these **121 invocations are not 121 distinct tests**.
  Clippy and native/musl release builds passed for the dependency patch.
- [Exact OpenWrt 25.12.6 differential](RUST_TLS_HTTPD_DIFFERENTIAL_20261022.json):
  **48 cases, 38 exact comparisons, zero differences**. It includes a TLS 1.2
  static GET. The stock image rejects TLS 1.3, so TLS 1.3 uses the old
  and new Rust servers as its compatibility/performance controls. The failed
  exploratory stock TLS 1.3 run is retained remotely, not counted as passing.
- The tested musl binary SHA-256 is recorded in the differential JSON. Later
  source edits require the final repository gate; these results are not a
  substitute for validation of that final artifact.

After the final HTTP test-reader fix and shared-platform changes, the daemon
was rebuilt with `mbx` for AArch64 musl. The
[final differential](RUST_HTTPD_FINAL_DIFFERENTIAL_20261022.json) passed
**49 cases, 39 exact comparisons, zero differences**, adding a TLS 1.2 CGI
POST that echoes 32 KiB while exercising alternating TLS reads/writes.
The [46-input identity check](RUST_HTTPD_FINAL_INPUTS_20261022.json) matches
local and remote files; final ELF SHA-256 is
`d26725351eb4687cf8e53b09c2d6a439652f9de6b5c37a2cf4b43691fab927be`.
HTTP all-target tests again passed 72 daemon plus 49 example invocations,
and Clippy passed. TLS CPU measurements were not repeated for these
test/documentation edits.

Performance model: server CPU contains handshake cryptography, TLS framing,
HTTP dispatch and file reads. Process CPU clocks exclude client CPU. Client
and server were pinned to separate CPUs; every response status and all 16 KiB
of body were checked. The preset acceptance threshold was a 5% systematic CPU
increase. Six alternating baseline/candidate pairs follow two same-binary
baseline floor runs; neither set is selectively filtered.

| Server CPU median change | TLS 1.2 | TLS 1.3 |
| --- | ---: | ---: |
| Full handshake | −0.20% | −0.10% |
| Established connection GET | +0.07% | +2.34% |

These are [quiet-window results](RUST_TLS_QUIET_RESULTS_20261022.json) with
100 handshakes or 1,000 requests per lane/run. Before the run, no Cargo, mbx,
rustc, rustdoc or Miri process was present and other agents paused CPU work.
The [quiet summary](RUST_TLS_QUIET_SUMMARY_20261022.json) meets the preset
threshold. The earlier concurrent-build/Miri run used 300/3,000 operations;
its [full samples](RUST_TLS_NOISY_RESULTS_20261022.json) and
[summary](RUST_TLS_NOISY_SUMMARY_20261022.json) remain available. Its TLS 1.2
keepalive median was +34.79%, with substantial baseline drift, so it was
inconclusive and was not discarded or described as a pass. Native Linux CPU
cost is a proxy, not a physical-router throughput or latency certification.

Additional memory-safety evidence: `mbx miri test` on nightly
1.101.0-nightly (c36f14571, 2026-10-01) passed all 10 selected ubus blob tests
and 23 DNS wire tests. Three expensive DNS tests were explicitly filtered;
an earlier all-wire run was stopped during one of them and is not a full pass.
These pure codec runs do not cover Linux FFI, TLS cryptography, netlink or
physical hardware. Logs remain under
`oracle:/home/ubuntu/owrt-rust-review-20261022/`.
