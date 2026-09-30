# Native C reference identity and calibration

The 2026-09-30 continuation reused the existing Linux C build after verifying its
current identity. No physical router was accessed. The host build is a functional
oracle; its glibc, compiler and kernel differ from the target, so it is not target
ABI or router performance evidence.

`prepare_reference.py` reconstructed and checked the image recipe again: 13
recipe files and 148 patched source files match. Its `identity.json` SHA256 is
`62cec0e9dda0265cb9c4f6af27f7d23067aed967afab3c74e37370149a8326e9`.
`verify_reference.py` then checked the remote copy, all 42 compiled objects'
source and feature-gated compile records, version output, ELF identity and linked
dependency locations. The recorded ELF SHA256 remains
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.

| Dependency | Image revision | Present source |
| --- | --- | --- |
| libubox | `7dd127841e82eb1cfb61185da37dde7b9bd9ba6d` | Exact revision, clean checkout |
| ubus | `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` | Exact revision, clean checkout |

The native ELF resolves both libraries from its own recorded `deps/lib`.
The audit records hashes of those libraries and every object used by extracted
C drivers. This checks present artifacts against build records; it does not
prove reproducible builds or substitute for a future target build.

Run the read-only audit on the Linux build host after copying the verified
identity and image source manifest:

```sh
python3 tools/dnsmasq/verify_reference.py \
  --source "$REFERENCE_SOURCE" \
  --build "$REFERENCE_BUILD" \
  --manifest manifests/ax3000t-stock-openwrt-25.12.5/sources.json \
  --identity-sha256 62cec0e9dda0265cb9c4f6af27f7d23067aed967afab3c74e37370149a8326e9 \
  > private/dnsmasq-rewrite/reference-audit/result.json
```

The current `dns_service_probe.py` was calibrated against that C daemon in fresh
loopback-only network namespaces. Its 12-case schedule completed with 12
successes, zero errors and exit 0. The same probe with `--inject-failure` returned
11 successes, one counted unknown-type SERVFAIL error and exit 1. Both daemon
processes terminated with exit 0. A deliberately incorrect prepared-identity
hash also caused `verify_reference.py` to exit 1. The probe comparator preserves
IDs, flags, TTLs, record order and upstream-query counts for this deterministic
schedule; this does not establish that its schedule covers all protocol behavior.

Raw results and the exact tool hashes are under ignored
`private/dnsmasq-rewrite/reference-audit-20260930/`: `result.json` contains the
reference audit, and `calibration.json` contains commands, all case results,
positive/negative exits and tool identities. Existing broader results remain
separate evidence; this C-only calibration is not a Rust correctness pass.
