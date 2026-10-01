# Generic malformed RDATA correction: native and image results

Product source `ac8a3b6` passes all 35 frozen observations against both native
C and the actual image. The [original 14 reply differences](GENERIC_MALFORMED_BEFORE_RESULT.md)
are resolved without changing the fixture, comparator or cache-prefix behavior.

| Run | C calibration | Paired observations | Differences | Fixture failures |
| --- | ---: | ---: | ---: | ---: |
| native-after-01 | 35/35 | 35/35 | 0 | 0 |
| image-after-01 | 35/35 | 35/35 | 0 | 0 |
| native-negative-01 | 35/35 | 34/35 | 1 deliberate | 0 |

Every C and Rust side passes 196 auxiliary process/UBus checks. The separate
negative run changes one decoded reply flag, detects exactly that one mismatch
and exits 1. It uses the same passing ELF and complete schedule; its original
unmodified raw packet traces remain preserved. Missing-row self-calibration
also passes. There were no failed positive attempts or fixture revisions.

Missing SRV/MX/SOA names and compressed-name RDLEN overrun now produce C's
SERVFAIL, empty answer/authority sections and EDE_OTHER. Disabled MX still
forwards the malformed bytes without validating or caching them. Enabled
unknown type 65280 still caches pointer-looking opaque bytes unchanged.

Ordered extraction remains observable before rejection. The replacement
profile removes the old owner while retaining its sentinel; the pressure
profile evicts two live records and increments `live_freed` by two. Neither
failed transaction increments `inserted` or exposes its new alias/owner.
Controlled failure probes retain those effects, and a later valid transaction
recovers and commits one owner. All 30 UBus counters, packet flags, EDE, record
order, TTLs and upstream event sequences match. Pending membership remains
source-supported rather than a separately exposed daemon count.

The correction carries generic name-decoding failures from their original
ordered extraction position into the existing downstream rejection path. It
does not prevalidate the entire packet or roll back earlier cache operations.
The separate `RecordTooLong` error describes expanded cache representation
size, not necessarily an invalid wire reply. Commit `ac8a3b6` preserves the
previous abort-cache/continue-forwarding behavior for that case. These small
fixtures do not qualify oversized expanded RDATA or C's size-wrapping behavior.

Frozen identities:

- Product source: `ac8a3b6851adb93d62a8f7b334c2b727deffedd0`.
- Rust ELF: `3d8462fac7a81707e3b24f84b1a25fc8b6903d808b66b14cc4f3ede9e230b692`.
- Plan/tool: `5c2fb8c` / `45df082`; unchanged tool SHA-256:
  `ac1dc882c46d822e3172fa786b04e668dc69198fd92d8baa539622ac04d9279c`.
- Native C ELF: `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Image C ELF: `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`;
  matching runner, loader and libraries are verified in each image run.

The [derived JSON](GENERIC_MALFORMED_AFTER_RESULT.json) preserves identities,
per-profile counts and boundaries. All 300 after/negative raw files were
downloaded and checked individually against the remote SHA-256 manifest:
`5dc117766d3724a78c3aec9aec9c8375ef6e0fdd1c0eabe03f18890ba296f07d`.
The ignored `private/evidence/generic-malformed-after-01.tar.gz` archive is
463,468 bytes with SHA-256
`7151f067abc2c11a28054ad86508b446bda728363497943a42883cc82c2eba46`.
Original baseline and before evidence is separately preserved in
`private/evidence/generic-malformed-before-01.tar.gz` (479,244 bytes), SHA-256
`d3f27bbfcee9c2360fdd0aec3857a2d1d77d7538b6168f5e3884bb28408923ea`.
The oracle copy remains under
`/home/ubuntu/dns-generic-malformed-20261001/work01/private/`.

All experiments ran through `run_isolated.sh`. No physical router was accessed.
The original 78-observation cache-rr fixture is unchanged. This result covers
the frozen UDP service boundary only; malformed TCP, DO/AD metadata expansion,
reverse PTR, arbitrary invalid packets, allocation failure, performance and
production acceptance remain outside it.
