# PGO smoke2: exact control identity stopped the attempt

The compiler-discovery repair worked: control built successfully through the
unchanged SDK recipe, with valid static PIE/RELRO/NX and release budgets. The
result is 2,136,859 bytes but SHA256
`aa8f3d50fe69f7aff473c91d541f5773b552496a6b37a9fc1a1efa8cef80b1e2`,
not frozen E's
`8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27`.
The controller rejected the control and did not start generate or runtime.
This is not evidence that PGO or instrumented static PIE is infeasible.

Cleanup verified no smoke process, an available SDK lock, restored recipe and
unchanged 179 source / 106 SDK file hashes. Loop received the explicit release
and began the separately reserved native screens. Before those screens, the
necessary receipts, compile log and link map were transferred as 176,612
compressed bytes; all subsequent investigation was local.

The original and smoke2 receipts agree on source commit, source digest and
every source file, epoch, SDK inputs, Rust/LLVM versions, map wrapper, builder
and helper. The significant changed build input was the prepared package
location: original `root/private/sdk-build-slot` became
`dns/private/pgo-sdk-smoke2/package-build`. The recipe remapped each location
to `/build`, but `owrt-ubus` is a Cargo path dependency. Its crate identifier
changed, as did both dnsmasq crate identifiers and the product object name:

| Identity | Original E | Smoke2 |
| --- | --- | --- |
| Cargo object suffix | `77cf8d445698bc78` | `c242272afadb83cd` |
| Product codegen unit | `6d20ce5edfbecc16` | `ac1ede19068af683` |
| owrt-ubus crate ID | `Cs7YTTomAqFzA` | `CsftZOvckZW1N` |

Two small local Rust 1.98.1 fixture groups separated the mechanism. For a
single crate, changing output directory, moving source with a corresponding
remap, or selecting the direct/proxy compiler retained the same Cargo metadata
and rlib hash. Changing only the remap to a nonmatching root changed rlib bytes
but not metadata. With a sibling path dependency, moving the otherwise
identical source tree and corresponding remap changed the dependency's
`-Cmetadata` and the dependent crate's `-Cmetadata`, plus both artifact names.
These observations show that source remapping does not remove the path
dependency identity input. They do not prove the next full SDK output hash.

The next tooling correction restores the original prepared build slot and
control Cargo target, binds them to the original E receipt, and keeps the
same exact-E hash gate. Separate fresh attempt outputs remain mandatory.
No new build was launched during the native reservation; no release source,
compiler option, linker, hardening or expected hash was changed to hide this
failure.

[Complete failure and local identity evidence](pgo-sdk-smoke2-failure.json).
Original raw outputs/ELF remain in Oracle private `dns/private/pgo-sdk-smoke2`;
the original attempt is immutable.
