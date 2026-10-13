# Final SDK validation

`validate_final.py` accepts the existing
`20261012/fix3_repairs/functional/types_validation_driver.py` prepare/run CLI.
It reuses its complete 49 jobs: 35 commands spanning 14 affected families,
13 directed daemon commands, and the separate native configuration-state probe.
All daemon jobs use the fresh final SDK payload.

The only strengthened assertion is N1: all 72 original cases must have identical
C and Rust response dictionaries, including full wire bytes and TTL, warm
response dictionaries, upstream counts, and healthy exits. There is no packet or
TTL normalization in this check. Other historical exceptions stay exactly as
declared by the retained driver; passing that matrix does not imply equivalence
to C TCP in its nine explicitly declared transport-routing differences.

`build/build_final.py --root ROOT --phase final` expects a frozen `source-final`,
its `private/source-final-identity.json`, and a separately copied, pinned SDK in
`private/sdk-isolated`. It runs the retained fresh release/test build, all ordinary
unit tests, and two clean SDK source builds. The second build retains the exact
link map and must produce the same ELF and APK as the first. The driver never
supplies `OWRT_DNSMASQ_FROZEN_ELF`; original size-budget failures remain failures.

Builds, functionality and performance occupy separate oracle windows. Outputs
must be new paths. Original failed observations, if any, are retained. The
collectors rehash the fresh outputs and produce only derived receipts and raw
file identities for Git; binaries, SDK files, full raw evidence and the image
remain private. The new DHCP-negative probe and N4 three-way measurements have
their own identities and results.
