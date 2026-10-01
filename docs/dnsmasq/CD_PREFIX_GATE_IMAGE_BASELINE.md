# Ordinary CD prefix gate on the exact image C daemon

The strictly verified image dnsmasq passed **10 cases / 136 observations** on
its first run of the already-frozen ordinary-CD prefix gate. Its observations
also match all 136 native-C observations under the frozen comparator, including
CNAME visibility before pending cleanup, direct-owner deletion, empty-CD-reply
cleanup, pressure eviction and recovery. No tool or expected-input change was
made between the native and image runs.

The image ELF is
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
The explicit private musl runner is
`de018ed3599e0d5f4a8f6c7646c8dd76759382b79b029ab40e3e3deac273e0db`.
`verify_reference` checked the canonical image identity, exact runner body,
image ELF and all pinned musl/libubus/libubox/libgcc dependencies before starting
the daemon. Native libraries were used only for the independent UBus client and
private bus fixture; the image runner explicitly selects its image libraries.

The tool and native baseline were frozen in `d39bde7` before this run.
Raw data is retained under ignored
`private/tcp-writeback-gates/cd-prefix-image-baseline-01`; the companion JSON
records identities, per-case counts, raw hashes and zero cross-reference
differences. The [native baseline](CD_PREFIX_GATE_BASELINE.md) describes the
scope and observations. This adds image authority, with no Rust parity claim
or router access.
