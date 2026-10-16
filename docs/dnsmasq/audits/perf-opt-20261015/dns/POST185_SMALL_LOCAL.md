# Separate next-candidate combination

Sourcea15d3ca2 starts at immutable185 and applies four independent performance
changes in their own commits: conservative lease-expiry bound, skipping disabled
wait-diagnostic clocks, reusing the selected positive cache entry for expiry
validation, and delaying the UDP socket Arc clone until actual packet work.
The existing hosts collision-generator repair is a separate test-only commit.
All cherry-picks applied without conflict or manual resolution.

Local Mac checks pass724 library tests with8 ignored and23 binary tests; musl
all-target checking passes both default and m6b-diagnostics configurations.
The same prepared-UDP control with64 unrelated live leases and reply recycling
shows185one allocation/21B per operation→zero for the combination. Both8000
operation controls have checksum468800, zero reallocations and zero live-byte
delta. This does not count the socket owner or establish a CPU improvement.

The individual source reviews remain available. Composition review and Linux
runtime gates are separate obligations. No SDK, native timing or device screen
has run for this source, and none is mixed into185. Refreshed exactC/185 hotspot
evidence will determine whether this becomes the next measured candidate.
[Local validation and unchanged-fixture count receipts](post185-small-local.json).
