# Reuse the original whole-owner allocation diagnostic on185

Excluded diagnostic source7c5b4c58 adds the original6d6e6038 meter to exact185.
The meter and standalone control are byte-identical to the prior E diagnostic.
Only the existing owner-turn/UDP-step/classification/normal-exit hooks are added;
the185 cached-reply recycling path remains unchanged. Removing the hooks
reconstructs185main exactly (independent review98367eec).

The unchanged standalone allocation/reallocation/whole-turn/unscoped control
passes; local musl daemon compilation checking passes. The actual instrumented
SDK artifact and a frozen three-window device plan remain pending. Preserve
the original actual-Cached denominator (including hits during prewarm), one
daemon thread, nested0/unscoped0 and normal-exit requirements. All instrumented
CPU/latency values remain excluded; instrumented size cannot qualify a release.

The value of this diagnostic is scope:185's zero-allocation evidence currently
covers a local prepared API, whereas the E diagnostic counted the real A53
UDP owner. No whole-owner zero claim is made for185 until those counts exist.
