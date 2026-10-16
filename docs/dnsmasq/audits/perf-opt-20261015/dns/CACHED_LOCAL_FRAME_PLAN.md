# Isolate full local-record assembly from the narrowed hit path

Independent child `a8dcdacc` of `0161ad9c` keeps validation, interface NX checks,
lease expiry, configured-CNAME detection, cache-name inspection and the narrow
fresh-address ownership check in their original order. Eligible fresh hits and
cached CNAMEs return before the full record assembly helper. Every other path
enters the non-inline helper with the original mutable lease Arc; it does not
clone, expire or inspect again. The CNAME block and remaining record assembly
tail are byte-identical to the parent. QueryEvents construction moves with that
body; its constructor has no allocation or external side effect.

Mac720/8 and musl all-target checking pass. The first build/check failed because
the initial helper passed only an immutable lease view to mail-address assembly;
the retained logs precede the correction to pass the original mutable owner.
Independent source review `b4fdacaf` finds no behavior blocker. No product bug
repair, expectation or new compiler option is part of this source.

[Final local cross-link evidence](cached-local-frame-local-codegen.json) uses
the existing pinned Rust/bundled-musl recipe, not the OpenWrt SDK. The local
entry shrinks from14,768 to4,508 emitted bytes and reserves384B instead of848B.
The new11,884-byte helper reserves784B. The fallback's two local frames total
1,168B,320B more than the parent's848B, and add a call. Whole.text grows864B.
The shared local/cache caller stays3,980B/608B and ownership helper528B/368B.
These are static extents/reservations, not measured memory traffic, instruction
cache misses or CPU savings. Cold-path regressions remain a concrete concern.

This source is separate from the bounded reply-buffer prototype and from all
active0161 measurements. If selected for screening after their results, first
run exact-source related Linux gates and the unchanged SDK build. Compare
independently to0161 using the original complete hot15/native240 protocol,
including all fallback scenes; keep the existing workload, operation counts,
PMU/plain pairs, checksums and W/direction rules. Only a supported result should
continue to original SDK owner32 and independent A53ten windows, without
pooling previous controls. Direct accepted-E full qualification remains needed
for any promotion. No new G has been selected.
