# Exact SDK confirms the narrowed entry and retains its fallback cost

The unchanged SDK produced185 ELF9109e987…7f99,2,145,051B, with the original
size/hardening gates passed. It is8,192B larger than acceptedE and4,096B larger
than0161. The APK is1,167,095B within the original1,200,000B budget. No compiler
option changed. These are still exploratory, unqualified artifacts.

[The codegen receipt](cached-zero-frame-sdk-codegen.json) binds each actual
ELF, same-link map and build receipt, then decodes the uniquely selected input
range within its executable file-backed PT_LOAD. No nearby-symbol guess or
replacement local cross-build supplies these SDK bytes.

| Selected emitted function |0161 code/frame bytes|185 code/frame bytes|
|---|---:|---:|
|Shared local/cache caller|3,980/608|3,980/608|
|Local entry|14,768/848|4,508/384|
|Full local-record helper|inside entry|12,132/784|
|Local ownership helper|528/368|528/368|
|Fresh-address writer|1,004/288|1,088/288|
|General cache answer|13,524/2,256|13,364/2,240|
|UDP owner process|4,480/1,056|4,672/1,056|
|Owner wait|7,304/352|7,304/352|

The selected hit avoids the large local-record helper; the fallback instead
has384+784=1,168B across its two local frames,320B above the parent848B and
an extra call. The buffer-return owner and fresh writer grow slightly. The
standalone local frame prototype had an11,884B record helper; the actual
combined SDK emits12,132B, so the standalone code extent must not be reused
as the combined result. The common entry frame observation does reproduce.

Static entry reservations and emitted extents do not measure per-query stack
writes, instruction-cache occupancy, or CPU savings. Native fallback scenes,
exact-owner timing and A53 controls retain their authority. No result from this
inspection selects185 or changes its frozen inputs.

Two private read-only extraction attempts failed first: ambiguous compiler
helper matches, then a script basename shadowing Python's inspect module.
Both are retained; unique ordinary-function selection and a nonconflicting
filename resolved them. No workload was run, replaced or changed for this
inspection.
