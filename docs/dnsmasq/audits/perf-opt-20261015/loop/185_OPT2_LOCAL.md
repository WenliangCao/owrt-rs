# Separate opt-level2 experiment on185

Source80351142 changes only the release optimization level from3 to2 in
shipping source; the prior hosts fixture repair is a separate test-only commit.
Fat LTO and codegen-units1 remain unchanged. This carries the previously
prepared single compiler experiment forward from F to the much smaller185
local-answer entry; it does not mix compiler and product changes or sweep flags.

A fresh local final Linux/AArch64 comparison reproduces185's parent ELF hash.
Its .text decreases1,823,896→1,729,992B (−5.15%). The local-answer entry falls
4,508→3,700B, shared local/cache3,980→3,668B and wait7,304→6,752B. The fresh
writer instead grows1,088→1,132B. Stack costs also grow: shared local/cache
608→672B, fresh writer288→320B and wait352→368B; local entry remains384B.
These tradeoffs do not establish an IPC or A53 benefit.

Release Mac library721passed/8ignored and musl release all-target checking
pass. No canonical SDK build, Linux runtime gates or performance measurement
has run. The refreshedC/185 hotspot data will guide whether to give this
separate compiler factor a fixed screen. Existing PGO budget failures remain
unchanged and no further PGO parameter search is introduced.
[Commands, ELF/code identities, sections and validation](185-opt2-local-codegen.json).
