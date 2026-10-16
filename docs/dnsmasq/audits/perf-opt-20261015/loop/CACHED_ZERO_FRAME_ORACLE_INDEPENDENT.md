# E/185 full110 independent raw audit

The existing F auditor, adapted only for output root and exact185 ELF pin,
ran after DNS's explicit completed/quiet handoff on Oracle CPU0. Its SHA256
was `5e5f74d11bdfe97c0e4c8fbee707387f3360eaeb439c29ded1613beceb96db51`.
No workload or measured window was rerun or changed.

[Full derived audit](cached-zero-frame-oracle-independent.json): **PASS**,
110 archives, 3,430 extracted files and 110 windows; no audit errors. Its
SHA256 is `fc72a89a96212b68d7ae7c4c9c8a5a22864b3a2b5daa15e15fb5d86da234c0b3`.
The original summary remains
`df085ab812892231f409920ddf9b54c0f3c31a49593825432edb0d428b888296`.
All archive members, source raw values and derived statistics were checked
by that original auditor; this is separate from the author's postflight.

All33 primary comparisons remain within variation or resolution. There is
no discernible primary improvement or regression. UDP-hit CPU is26→24us per
operation, −7.692%, W16.667%, four favorable pairs and a one-tick median
difference, which fails the strict CPU precision gate. It is not an accepted
gain. The seven traffic-scene PSS/USS medians increase60–72KiB; those resource
values remain explicit rather than being reclassified as a performance win.

The full raw tree remains
`/home/ubuntu/dnsmasq-perf-20261015/root/private/oracle-cached-zero-frame-vs-e`.
Only the172,638B derived audit was copied locally and rehashed. Afterward,
there were no research processes and all three existing SDK/native/cargo
build locks were obtainable. Oracle then remained reserved to loop for the
separate, pre-reviewed exact-C/18516-window stat/cycles diagnostic.
