# Native layout screen: smaller frames do not guarantee lower CPU

The fixed plan completed all480 windows (180 grouped PMU,300 plain) and all486 build/workload commands exited successfully. Source hashes before/after, fixed checksums, zero allocation-tracking fields and complete unscaled equal-time PMU groups passed. Each prototype was built separately from F; no prototype combination or compiler change was tested.

The owned-answer reply split regresses ordinary hits and configured CNAME in this native screen. The address-dispatch split offers modest gains on ordinary address paths. Neither is yet selected: the original-SDK32-window confirmation is running independently, and no full candidate or device acceptance is claimed.

CPU changes below use whole-process RUSAGE_CHILDREN and five alternating pairs. Child process startup, fixture setup/priming and teardown are included; the controller parent CPU is excluded. Each comparison has its own interleaved F controls; the two F cohorts are not pooled. PMU uses three separate pairs; its cycles and IPC describe the mechanism and do not borrow the five-pair statistical decision.

| Scene | Reply CPU change / W | Reply decision | Address CPU change / W | Address decision |
| --- | ---: | --- | ---: | --- |
| hit | +0.568% / 0.197% | slower | -1.208% / 0.339% | faster |
| hit-upper | +0.768% / 0.455% | slower | -1.252% / 1.495% | within_variation_or_resolution |
| hit-leases | +0.542% / 0.453% | slower | -1.241% / 0.486% | faster |
| hit-typed | +0.707% / 0.603% | slower | -1.336% / 0.242% | faster |
| miss | +0.962% / 0.415% | slower | -1.705% / 0.594% | faster |
| miss-leases | +0.609% / 0.259% | slower | -1.665% / 0.188% | faster |
| host | +1.219% / 2.375% | within_variation_or_resolution | -0.768% / 2.394% | within_variation_or_resolution |
| host-localise | +2.437% / 5.977% | within_variation_or_resolution | +2.482% / 3.631% | within_variation_or_resolution |
| raw-address | +0.235% / 0.561% | within_variation_or_resolution | +0.604% / 0.712% | within_variation_or_resolution |
| synth-address | +1.706% / 0.406% | slower | -1.275% / 0.422% | faster |
| lease-address | -0.514% / 1.819% | within_variation_or_resolution | -1.555% / 0.487% | faster |
| rrset | +1.281% / 0.783% | slower | -0.012% / 0.572% | within_variation_or_resolution |
| cname | -0.070% / 0.994% | within_variation_or_resolution | -0.074% / 0.495% | within_variation_or_resolution |
| cname-leases | +0.554% / 0.779% | within_variation_or_resolution | -0.561% / 0.659% | within_variation_or_resolution |
| cname-config | +7.228% / 0.387% | slower | -0.313% / 0.096% | faster |

Reply-layout has9 discernible native regressions and no discernible gains. Address-dispatch has8 discernible native gains and no discernible regressions among these15 scenes. This is not an equivalence proof: address host-localise CPU is+2.482% (W3.631%) and its median instructions/cycles rise+2.957%/+3.358%; those adverse counters are retained. Address raw records also rise+0.604% CPU within W0.712%.

For ordinary hit, reply instructions are+0.016%, cycles+0.715% and CPU+0.568%; per-window IPC median falls2.628→2.610. The large configured-CNAME cost is primarily efficiency: instructions−0.036%, cycles+6.784%, CPU+7.228%, IPC3.273→3.063. Moving the body out therefore did not achieve the intended general efficiency improvement.

Address ordinary hit instructions fall1.045%, cycles1.090%, CPU1.208%, while IPC stays about2.630. This looks mainly like less work in this warm native loop, not proof that the original E/C cold owner IPC gap has been eliminated. The exact-SDK low-rate owner screen is required to test that separate effect.

All operation counts were fixed before measurement:200k for stat;2m for plain except raw-address/configured-CNAME200k. They divide every fixture population exactly. The native fixture checks answer count/rcode/id during priming and a fixed output-length checksum; it is a coarse work/answer sentinel, not the correctness oracle or performance coverage for every RR type.

Raw logs, native ELFs and all command identities remain in Oracle private `root/private/layout-native-screen1`; its complete result is also retained locally. The result SHA is `c25c5c5ce76452737f03b6d880924470b95e81b39a11ca9653b368939d3fc9d6`.

[All derived windows and comparisons](layout-native-screen-result.json), [fixed plan](layout-screen-plan.json), [replay](run_layout_native_screen.py), [derivation](analyze_layout_native_screen.py), [independent pre-run accounting review](layout-screen-timing-review.json).
