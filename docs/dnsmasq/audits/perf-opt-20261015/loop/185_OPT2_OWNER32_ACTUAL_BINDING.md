# Bind actual 803 SDK and 957 gate to original owner32

The [actual plan](185-opt2-owner32-plan.json) now binds source
`8035114257c8706047d2038c2bb8126391331925`, the actual 957 related-test receipt
and the downloaded SDK ELF/map/build hashes. Its status still rejects launch:
all pretransfers and DNS's final explicit quiet release remain pending.
No native240 is added.

The [binding receipt](185-opt2-owner32-actual-binding.json) records exact
artifacts, including the 2,046,747-byte ELF and 1,126,646-byte APK. Both satisfy
the original 2,200,000 / 1,200,000-byte budgets. The actual 179 source hashes
match the frozen plan, and the reviewed builder's receipt records verified
shipping profile2 commands. Complete independent review is bound separately;
the builder's own assertion is not substituted for it.

The controller, analyzer, eight original imports and all 32 window argv remain
unchanged from `b1efce28`, independently reviewed in `0f43a8d1`. This change
updates only actual identity metadata. Both owner input transfer and DHCP's
four-artifact device pretransfer must finish before the final quiet handoff;
measurement starts only after that handoff and complete actual audit binding.

The complete actual related/SDK independent audit passed in `3ce1e7e5`:
[957 raw/source audit](../correctness/185-opt2-related-independent-audit.json)
SHA-256 `8834e4812f9b8438216df26595288dab635f0341e5cd93a2a1bed39757398610`,
and [SDK audit](../correctness/185-opt2-sdk-independent-audit.json)
SHA-256 `267753aef3405f5d6e9ffea2a33f9d707aaff55e6c77561ab24924d8f18bfcc2`.
Root's actual identity-delta review `dd4fd1bd` also passed, SHA-256
`31e117a742c4013ebf98be50c79afcb793ea1f238656b0c16809adb50b4a2509`.
The owner input pretransfer is retained in
[its receipt](185-opt2-owner32-pretransfer.json); DHCP's device pretransfer and
the final release are still required before either measurement starts.
