# Bind actual 803 SDK and 957 gate to original owner32

The [actual plan](185-opt2-owner32-plan.json) now binds source
`8035114257c8706047d2038c2bb8126391331925`, the actual 957 related-test receipt
and the downloaded SDK ELF/map/build hashes. Both pretransfers, full actual
independent review and DNS's explicit final quiet release are complete.
The original owner32 started at 2026-10-16 07:50:39 UTC; results are pending.
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
the final release were completed before either measurement started.

The [DNS release](185-opt2-screen-release.json) has SHA-256
`f9533ce806a75c35b6475e88a5fa9b0b0f36e5b201f3a45684824d6ba59c4b28`.
After that handoff, only the final ready metadata was uploaded and rehashed:
[receipt](185-opt2-owner32-final-ready-metadata.json), SHA-256
`86307ea61be6ce9c15236d59ee0edc120f10a03f8f146bda891adc4125e5c306`.
The [ready self-check](185-opt2-owner32-ready.json) preserves the unchanged
protocol fields. Final plan SHA-256 is
`715d64768c4616c10ce41983b48f0d801f404b4da6807aed5e756cdd21dd6c31`.
The [launch](185-opt2-owner32-launch.json) binds controller PID 976472,
original 32 windows and the transfer hold during both measurement slots.
