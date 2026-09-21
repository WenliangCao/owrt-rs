# R108 receive inlining hint — rejected

R108 retained the R106 threshold design and added `#[inline(always)]` to `Client::read_message`. Rust documents this attribute as a hint the compiler may ignore; it is not a performance guarantee.

| Condition | `user_1_1` daemon CPU | `user_8_1` daemon CPU | `user_1_0` daemon CPU |
|---|---:|---:|---:|
| R108 low | -0.20% | -0.99% | +0.41% |
| R108 loaded | +1.27% | +0.33% | +2.55% |

The low-connection matched lanes are near the control, but the unmatched lane remains +0.41%. With 64 validated held connections, matched `user_1_1` is +1.27% and unmatched `user_1_0` is +2.55%; `user_8_1` is +0.33%. Four windows per condition are exploratory ratios, not a formal superiority interval, but the loaded CPU direction is not acceptable for a memory optimization.

R108 passed the basic router unit/protocol preflight and all eight performance windows passed health, identity and cleanup checks. The candidate was never installed. The working source is restored to R103. R105–R108 collectively show: immediate release saves memory but repeatedly allocates; shared spare lowers held-connection memory but raises active CPU; thresholding and inlining do not satisfy both. This receive optimization family is rejected under the current architecture.

The diagnostic symbol comparison remains only a lead: the unstripped diagnostic `.text` differs from the measured release `.text`, so it cannot prove an inlining cause. The exact R103 source rebuild is byte-identical. Evidence: [low results](r108-rx-inline-low-results.json), [loaded results](r108-rx-inline-loaded-results.json), [plans](r108-rx-inline-low-plan.json), [loaded plan](r108-rx-inline-loaded-plan.json), [preflight](r108-rx-inline-preflight.json), [R105 rejection](R105_UBUSD_RX_SPARE.md), [R106/R107 rejection](R106_UBUSD_RX_THRESHOLD.md).

No Rust/C language-limit conclusion follows. Further receive optimization needs a new design with a separately measured allocation strategy, not another threshold or branch variant.
