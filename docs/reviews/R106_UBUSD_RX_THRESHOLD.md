# R106/R107 receive threshold candidates — rejected

The threshold candidate was intended to keep the original read path below eight clients and use the shared spare only at connection scale. It passed the 41 router unit tests and protocol differentials, but both physical CPU screens rejected it.

| Candidate / condition | `user_1_1` daemon CPU | `user_8_1` daemon CPU | `user_1_0` daemon CPU |
|---|---:|---:|---:|
| R106 threshold, 4 low-connection windows | +2.38% | +2.12% | +1.59% |
| R106 threshold, 4 loaded windows +64 idle connections | +2.78% | +2.69% | +2.38% |
| R107 compile-time specialization, 4 low-connection windows | +1.23% | −0.56% | +1.08% |

R106 used a runtime `Option<&mut Vec<u8>>` in every receive loop; R107 specialized the branch with a const generic. R107 reduced the cost but still did not make all scenarios safe, and it had no high-connection confirmation. Neither candidate is accepted or remains in the working runtime.

AArch64 diagnostic builds with release stripping disabled suggest a code-generation effect: the accepted R103 build has `ubusd_rs::main` size `0xcc0` and no standalone `Client::read_message` symbol; the shared-wrapper build keeps the same main size and also has no standalone receive symbol, while the threshold build has main size `0x2cd8` and a standalone `Client::read_message` of `0x92c`. The diagnostic .text bytes are NOT identical to the measured release .text bytes, although lengths match. Therefore these symbols cannot yet identify the exact measured instructions or explain the R105 regression. Disabling stripping changed build output; no causal attribution follows. The release bytes, diagnostics and all raw router windows are retained.

The candidate source has been restored to R103. The next minimal experiment is to test explicit inlining of read_message in the R106 threshold variant, with the same correctness gates and router CPU measurement. No Rust/C language-limit conclusion is justified.

R107 limitations: its frozen plan erroneously listed family_comparisons=1 for 12 metrics and referred to four lanes although three were specified. The derived report deliberately computes no interval or formal decision from those fields. Four exploratory ratios are retained for each of all 12 metrics. R107 had 41 native tests and validated event traffic, but did not rerun the full physical unit/protocol gates and cannot be accepted.
