# R106/R107 receive threshold candidates — rejected

The threshold candidate was intended to keep the original read path below eight clients and use the shared spare only at connection scale. It passed the 41 router unit tests and protocol differentials, but both physical CPU screens rejected it.

| Candidate / condition | `user_1_1` daemon CPU | `user_8_1` daemon CPU | `user_1_0` daemon CPU |
|---|---:|---:|---:|
| R106 threshold, 4 low-connection windows | +2.38% | +2.12% | +1.59% |
| R106 threshold, 4 loaded windows +64 idle connections | +2.78% | +2.69% | +2.38% |
| R107 compile-time specialization, 4 low-connection windows | +1.23% | −0.56% | +1.08% |

R106 used a runtime `Option<&mut Vec<u8>>` in every receive loop; R107 specialized the branch with a const generic. R107 reduced the cost but still did not make all scenarios safe, and it had no high-connection confirmation. Neither candidate is accepted or remains in the working runtime.

AArch64 release symbol inspection is consistent with a code-generation effect: the accepted R103 build has `ubusd_rs::main` size `0xcc0` and no standalone `Client::read_message` symbol; the shared-wrapper build keeps the same main size but introduces the wrapper path, while the threshold build has main size `0x2cd8` and a standalone `Client::read_message` of `0x92c`. This is evidence about inlining/code layout, not proof of causality; the release bytes and all raw router windows are retained.

The candidate source has been restored to R103. The next minimal experiment is to test explicit inlining on the receive methods, with the same correctness gates and router CPU measurement. No Rust/C language-limit conclusion is justified.
