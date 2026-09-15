# R93 RPCD glob candidate：AX3000T 四侧实机矩阵

2026-09-15。C/R89/source05 control/ASCII trailing-star candidate 四侧四轮，共 **288 个观测**，全部正确性、身份、统计和清理门通过。候选仍未合入。

单位：µs/请求；CPU 是被测 rpcd 自身 CPU。括号是 candidate 相对 R89 的变化。

| workload | C CPU | R89 CPU | control CPU | candidate CPU | candidate/R89 | candidate/C |
|---|---:|---:|---:|---:|---:|---:|
| uci_configs | 81.500 | 63.750 | 64.750 | 63.250 | -0.78% | -22.39% |
| uci_get_network | 222.250 | 180.250 | 180.250 | 180.750 | +0.28% | -18.67% |
| file_stat | 78.000 | 72.000 | 70.750 | 72.000 | +0.00% | -7.69% |
| session_access | 27.750 | 22.750 | 24.250 | 23.750 | +4.40% | -14.41% |
| uci_configs_c4 | 75.697 | 53.287 | 53.287 | 53.038 | -0.47% | -29.93% |
| uci_get_network_c4 | 200.199 | 149.402 | 149.402 | 151.892 | +1.67% | -24.13% |
| file_stat_c4 | 70.717 | 58.018 | 58.267 | 59.761 | +3.00% | -15.49% |
| session_access_c4 | 23.655 | 16.683 | 19.920 | 18.675 | +11.94% | -21.05% |
| uci_get_64 | 1515.000 | 670.000 | 655.000 | 657.500 | -1.87% | -56.60% |
| uci_get_64_c4 | 1536.058 | 661.058 | 644.231 | 649.038 | -1.82% | -57.75% |
| uci_get_authorized | 237.500 | 190.750 | 194.500 | 190.250 | -0.26% | -19.89% |
| uci_get_authorized_c4 | 215.637 | 159.861 | 161.853 | 160.608 | +0.47% | -25.52% |
| session_access_granted | 28.500 | 22.500 | 27.250 | 23.750 | +5.56% | -16.67% |
| session_access_granted_c4 | 24.402 | 17.430 | 21.663 | 18.675 | +7.14% | -23.47% |
| file_list | 458.250 | 233.250 | 236.750 | 238.250 | +2.14% | -48.01% |
| file_list_c4 | 423.307 | 202.440 | 203.685 | 206.922 | +2.21% | -51.12% |
| session_access_64 | 30.500 | 25.250 | 29.750 | 26.000 | +2.97% | -14.75% |
| session_access_64_c4 | 26.145 | 20.169 | 22.410 | 19.422 | -3.70% | -25.71% |

## 结论

- `session_access_granted`、`session_access_64` 串行及其大部分并发样本相对 source05 control 有清晰 CPU 下降；这与 ASCII 单尾 `*` 快路减少 CString 分配的源码假设一致。
- 候选相对正式 R89 仍不是全面胜出：普通 `session_access`、文件列表和 UCI 路径有持平或退步；拒绝路径和并发路径存在轮次方向混合。
- 不能把授权路径的收益推广成 rpcd 全面提速，也不能据此合入生产。下一步应保留候选，针对 denied ACL 与普通路径继续拆分计数，并比较整机空闲/内存影响。

## 身份与边界

- candidate `5d2dbbf67b6024306bc02232894a96b0fc7302818b499a2e0aef81c3acc4f1fa`；control `d78a752cb383abfbc3c2d0050e445e3742595706e0baf05af17c60d3fcd5d1a8`；依赖 ubusd `cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88`。
- N=20,000；四轮 Williams 交错顺序；每轮 4 sides × 18 workloads。
- 同一 frozen OpenWrt 原版依赖；生产路由器未切换 runtime。
- 四轮结果与逐样本原始归档在 `private/r93/rpcd-device-matrix-resumed-04/`；smoke 在 `private/r93/rpcd-device-smoke-resumed-04/`。
