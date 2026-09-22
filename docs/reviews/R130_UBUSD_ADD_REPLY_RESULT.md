# R130：ADD 回复合并的路由器实测结果

R130 在精确 AX3000T 上完成了 18 个新隔离窗口：C、R124、R130 的六种排列，每方六窗；每个窗口包含
1/16 方法注册和四条严格 lookup/invoke 护栏，注册每窗 5000 次、20 次预热。daemon 实际固定 CPU1，
caller/provider 固定 CPU0，argv0、ELF、PID starttime、清理和生产身份均逐窗核验。生产进程始终是 C，
18 个窗口全部通过健康与清理检查。

R130 的代码变化只在成功 ADD 且无 monitor 时把 DATA 与紧接的 OK STATUS 交给已有合并发送路径；REMOVE、
monitor、删除通知、FD 和排队边界保持原路径。Oracle 机制审计已确认 121 个成功 ADD 各少一次 `sendmsg`，
R124/R130 分别为 488/367 次；总字节数和逻辑帧数相同。

## R130 相对 R124

| lane | mean | p50 | p95 | p99 | daemon CPU/op | caller CPU/op |
|---|---:|---:|---:|---:|---:|---:|
| register 1×8 | −0.25% | −1.20% | **+6.87%** | +3.60% | −5.96% | −2.37% |
| register 16×8 | −0.09% | −0.53% | +2.16% | −0.94% | −3.66% | −1.42% |
| exact lookup 护栏 | −0.62% | +0.29% | −0.53% | +0.46% | −0.80% | +0.06% |
| all lookup 护栏 | −0.54% | −1.34% | −1.08% | +0.67% | −3.13% | +0.11% |
| prefix lookup 护栏 | **+1.38%** | +0.21% | **+5.50%** | +1.05% | +1.10% | +0.99% |
| invoke 护栏 | +0.85% | −0.15% | +5.52% | +6.62% | +0.35% | −0.76% |

这些是六个三方 block 的配对中位描述值，不是总体显著性或等价性检验。冻结工程门要求两个注册 mean lane
六块全降且中位至少 −3%；R130 未通过。其注册 1×8 的 p95 中位回退超过 5%，prefix lookup 护栏的
p95 也触发了共享 helper 回退门，因此 R130 **不接受为 R124 的新基线**。

相对 C，R130 仍保留 R124 在 lookup/invoke 上的优势；这不能抵消它相对 R124 未形成稳定注册收益，
也不能把一次少 syscall 的机制证明写成整体性能胜出。

完整逐窗原始数据、延迟数组、CPU、内存快照、身份和健康校验保存在被忽略的
`private/r130-add-reply/router-01/`；派生摘要见 [r130-ubusd-registration-results.json](r130-ubusd-registration-results.json)。
机制阶段见 [R130_UBUSD_ADD_REPLY_MECHANISM.md](R130_UBUSD_ADD_REPLY_MECHANISM.md)。
