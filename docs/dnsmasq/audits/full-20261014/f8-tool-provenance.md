# F8：TFTP 审计报告的源码归属

修复基线：`e9d89b17d72a58b723cce88038ceaa1be58d7f8c`。

`audit_20261011_tftp.py` 不掌握候选 ELF 的构建收据，却在每份报告中写入固定
`source_commit=3e7df6c1cc45b74f0430e5460379713900172cb4`。本次删除该字段，
继续记录从实际文件计算的 C ELF、Rust ELF 和工具 SHA-256。源码归属应由
另行核验的构建收据建立；未增加无法验证的 commit 参数。

## 独立复现

只读核对已有 fresh 报告
`private/full-audit-20261014/dhcp/tftp-01.json`：报告 SHA-256 为
`4b1695ba33ca29f9f5517d7f10ea99819e4eb3d6c3a7f0e81abd18cccaddf441`，
Rust SHA-256 为
`e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0`，
但 `source_commit` 仍是上述旧值。该报告的精确 C SHA-256 为
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
这项只读核对不算重新执行其 24 个 TFTP 场景。

另以两份不同的合成输入运行修复前后的真实 `main()` 报告组装路径，仅模拟
服务执行、命名空间授权和 ELF 启动边界，没有启动服务或发网络报文：

- 修复前：两份报告的 Rust SHA-256 不同，`source_commit` 都是同一个旧值。
- 修复后：两份报告都没有 `source_commit`；C/Rust/tool SHA-256 均与输入
  文件一致；case count、match count 和 verified 汇总保持正确。
- 相邻边界：C 文件 SHA-256 不匹配仍在任何服务探针执行前被拒绝。
- `py_compile`、`--help` 和 `git diff --check` 通过。

检查器与输出保留在本修复 worktree 的 `private/f8-metadata-validation/`：

| 文件 | SHA-256 |
| --- | --- |
| `check.py` | `58229ffaf6239de94916ef7030eb51a550538350b969e8b682f7a7b5511a3afe` |
| `before/summary.json` | `730c8c4c359db41378fc53a5a6d9d22d3ec23fdaa03a6819376e06d1c3cff537` |
| `after/summary.json` | `078178f9fc8a2b1d590bd831c667b9825c35ac138693258492dcdb6f23db224b` |

本次没有产品构建、TFTP 服务重跑、物理路由器操作或 push。
