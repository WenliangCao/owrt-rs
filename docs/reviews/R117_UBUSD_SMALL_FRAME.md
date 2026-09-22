# R117 ubusd 小帧 owned-body 消融

日期：2026-09-22。R117 是隔离 worktree `codex/r117-smallframe`，基于 R115
`b28dbc8`，源码提交 `f8bc4f7`、测试修订 `c87f3ec`。生产路由器保持 C，候选从未安装。

## 假设

R113/R115 的正确性修复要求 prefix `recvmsg` 严格停在 12 字节，正文用不带 ancillary
的 `read`，否则会重新引入跨帧 FD 错配。R117 保持这个边界；prefix 完成后按长度分配
owned `Vec`，正文直接写入该 Vec，并跨 readiness 保存 `got` 与 FD。这样去掉了 R115 的
共享 4096 字节 scratch 完成后再 `to_vec()` 的复制，但小帧从 `Cow::Borrowed` 变成
`Cow::Owned`，每帧分配成本重新出现。

## 正确性与构建

- Oracle release 交叉构建成功，候选 SHA-256：
  `dcee8055783bdbacae6e72880356eeea8904e219e20faf1fd8984ea22c7a28a5`。
- aarch64 musl 单测 **45/45** 通过。
- 覆盖了 prefix 分片、正文分片、完整小/大帧、bundled frames、正文 FD 丢弃、prefix
  FD first-wins/关闭和多帧 FD 归属；现有 server 事件、lookup、背压和注册测试保持通过。
- 路由器 pilot 前后健康、boot/config/挂载/生产身份均相同，候选未安装，清理通过；
  生产身份前后仍为 C。原始记录保存在 ignored `private/r117-smallframe/pilot-low/`。

## 路由器 pilot

AX3000T，精确 C 对照 R115，user-event workload，单块交错，每段 1000 次、warmup 2000，
固定 CPU。结果是描述性信号，不是最终性能验收：

| lane | daemon CPU 相对 R115 | total CPU | wall |
|---|---:|---:|---:|
| user_1_1 | +3.66% | +1.79% | +1.75% |
| user_8_1 | −0.28% | −0.23% | +0.24% |
| user_1_0 | +3.08% | +1.51% | +0.83% |

没有出现同号改善；`user_1_1` 和 `user_1_0` 反而回退。按预先的停止规则，不再启动
64 客户端和多窗口验收，R117 不进入候选排名。

## 结论

R117 证明了生命周期设计可以在不破坏 FD 语义的情况下直接完成 owned body，但没有证明
它在路由器上更快。它保留为可追溯的失败消融；R115 仍是当前正确性开发基线，生产仍为 C。
