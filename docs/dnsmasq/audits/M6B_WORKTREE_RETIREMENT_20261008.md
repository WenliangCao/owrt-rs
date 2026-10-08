# M6b 本地工具工作树退役记录 — 2026-10-08

本轮仅操作授权的已交付 M6b 工具树。原始保全完成后因产品差异排查暂停；恢复时重新核对 tip、status、archive tag、ignored 文件 SHA 和 metadata，再实际移除七棵树及对应任务分支。未访问 Oracle、未运行构建或测试、未改公共账本、用户 prompts 或非 M6b detached 树。

原始保全证明保持不变：

- [preservation manifest](../../../private/dnsmasq-rewrite/evidence/M6B/worktree-retirement-20261008/delivered-tools-01/manifest.json)，SHA256 `bc48c3f16a9c6f4c09837d86f47fe2edd5f3bc3cda1f7bbf5570f4c24dc2b771`。
- [completion manifest](../../../private/dnsmasq-rewrite/evidence/M6B/worktree-retirement-20261008/delivered-tools-01/completion-01.json)，SHA256 `a61c3ce0abda1cb11aeee283cafbd61f7a22a98d8ba6d6a7f1d5380b8834dd00`；包含逐条 remove/delete argv、exit、结果及仍注册的受保护树。

## 实际退役

每个 archive tag 已验证解析到以下完整40位 commit；所有 unmerged 历史提交仍由 tag 可达。忽略的缓存／构建产物在删树前完整打包，并逐文件复核 SHA、mtime_ns、mode、uid/gid 和 symlink/hardlink内容。

| 已移除工作树／分支 | 完整 tip | durable archive tag |
| --- | --- | --- |
| `m6b-a-caller-qualification` / `m6b/a-caller-qualification` | `16fb58b912ffb2a87af02b93f00a93a896e319b4` | `archive/m6b/retired-20261008-a-caller-qualification` |
| `m6b-a-primitive-adapters` / `m6b/a-primitive-adapters` | `22ef68954c96c1dbeefebef130dbcc63e1a8d051` | `archive/m6b/retired-20261008-a-primitive-adapters` |
| `m6b-a-tools-dependencies` / `m6b/a-tools-dependencies` | `0c976f77bd6de624e14a22690c1f0881eb021c32` | `archive/m6b/retired-20261008-a-tools-dependencies` |
| `m6b-apk-release-upgrade` / `m6b/apk-release-upgrade` | `3e7d1cc495370649320e2ecb3078bdc660924ff1` | `archive/m6b/retired-20261008-apk-release-upgrade` |
| `m6b-final-acceptance-recipe` / `m6b/final-acceptance-recipe` | `3baea941dff8bf2dcc979c198dc9e5271671c15a` | `archive/m6b/retired-20261008-final-acceptance-recipe` |
| `m6b-tcp-dns-work-release` / `m6b/tcp-dns-work-release` | `cce611916d651610fa13564f1fd8c2fe9f46a5d6` | `archive/m6b/retired-20261008-tcp-dns-work-release` |
| `m6b-udp-miss-kernel-attribution` / `m6b/udp-miss-kernel-attribution` | `4da1585db8dee4f4853b717c8998f6a646b5746b` | `archive/m6b/retired-20261008-udp-miss-kernel-attribution` |

`apk-release-upgrade` 的9个 pycache、`final-acceptance-recipe` 的12个 pycache，以及 `tcp-dns-work-release` 的1,972个 ignored target文件（430,624,438 B）全部保存在原保全目录的 ignored.tar.gz／ignored-files.json 中；没有只删除这些本地痕迹。其余退役树 tracked/untracked/ignored均干净。

## 保留

- `a-evidence-review`：原证明tip是408e10ae，恢复时已推进到 `156c00975be37f57f5b5c1026c4eee0e85af0f96`。新CPU gate文档不在原保全tip中，保留树和分支；旧408 archive tag也保留。
- `a-libtest-adapters`：root明确保留供后继工具修复，最新路径修复提交 `880ca97c8dcdd5852bec59670d0ac1308b5bf7d2`。
- `reverse-cname-family`、`reverse-import-direction-noa`：新的活跃接线／产品修复树。
- 所有A产品树、所有route树、两棵interface树、resource-diagnostic历史refs，以及resource-runplan／interleaved当前或潜在审查树全部保留。

移除后检查Git注册列表，七个精确路径均不存在、对应任务分支不存在、archive tags仍指向原tip。没有剩余针对这七条路径的失效记录，因此未运行全局worktree prune；不按年龄清理其他任务。恢复旧现场时先从对应tag创建新树，再按 ignored manifest 恢复所需原始产物。
