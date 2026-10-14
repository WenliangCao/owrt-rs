# 修复方最终回交：2026-10-14

本轮收尾。最新产品候选为 **`340ed73e` / ELF `edb5b4f9…`**，已修复
无既有 TCP 时 hostsdir 内存不足导致的不完整发布。原 `19bd6162` 候选、
失败反例和所有独立分支均保留。**F10 条件性多 PTR/轮转兼容问题保持开放，
没有兼容豁免。** 没有合并产品到 main、push、部署或修改物理路由器。

独立审计已在 main 提交 `215fbb60` 的 `docs/dnsmasq/FULL_AUDIT.md`。
审计完成不是正式部署放行；基线 main、组合候选与后继定向修复分开评价。

## 冻结身份

| 层次 | 产品源码提交 | Oracle ELF | SHA-256 |
| --- | --- | --- | --- |
| 原审计基线 | `e9d89b17d72a58b723cce88038ceaa1be58d7f8c` | `/home/ubuntu/full-audit-20261014/private/release/dnsmasq-rs` | `e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0` |
| 保留的组合候选 | `19bd6162e1b33c92a1e5ea26e864497800c7cfed` | `/dev/shm/full-integrated-fix-20261014/private/release-final/dnsmasq-rs` | `fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b` |
| 后继事务发布修复 | `340ed73e83e58ba845e0a645eb21e9ead0d0f108` | `/dev/shm/full-inotify-fix-20261014/private/release-final/dnsmasq-rs` | `edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d` |

两份候选均为 2,089,440 bytes；各自 647 个 dnsmasq/ubus/packaging/tool 输入
与 Git 一致。此范围不替另外九个组件提供源码身份。精确镜像 C SHA 为
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
候选脚本 SHA 为 `dfa94d52cb132a181d78b8a0471b49868d9d3dd8bf9f79b00839edbd649f8b74`。

本地持久 tag：`audit/dnsmasq-full-19bd6162-20261014` 与
`audit/dnsmasq-full-340ed73e-20261014`。Oracle 原始路径没有覆盖；源码、ELF、
抓包、跟踪与构建日志另已备份到对应 worktree 的 Git 忽略 `private/`。

## 修复和证据提交

| 项目 | 产品提交 / 处置 | 证据位置与范围 |
| --- | --- | --- |
| F1 TCP hosts/config 深复制 | 独立 `936514cd`、`22fe5dd9`；组合 `7b8942bc`、`7ddb5439` | 独立 TCP 分支保留；19bd 的 50k/20TCP/64MiB、HUP 和 42 项快照已重新执行 |
| F1 暖轮转表首次查询深复制 | 独立 `2f658ea4`；组合 `eea4bf48` | 有界分页；原 60k/64MiB OOM 与修复/rolling 证据在 rotation 分支 |
| F2 hosts 重载 OOM/失败 HUP 缓存 | `68f96cf3`、`98bc6b58`；组合 owner 修复 `1d535cb9`、`19bd6162` | 旧反例、相邻余量、共享服务、缓存清除、恢复和旧 TCP 视图均留档 |
| F3/F6 自动恢复/上传路径 | 独立 `18d83527`、`fd62cf85`；组合 `592fe269`、`397cecb6` | 19bd 新跑 12/12 场景、39 次客户端健康；340ed 另跑 1 次真实中断、3 次健康检查 |
| F8 工具错误来源字段 | `dc733337`，独立工具分支 | 删除无法证明的硬编码 commit，保留 ELF/tool hash；未声称新跑 TFTP |
| F9 增量不完整发布 | **`340ed73e`**，独立 inotify 分支 | `28f0aee6` 原反例/19 组修复证据；`c5a1d74f` 同产物核心与回退证据 |
| F10 多 PTR/轮转 | **开放，无产品修改** | `c2e75c23` 大样本归因；`07e851be` 六行真实反例；`adf4861f` 成本和合同处置 |

19bd 的身份/单元收据提交为 `c2fbaf4e`，TCP/trial 收据为 `13fc6472`。
这些是文档/工具提交，不改变冻结产品身份。各报告均列精确 argv、工具 hash、
原始路径和备份 hash，可以从对应证据提交恢复，不依赖本会话文字。

## F9 修复结果和实际边界

旧 19bd 在初始 2000、替换 6000、VmSize +1024 KiB、无 held TCP 时，
完整读到 EOF 后在逐条索引组装中丢弃分配失败的记录，最终仍可能成功克隆并
发布不完整代。修复方独立复现四次；进程和控制 DNS/DHCP 健康，不能称为断网。

340ed 新增小型 fallible source-replacement helper，先在私有工作代完成移除、
来源路径和所有记录/祖先索引，再完成 daemon 发布副本；随后才更换两个 owner。
失败丢弃工作代，旧 owner 保持不动，不靠再次分配来恢复。瞬时保留旧代是明确
的内存取舍；没有放宽 RLIMIT_AS、cgroup 或改 allocator/profile。

- 19/19 新 inotify 运行通过：held/no-held × 2000/6000 ×
  +256/+512/+1024/无限制共 16 组，加原失败点三次重复。受限失败保留完整旧代，
  解除限制且无新事件时仍保持旧代，后续 close-write 恢复完整新代。
- 新源码 musl lib 789、bin 78、native allocator 9 通过；23 个 ignored 未执行。
  allocator 测试调用生产 helper，覆盖单点/持续失败、held/no-held、删除、重复、
  祖先索引、来源 metadata 和实际 publication clone。
- 新 ELF 50k/20TCP/64MiB+HUP、42 项快照通过。Rust cgroup peak 46,514,176 B，
  无 OOM；不据此声称绝对内存等于 C。
- 新 ELF held HUP+cache-expiry 在 +256/+512/+1024 三档全通过。
  配对驱动 exit 1 原样保留：C 低两档 ready UDP 超时，三档新 TCP short frame；
  C 存活、解除限制后恢复，未把 C 失败从分母删除或写成双方全过。
- 独立审计 `d24bc649` 验证原反例完整 census，`e7e0574e` 验证同 ELF Rust9
  23+5 管理/helper 路径；这是独立审计提供的证据，不冒充修复方新跑。

详细报告位于 inotify worktree 的
`docs/dnsmasq/audits/full-20261014/INOTIFY_TRANSACTION_FIX.md` 和
`inotify-fix/CORE.md`、`inotify-fix/trial/report.md`。

## F10 最终处置

原 188 条 A 顺序差异全部对应精确 C 的混合 `F_REVERSE` 组；四份 cache dump
共 240,000 条标志与源模型一致。六行最小真实夹具进一步证明：UDP/TCP PTR
同一地址，C 返回 `x.test` 与 `y.test`，旧 Rust 与 19bd 只返回 `x.test`；
TC=0，RCODE=0，邻界单 PTR 一致。独立审计还在原 main 和 340ed 确认少名。
因此 F10 是 **P2 条件性缺 PTR**，不能只写低影响顺序差异；没有错误 A 集合、
进程退出或 DHCP/网络中断证据。

完整修复涉及跨文件 bulk 临时链、不同的增量生命周期、多个 PTR owner、删除/
克隆/快照调用契约及 C 全局名字哈希遍历。仅翻转标记不能修复 PTR；为复制 C
复用 next 的行为引入更多状态，需要重新论证成本并验证资源门。按用户本轮
收尾范围，不扩展此产品改造，不假定 first-owner 行为获得豁免。
rotation 分支的 `F10_DISPOSITION.md` 记录具体选项、内存算术下界和未证明边界；
预备 contract 分支仍停在 19bd，没有产品修改。

## 保留与后续

所有活动/未合入分支保持原位，包括 r2、tcp、trial、rotation、integrated、
inotify、audit-f8 和 rotation-contract；没有删除或重写证据 refs。
当前部署资格仍受开放 F10、共有 APK 活进程切换/ubusd 恢复边界、体积预算及
最终打包/硬件长期验证等约束，详见独立 FULL_AUDIT。此次不追加无界测试，
不把 Oracle 验收转签为生产部署授权。

双方已验证的后续会话 key：修复方 `codex:06556d25-d420-4ace-87ae-565583e2baf4`，
审计方 `codex:0733ce73-c5e4-4743-9174-9bd3aa322a90`。
