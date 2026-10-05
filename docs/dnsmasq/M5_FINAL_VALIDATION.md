# M5 最终统一验收准备

这是准备材料，没有执行最终资格。最终产品和剩余五个消费者仍由主代理
收尾；不得把当前单族旧成功结果填进最终报告。

`m5_final_validation.py` 使用一个冻结 ELF，写出全部结构化 argv，再逐阶段
执行。每次尝试独立保存，失败不覆盖；输入/工具/运行快照变化立即拒绝。
family registry 当前有 38 组、44 条完整原驱动命令草稿，`complete=false`
有意阻止尚未核对最终驱动的清单变成资格。

## 最终输入

从 `tools/dnsmasq/m5_final_inputs.example.json` 复制到 ignored/private，填写：

- 最终 source archive 对应的完整 commit/epoch、immutable release ELF/SHA
  与 `oracle_build.sh` 的 `build.json`，以及带真实 git archive PAX commit 的
  `source.tar`。构建设 `ORACLE_BUILD_LINK_MAP=1`，
  TFTP 的真实 malloc fault 调用需要与本 ELF 同次构建的 `link.map`。
- 将 `m5_final_families.draft.json` 对照最终各 owner 的工具刷新完整 scope、
  默认全部案例及 completion predicate，确认覆盖所有原功能族后设
  `complete=true`。不得选择 reference-only/partial，也不得引用旧 result。
- `deferred-review.json` 和 `safety-review.json` 绑定最终 `source_commit`，
  `complete=true`、`ordinary_unresolved=[]`。前者逐项记录处理、精确 C
  位置、理由与证据；后者记录 SAFETY、网络/定时 unwrap/expect、额外 Mutex
  的审查与处理。静态审查不能替代实际运行资格。
- 两个不同且可用的 CPU。主代理协调 Oracle 排除其他构建和测试负载；
  控制器在资源阶段持有唯一 Cargo 锁并检查外部测试/构建进程，但不能替代
  主代理对其他主机负载的协调。

现存资产已经 read-only 核对，路径和 SHA 在 `m5_final_assets.json`。
精确 image root 为
`/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`。
原运行快照为 `/home/ubuntu/dnsmasq-real-startup-20261001/source/rootfs`，
真实配置在 `var/etc/dnsmasq.conf.cfg01411c`，不是 `etc/config/dhcp`。
M2 plan、stock APK、两个 variant APK 与五个 solver dependencies 均仍存在。
准备时再核对全部源文件、工具、image/runtime 文件、SDK 工具/归档及资产。

## 可回放命令

将准备工具合入最终源码后，使用唯一共享 target 的构建入口：

```sh
ORACLE_BUILD_LINK_MAP=1 sh tools/dnsmasq/oracle_build.sh SOURCE PRIVATE_RELEASE release
python3 tools/dnsmasq/m5_final_validation.py prepare --inputs PRIVATE_INPUTS_JSON --out SOURCE/private/m5-final
sudo -n python3 tools/dnsmasq/m5_final_validation.py run --manifest SOURCE/private/m5-final/identity.json --phase families
sudo -n python3 tools/dnsmasq/m5_final_validation.py run --manifest SOURCE/private/m5-final/identity.json --phase m2
sudo -n python3 tools/dnsmasq/m5_final_validation.py run --manifest SOURCE/private/m5-final/identity.json --phase fuzz-build
sudo -n python3 tools/dnsmasq/m5_final_validation.py run --manifest SOURCE/private/m5-final/identity.json --phase fuzz
sudo -n python3 tools/dnsmasq/m5_final_validation.py run --manifest SOURCE/private/m5-final/identity.json --phase resources --exclusive-window
sudo -n python3 tools/dnsmasq/m5_final_validation.py run --manifest SOURCE/private/m5-final/identity.json --phase pressure --exclusive-window
sudo -n python3 tools/dnsmasq/m5_final_validation.py run --manifest SOURCE/private/m5-final/identity.json --phase package
sudo -n python3 tools/dnsmasq/m5_final_validation.py run --manifest SOURCE/private/m5-final/identity.json --phase lifecycle
sudo -n python3 tools/dnsmasq/m5_final_validation.py summary --manifest SOURCE/private/m5-final/identity.json
```

`SOURCE`、`PRIVATE_RELEASE`、`PRIVATE_INPUTS_JSON` 是上述实际冻结路径。
每个运行输出必须在对应 SOURCE/private 下，老工具保持其路径边界。
控制器统一以 root 执行，namespace 检查需要它；fuzz/SDK build worker 用
`runuser -u ubuntu`，避免污染唯一 Cargo/SDK 缓存的所有权。
独立功能族可用重复 `--family FAMILY_ID` 分组并行，每组有独立 fresh
namespace/output。只保存 `family:<id>` completion；所有 registry IDs 的
完整 steps 在同一 source/ELF/manifest/tools 身份下通过后，才 aggregate 为
`families`。completed.json 更新用 flock 和 atomic replace，partial 不能让
package 前置门通过；失败会撤销该族旧 completion。
失败复跑使用 `--attempt 2` 等新编号；旧失败原样保存。

阶段门槛：完整 M2 的七个 DNS profile、四个实际 DHCP profile、两侧完整
lifecycle（含 odhcpd）；三个 native instrumented fuzz ELF 各实跑 1800 秒；
mixed 与可证明 4096 条 live A 记录的 full-cache 各实跑 300 秒；两侧
ENOSPC/EMFILE 恢复；APK 的完整真实安装/升级/卸载/回滚及变体互斥。
pressure 的 `300` 是每侧 deadline，不冒称实际暴露 300 秒。

fuzz 通过 `oracle_build.sh ... fuzz` 使用同一
`/home/ubuntu/dnsmasq-cargo-target` 与同一锁，先清理 native profile 的三个
package，再复制实际 instrumented ELFs、输入 SHA、锁和 nightly 工具身份。
它们来自同一源码，但与交付 musl ELF 是不同产物；只 build/no-run 不算通过。
cargo-fuzz 0.13.2 的本机 help 与 [上游命令文档](https://github.com/rust-fuzz/cargo-fuzz)
已核对。实际三轮 fuzz 总计至少 90 分钟。

300 秒 full-cache 通过后，可选
`--phase full-cache-600 --exclusive-window` 进一步核对内存稳定性。
这不是 M6 性能窗口，也不是本次五分钟退出条件的替代。

## 包与报告边界

预算固定为原 ELF 1,000,000 字节和 APK 700,000 字节，没有
`user_accepted_elf`。包工具先产出并核对 APK/ELF，然后才可能因 size-target
返回失败。控制器只允许已验证 artifact identity、已恢复 SDK recipe、且
失败仅为 size-target 的包继续隔离生命周期；包的预算检查仍失败，用户
尚未接受新增体积。其他失败立即停下。SIGTERM/SIGINT 现在会使包工具展开
recipe context、恢复 SDK recipe 并留下失败 manifest。

`summary` 产出 `summary.json` 和 `M5_REPORT.draft.md`，比较 M4 的
1,159,280 字节、2,676 KiB。最终报告仍须补齐全部族、deferred/SAFETY
审查、资源趋势和失败归因，再交用户决定体积。M6 只允许准备冻结协议；
没有执行正式性能，也没有操作物理路由器，未经 M7 不称生产验收。

原始数据在 canonical `private/dnsmasq-rewrite/evidence/M5/` 统一保存。
用 `m5_option_matrix_archive.py pack/verify/prune` 全 SHA+metadata 回拷验证
后才清远端；包含失败、最终 source/ELF、APK、完整 overlay upper 与命令。
