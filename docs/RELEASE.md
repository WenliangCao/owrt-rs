# 集成固件的发布与维护

2026-10-18 更新：新增 odhcpd-rs 组件的下一版本改为
**v0.3.0 / `0.3.0-r1` / `native-eleven`**。最终 SDK `589226a1…` 的完整
10 项指标真机对照已通过；40 个正式配对中 39 个改善、1 个 Renew 在噪声内，
没有退步。后续镜像构建、有限客户端试运行、刷机与发布已获用户授权，尚待执行，
无需重复请示；不再追加性能轮次。PR #1 仍为草稿，未合并、刷机或发布；
现网 v0.2.3 和 C odhcpd 未变。
新配方有十一程序、两个 dnsmasq 集成文件、十三份 C 恢复文件，保留原 odhcpd
init、配置和 `odhcpd-update`。

配方绑定 source `162d9ba8`、SDK CI `39122603394` 的 802936 字节静态 ELF，
SHA256 `589226a178668c0e53fa8db5ff726e2b4e69464f9521355fad229b1862c3043e`。
最终全指标正式中位数 C/Rust：空闲 CPU 18.0509/0 µs/s，Renew
574.12375/221.767 µs，更新 CPU 2.30896075/1.6476925 ms，3 个 NA 租约时
RSS 1106/806 KiB（Rust 为 C 的 72.9%）。空闲 0 仅指测量窗口内无进程 CPU 增量。
整批 14 个样本、218.668192 秒、498 份原始文件哈希核验通过并归档；生产 C 的
PID/boot、配置与客户端健康保持不变，任务临时材料已清理。见
[最终全指标结果](reviews/ODHCPD_FINAL_FULL_AB_RESULT_20261018.md)。

[两项复测](reviews/ODHCPD_IDLE_RENEW_RESULT_20261018.md)和
[首批停止报告](reviews/ODHCPD_DEVICE_AB_RESULT_20261018.md)保持原样。
之前提前启动的镜像 CI `39123811190`（source `346470cd`）已取消；最终门通过后
再构建 v0.3.0 镜像，版本和 SDK 绑定不变，不增加产品优化。

此前 v0.2.4 候选的测量、镜像与历史报告保持原版本和哈希，不重命名为 v0.3.0。
其 Fable 修复 ELF 已完成 129 项 SDK 实包检查、完整镜像夹具及 123.739 秒真实
客户端短时试运行，确认后已恢复 C；见[Fable 候选结果](reviews/ODHCPD_FABLE_RESULT_20261018.md)
与[当时的集成报告](reviews/ODHCPD_NATIVE_INTEGRATION_20261018.md)。这些既有功能
证据不替代新 SDK 的资格或 v0.3.0 的正式构建资格；下方历史版本的验收与回滚目标
同样保留其原适用范围。

2026-10-17。当前配方交付十组件统一 **`v0.2.2`**，同一正式 CI 镜像已完成一次保配置部署与健康观察。生成一个小米 AX3000T sysupgrade 镜像，十个 Rust 程序直接安装到 OpenWrt 标准路径，由统一 **`owrt-control-plane 0.2.2-r1`** APK 管理；dnsmasq 的既有 init 与 ACL 随程序成套安装。正式镜像不包含绑定挂载、boot-enable 标记、试验采集器或临时部署守卫。刷写仍需明确授权与当次恢复核验；已有当次刷机授权不重复询问。构建成功不代表真机验收完成，实现与验收见[统一报告](reviews/CORE_SAFE_20261017.md)，现场记录见[v0.2.2 部署报告](reviews/DEPLOYMENT_V0_2_2_20261017.md)。

适配范围固定为 OpenWrt **25.12.5**、`mediatek/filogic`、`xiaomi_mi-router-ax3000t`。[配方](../packaging/image/native-25.12.5.json)固定标准路径、C 原件哈希、原软件包所有者及 dnsmasq 的构建输入。[镜像配方说明](../packaging/image/README.md)描述安装与迁移约定。

历史版本保持原身份与验收范围：首份九组件镜像 [AX3000T Rust9 v0.1.0](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/ax3000t-rust9-v0.1.0) 使用 `0.1.0-r2`，完成保留配置刷写和物理断电复测，见[镜像验收](reviews/NATIVE_IMAGE_20260929.md)与[部署记录](reviews/NATIVE_DEPLOYMENT_20260929_RESULT.md)。[v0.1.1](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.1.1) 使用 `0.1.0-r3`；其[快速部署记录](reviews/DEPLOYMENT_V0_1_1_20261009_RESULT.md)明确未执行断电测试。两者均仍使用原版 C dnsmasq，不能把十组件资格倒填给历史版本。现役 v0.2.2 的整镜像回滚基线为 [v0.2.1](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.2.1)。

## 安装布局

| 组件 | 镜像内的实际程序路径 |
|---|---|
| procd / ubusd / netifd | `/sbin/procd`、`/sbin/ubusd`、`/sbin/netifd` |
| rpcd / logd | `/sbin/rpcd`、`/sbin/logd` |
| uci / reload-config / fw4 | `/sbin/uci`、`/sbin/reload_config`、`/sbin/fw4` |
| httpd | `/usr/sbin/uhttpd` |
| dnsmasq | `/usr/sbin/dnsmasq` |
| odhcpd（v0.3.0 新增） | `/usr/sbin/odhcpd` |

沿用 `log`、`rpcd`、`network`、`uhttpd`、`odhcpd` 服务。httpd 使用原启动脚本生成首次证书、读取 `/etc/config/uhttpd`；原 log 脚本保留 logread 的文件与远程日志配置。dnsmasq 使用已验收包中的 `/etc/init.d/dnsmasq` 和 `/usr/share/acl.d/dnsmasq_acl.json`，这两个文件也是升级与恢复身份的一部分，不能只替换 ELF。内核、驱动、无线 handler、DHCP 客户端、dropbear、BusyBox、LuCI、apk 和 sysupgrade 执行面保留。

APK 的 `replaces` 与 `replaces-priority` 指定十一个程序及两个 dnsmasq 集成文件归 `owrt-control-plane` 所有；原十个软件包继续提供其余文件。依赖固定为验收过的原包版本，避免原包更新与恢复副本不匹配。原六套开关包、四个独立核心程序和 dnsmasq SDK APK 是构建中间产物，旧 `owrt-*` 开关包不会混入最终镜像。四个中文包从匹配 LuCI 修订重建。

`/usr/share/owrt-control-plane/release.json` 使用 `schema: 2`、`layout: native-eleven`，保存统一版本、源码提交、十一组件身份、两个 `integration_files` 及恢复清单哈希。配方 `version` 是最终统一 APK 版本；dnsmasq SDK 中间包的 release 编号与它分别记录。历史十组件镜像继续使用 `native-ten`。

v0.2.1 的另外九个 ELF、dnsmasq init/ACL 与 v0.2.0 逐字节相同。历史 v0.2.0 保持另外九个组件各自源码与 v0.1.1 一致，但共享 `components/ubus` 有已记录的 dnsmasq 所需接口与边界修复，见[最终 SDK 栈及 UBus 复验](dnsmasq/audits/full-20261014/final-sdk-stack-ubus-review.md)；不能将源码相同自动当作跨版本 ELF 相同。

## 正式构建

正式发布使用 [release-image](../.github/workflows/release-image.yml) GitHub Actions；canonical builder 是固定 Rust 工具链的 x86_64 Linux runner，见[决策 0018](decisions/0018-canonical-build-host-ci.md)。

| 阶段 | 工具与结果 |
|---|---|
| SDK 与六个包 | `tools/ci_build_image.sh` 校验官方下载，按既有 SDK 配方构建六个 Rust 程序及中间镜像 |
| 四个核心程序 | `tools/ci_build_core.sh` 在 `OWRT_CORE_INCLUDE_ODHCPD=1` 下构建 procd/ubusd/netifd/odhcpd，固定源码路径及工具链，核验 ABI 与归档身份 |
| dnsmasq | `tools/ci_build_dnsmasq.py` 核验冻结产品的源码和 SDK 配方 digest，通过原 SDK recipe 新编译；记录实际 ELF、init、ACL 及参考 ELF 比较 |
| 原位整合 | `tools/ci_integrate_image.sh`、`tools/native_image.py` 固定官方镜像与 LuCI 源码归档 SHA256，离线安装统一 APK 与四个中文包，以匹配 ImageBuilder 的 squashfs/sysupgrade-tar/fwtool 工具重新装配 |
| 内容审计 | 十一个程序、init/ACL、APK 所有权、十三份 stock 恢复文件、配置及其余原包内容/权限/所有者均检查；内核、CONTROL 与固件元数据逐字节比较 |

最终根文件系统来自固定 SHA256 的官方镜像，避免普通 ImageBuilder 从滚动软件源连带更新无线脚本、LuCI 或库。缺失工具、构建输入身份漂移、所有权或未批准执行面变化都会使流程失败。dnsmasq 当前版本的 canonical 参考为 `0421a5d02a4b5e8fb23c60572f0de113628fe1b2d88ebc92485a9359d9d80244`；正式 CI 必须新编译并核对完整哈希，不能偷换为参考二进制。固定 PGO 从独立[构建输入 Release](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/dnsmasq-k-pgo-inputs-20261017)下载并核验；SDK 构建槽路径也是 Cargo 外部依赖身份的输入。v0.2.1 的 CI 已精确复现 K；v0.2.2 的统一 generator/use 已完成且 0 PGO missing/mismatch，整镜像重建仍必须逐字节复现新参考。历史 v0.2.0 发布 ELF `8472be5a…` 与早期性能 ELF `50e591a9…` 的资格仍分别记录，不能混用；本轮 v0.2.0/J 直接比较使用实际 `8472be5a…`。

可先在 Actions 页面选择已审阅分支，或执行：

```sh
gh workflow run release-image.yml --ref <reviewed-ref> -f openwrt_version=25.12.5
```

普通 `workflow_dispatch` 只生成 Actions artifact。Linux 的 `make ci-image VERSION=25.12.5` 运行相同完整构建链；`tools/release.sh apk|image` / `make apk|image` 是旧六组件配方的研究入口，不是当前集成发布入口。

最终产物在 `work/native/out/`：

- 一个 `*-sysupgrade.bin`、一个 `owrt-control-plane-*.apk` 和四个匹配中文 APK。用户安装整个固件；统一 APK 是离线装配输入，不支持在线替换 PID1/总线。
- `manifest.json`（`schema_version: 3`、`deployment_layout: native-eleven`）、`binary-sha256.txt`、`SHA256SUMS`，固定镜像、包、十一个程序及配套文件的身份。
- `build-inputs.json`、`dnsmasq-build-manifest.json` 和构建日志，记录正式输入、工具链、SDK 实际产物与验收参考比较。

失败流水线另存诊断日志和已生成的候选镜像；未通过的候选不作为发布完成证据。

## v0.2.2 统一验收与一次部署

十组件以 `research/core-safe-20261017` 为整合主线，一起验收、正式构建并最终只刷一次。
配方 `0.2.2-r1` 绑定 procd 修复 `d644eda4`、core CI `39050152457` 的实际 ELF；
其中另外八个 ELF 与 e212/core CI `39047139959` 逐字节相同。DNS 仍绑定 e212 的
canonical use CI `39048357460` 实际 ELF。共享 platform、ubus、锁文件和构建槽
都在新 DNS 的 212 输入闭包中；旧 a97 独立候选及 profile 不转授给整合版。

正式 [CI 39050957718](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/39050957718)
从 `598b19a77021fef9abf62048d5c1e5b01c6c147c` 重建并精确复现十个 ELF，最终固件
13,783,328 B、SHA256 `af05e9325e43b4961bb332aa8d004f9141a040d88ee87c7f77515e628406693d`。
完整正确性、整镜像离线恢复与启动检查通过。按用户最终指示，物理性能范围缩为四场景
各三对及十次启动，没有追加旧大矩阵；结果见[派生数据](reviews/V0_2_2_SHORT_REGRESSION_20261017.json)。

同一镜像完成一次保配置刷写，连续 184 秒客户端健康确认后，再取得 121 个点的 600 秒
资源观察及 21/21 组健康检查通过。没有额外普通重启或断电测试。当次备份与精确 v0.2.1
回滚镜像在刷前离机核验，临时自动回退用于此次验收。主分支、标签和 Latest 仅在实际
部署验收通过后推送；标签固定上述构建提交，后续报告不移动它。发布资产保持 CI 原字节，
沿 v0.2.1 的短时 workflow 停用/finally 恢复协议避免 tag 重建覆盖，再重新下载核验。
具体实际结果见[部署记录](reviews/DEPLOYMENT_V0_2_2_20261017.md)和[发布说明](reviews/RELEASE_V0_2_2_20261017_NOTES.md)。

DNS `frozen-use` spec 保留产品提交、冻结时间、完整文件哈希/count/digest、实际 ELF
SHA256/字节数、profile URL/SHA256/字节数和训练来源。中间包仍为 `package_release="4"`，
最终预算 2.5/1.4 MB。PGO 槽为
`/home/ubuntu/owrt-unified-v022-20261017/private/dnsmasq-sdk-build-slot`。
九个非 DNS 条目也各有 `reference_elf_sha256`；native 整合拒绝漏项和任一重建漂移。
[统一 PGO 链](dnsmasq/CANONICAL_PGO_PIPELINE.md)保留 generator/use 的独立来源。

正式 checkout 重新编译；manifest 的 `source_commit` 是统一构建提交，DNS 的
`accepted_product_commit` 和 `source_date_epoch` 保留原产品身份与 Git 时间。
这些既有字段是构建归属，不代替硬件接受记录。首份 `34300d29` 镜像因 procd
漏收独立会话子进程被拒绝；修复后 R71 计数恢复 `1→2`、R83 恢复 11 次，
最终 `598b19a7` 镜像已重新构建并完成整栈验收。完整 Git 历史用于核验冻结时间；后续
版本/报告提交不改变 DNS 打包时间。native 整合再次核验 ELF SHA、大小和 profile/slot，
不把 diagnostic candidate 输出直接装入镜像。

身份测试现固定新的 212 输入与 `0f87482e…` digest，工作树漂移负控仍保留。另九组件
原路径、C 身份、包所有者及程序名的历史摘要不变；新 ELF 参考另由九项漂移负控覆盖。
主 CI 的 DNS 隔离测试、工具/镜像/benchmark 检查仍须通过。

相对 v0.2.1，九个 SDK ELF 总计 7,762,326 → 7,774,614 B（+12,288 B）；新 DNS 为
2,308,899 B（+12,288 B），十项合计 **+24,576 B**。该数不是 RSS、压缩镜像大小或性能；
这些体积变化不替代短回归结论；七个常驻服务的资源另有实际观测，三个 CLI 不列常驻 RSS。

## v0.2.1 发布与部署

实际构建为 [run 39007479025](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/39007479025)，
源码 `867c9c53d65b03d5d8266df278a03b87b5b791af`。本次顺序由用户明确指定：先推 release
分支进行正式 CI，本地 main 整合；同一 CI 镜像保留配置刷机、正常重启、白天 3600 秒
流量及资源观察通过后，才推 main/v0.2.1 并标 Latest。标签只指向实际构建提交，文档提交不移动它。

沿用下方历史版本的短时 workflow 停用/finally 恢复和延迟 tag run 检查，避免 tag 自动重建
替换已验收资产。10 份 CI 资产加原始 `CI-SHA256SUMS`、发布说明和公开名称校验和，共 13 份。
发布后重下载核对全部字节，再将同一个 Release 转正。

恢复基线是当次离线核验的 v0.2.0 镜像与独立配置备份；临时自动回退守卫经离线验证后
随保留配置进入新启动，最终验收后移除并生成干净新备份。正式镜像本身不包含该守卫。
当前结果见[部署报告](reviews/DEPLOYMENT_V0_2_1_20261017.md)，收益及限制见
[发布说明](reviews/RELEASE_V0_2_1_20261017_NOTES.md)。

## 历史 v0.2.0 发布、部署与转正

本次使用通用 **`v0.2.0`** 标签，采用 v0.1.1 已用过的“正式 CI 产物先完成核验，再发布同一字节”路径：

1. 提交审阅后的代码与公开文档，确认 main 不包含用户未提交的 `docs/prompts/`、私有备份或镜像，推送 main。以该精确提交执行 `workflow_dispatch`，完成正式 CI 构建，核对已完成的有限离线证据。此前阻断发布的 ubus 生命周期测试已修复、70 项通过；`ded73bae` 对应完整 host CI `38636080350` 已成功，原 namespace 环境问题与修正记录保留，不为本次继续扩大验证。
2. 下载并逐项核验该 run 的原始资产，固定构建提交、run ID、manifest 与 SHA256。失败先修复并在新提交重新构建，不能提前占用不可移动的正式标签。
3. 记录 `release-image` 原启用状态，确认没有 active run，再仅为推送标签的短窗口暂时停用该 workflow。创建 annotated `v0.2.0`，直接指向已通过的实际 CI 构建提交，推送标签；无论后续动作成功或失败，都在 `finally` 清理中恢复原 workflow 状态并核验。短窗口停用不能保证阻止 GitHub 延迟处理标签事件；恢复后须检查并取消多余 tag run，核验其未上传资产或创建 Release，不能借此更换构建输入或资产。
4. 创建 `v0.2.0` GitHub Release，保持 **prerelease、`latest=false`**，上传已通过的同一批 CI 字节；可按约定改显示文件名，但须重核内容哈希及校验和。下载公开附件再核验，然后使用其中同一个镜像部署。不得替换为本机构建，也不得因后续文档提交移动标签。

本次最终构建是 [run 38636115402](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/38636115402)，提交 `ded73bae75f44269c93366593481d866a2e68e35`；35 项 CI 校验和已全部通过。发布保持镜像与五个 APK、四份身份清单的原始字节；CI 原 `SHA256SUMS` 改名为 `CI-SHA256SUMS`，补充 `RELEASE_NOTES.md` 和覆盖发布附件的外层 `SHA256SUMS`，共 13 个附件。构建日志保留在 Actions artifact。完整身份与当前真机状态见[部署记录](reviews/DEPLOYMENT_V0_2_0_20261014.md)，后续文档提交不改变标签目标。

[v0.2.0](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.2.0) 于 2026-10-14 21:12:07 UTC 发布为 prerelease，完成同一镜像保留配置刷写、正常重启、用户断电重启、有效 600 秒资源采集和清理后，于 21:38:46 UTC 核验为正式 Latest。部署保留明确的客户端诊断限制：Mac UDP DNS 在刷前 C 与刷后 Rust 均超时，Rust 健康脚本首组后停止，只执行 1/20 组，不能称完整健康窗口通过；组件/配置、路由器 DNS、客户端 TCP DNS、DHCP、双栈、LuCI 及用户 Wi-Fi 使用验收见[实际报告](reviews/DEPLOYMENT_V0_2_0_20261014.md)。GitHub 把四个 LuCI 中文 APK 公开名称中的 `26.180.75667~128a781` 改成 `26.180.75667.128a781`，字节及包内版本不变；外层 `SHA256SUMS` 使用公开名称，原 CI 清单保持原始名称和内容。

本次恢复 workflow 后 GitHub 延迟触发了 [tag run 38638003434](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/38638003434)，已于 21:10:51 UTC 完成取消；正式整合、上传 artifact 和创建 Release 均跳过，继续使用已核验的 run `38636115402`。

临时关闭只影响发布触发入口，不改变产物身份；记录关闭前后的状态与时间，恢复后检查并处理误触发的构建。直接推送其他 `v*` 标签的默认 Actions 行为仍是自动构建并创建 **prerelease、非 Latest** 候选，不代表真机资格。本次说明列明新增 dnsmasq-rs、真实性能差异、已知边界以及实际部署验收范围。

按以下顺序完成本次部署，任何尚未完成的项目不能写成通过：

1. 保存当次完整配置备份到电脑 `private/`，核验可读取、内容与现场一致。保存并核验 v0.1.1 原镜像及其哈希，准备手动恢复路径。用户本次明确选择手动刷回 v0.1.1，**不安装自动回退守卫、不追加 Oracle 模拟或新验证**；既有离线测试只作为已经取得的证据。
2. 用[固定日常采集协议](dnsmasq/audits/deployment-v0.2.0-20261014/daily-protocol.md)记录现役 C **600 秒、每 5 秒一次**资源数据及低频健康。它只表示此时日常占用，不代表性能。
3. 告知预计断网时长，等用户确认后才进入断网操作。把发布的同一个镜像上传 `/tmp`，核对哈希并通过 `sysupgrade -T` 等当次预检；使用保留配置的刷写方式，不加 `-n`。
4. 核验十组件实际身份、init/ACL、配置保留、Wi-Fi、客户端 DHCP、IPv4/IPv6、DNS UDP/TCP、LuCI、WAN。按方案验证正常重启，并由用户执行物理断电重启后重复验收；需要人工步骤时等待真实回复。
5. 在稳定运行的 Rust 服务上用同一工具、同样 **600 秒**采集，报告服务年龄、CPU/RSS/FD/线程等日常数据。原始备份/日志/数据不进 Git，公开记录保留脱敏结果及证据哈希。
6. 失败时按已验证方案恢复 v0.1.1，记录原因，不转正。全部验收通过并完成部署报告后，清理本次上传/采集材料并核验最终状态，再晋升**同一个** GitHub Release：`prerelease=false`、`latest=true`。不重新构建、不换镜像、不移动标签。

晋升命令（仅在以上证据齐全后执行）：

```sh
gh release edit v0.2.0 --prerelease=false --latest
```

更新同一 Release 的说明，加入实际构建提交、资产哈希、部署/正常重启/断电结果和日常占用对照。后续观察自然续租、新设备入网、长期资源趋势，以及性能报告中两处原因未明尾延迟；短期验收不等于消除这些边界。

历史设备专用标签如 `ax3000t-rust9-v0.1.0` 保持不变。`tools/native_release_prepare.py` 的既有产物晋升流程仍是历史九组件节点的可追溯依据；不可直接假定其旧 schema 或固定恢复集合适用于本次十组件。v0.2.0 以当前 Actions 的 `native-ten` 正式资产和匹配的新验收记录为准。

## 保留配置与首次迁移

sysupgrade 默认保留选定配置，安装新系统后由原 preinit 恢复；它不保留整个 overlay。网络、Wi-Fi、密码、证书、DHCP 静态分配与定时任务通过配置备份迁移，不进入公共镜像。额外保留项由 `/etc/sysupgrade.conf` 和 `/lib/upgrade/keep.d/*` 决定，刷前实际清单必须核验。

旧分层部署曾禁用原 `log`、`rpcd`、`uhttpd`。首次采用集成布局时，`05-owrt-native` 在 sysupgrade 生成的 `10_disable_services` 之前移除这三个禁用命令并启用服务；其他服务状态保留。

`/etc/owrt-control-plane-layout` 的历史值 **`native-nine-v1` 有意保留**，由包内 keep.d 规则迁移。它表示“已经完成首次布局迁移”，不是当前组件数量；当前布局由 release manifest 的 `native-ten` 描述。改 marker 会误触发首次迁移，覆盖从 v0.1.1 升级用户的服务启停选择，故不随组件数量改名。正式固件没有后台试验守卫；本次临时恢复包与普通配置备份分别保存，验收结束再生成不含守卫的配置备份。恢复出厂丢弃 overlay 与个人配置，回到镜像内置 Rust 栈。

## 恢复路径

v0.2.0 起的 `/usr/libexec/owrt-stock/` 保留 **十二份**精确 stock 文件：十个 C 程序，加 C dnsmasq 原 init 与 ACL，保持相对路径。**`/rom` 中对应路径已是集成 Rust 版本，不能当 C 原件。**

SSH 可用，或进入 failsafe 并 `mount_root` 后，可运行：

```sh
owrt-recover-c
# 核对成功提示后另行重启；failsafe 使用 reboot -f。
reboot
```

工具先校验全部恢复文件、拒绝被绑定挂载的目标，准备并核验完整临时集合，再替换十二个路径；dnsmasq 必须与原 init/ACL 一同恢复。它不主动重启，不依赖 ubus/netifd，不修改用户配置。多次运行结果一致；十二次 rename 不是跨文件原子事务，中断可在 failsafe 重跑。

这条路径恢复精确官方 C 栈，**不等同于刷回某个历史固件版本**。v0.2.2 的版本回滚使用已核验 v0.2.1 镜像与当次配置备份；本次验收期临时守卫也以它为回刷目标。管理不可达时使用 failsafe/TFTP 救援路径。原版内核、早期 init、preinit/failsafe 和救援材料保留；Wi-Fi 管理获授权，网线不是普通刷写的前提，实际 failsafe/TFTP 见[救援手册](RUNBOOK_AX3000T_RECOVERY.md)。

## 验收边界

`tools/native_image_check.py` 在 aarch64 Linux 独立 namespace 与镜像副本中运行精确 sysupgrade 备份、preinit 配置恢复、首次迁移、后续原生升级、错误身份拒绝、完整 C 恢复及 APK 重装。原九组件历史通过记录不能自动升级为十二恢复项通过；本次须保存 `native-ten` 实际执行结果。`tools/native_apk_fixtures.py` 从精确原镜像文件清单重建原包载荷，供 `--no-scripts` 所有权重装；它们不是原始签名 APK。测试须确认已删除文件恢复，拒绝 APK 成功却跳过载荷。

`tools/native_boot_check.sh` 使用镜像内 PID1、总线及启动脚本验证模拟 LAN/WAN、RPCD、日志、HTTP/HTTPS、首次证书、UCI、reload_config、fw4。dnsmasq 还须验证实际最终 ELF 与 init/ACL 的 DNS/DHCP、helper/ubus、恢复与权限链路。物理无线、闪存写入、正常重启及断电行为由真机验收负责，隔离测试不能替代。

刷前须核验离线备份、正式镜像身份、本次回滚材料与机制和客户端健康。旧分层 `/rom` 假设及 `/root/r84` 不适用于集成镜像。首轮原生部署[冻结计划](reviews/NATIVE_DEPLOYMENT_20260929_PLAN.md)仅是历史依据，不能借用其旧 token、哈希或九文件集合。

## 后续 OpenWrt 版本

先引入精确新镜像及对应源码，在新 rootfs 上执行当前全部组件差分回归，再新增软件包列表与 native 配方。C 身份、原包版本、脚本、内核及恢复语义变化须逐项复核；只改下载版本号不足以完成适配。

跨宿主 TLS 差异的历史调查见 [R35](reviews/R35_RING_INVESTIGATION.md)。统一构建来源解决发布身份问题；包用于离线装配，不生成随机本地签名密钥。二进制与整镜像可复现性分别核验。
