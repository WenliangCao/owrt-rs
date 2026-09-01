# Rust-native OpenWrt Control Plane：证据驱动执行计划

> 状态：H1 无拆机边界重规划完成；下一阶段 H1.4 offline preflight 尚未执行
> 版本：2.0
> 日期：2026-09-01
> 前置探索：[L0_DISCOVERY.md](L0_DISCOVERY.md)
> 输入规范：[IMAGE_INTAKE.md](IMAGE_INTAKE.md)

## 1. 文档用途

本文件是项目的执行控制文档，不是架构愿望清单。

- 阶段只能在退出门有证据时勾选完成；
- 代码完成不等于阶段完成；
- 未观察到的行为必须保持未知；
- 新证据推翻旧结论时，修改计划并保留决策记录；
- I0 完成以前，不建立完整 Rust control-plane 架构。

每次执行结束都要更新本文件的状态表或对应阶段报告。执行记录不能只写“测试通过”，必须
说明输入、命令/工具版本、输出、失败和证据边界。

## 2. 项目目标

项目最终要构建 Rust-native OpenWrt control plane，但实现路线由现有系统决定：

1. 以实际装机镜像作为部署规格；
2. 以该镜像匹配的 OpenWrt 和组件源码作为实现参考；
3. 以脱敏运行态作为行为权威；
4. 逐项识别哪些控制平面职责应保留、包装、适配或替换；
5. 保留成熟的 kernel、驱动和执行平面，除非具体证据证明必须改变。

本项目采用“源码先行”不是“源码替代证据”：先用最小部署身份选择匹配源码，用源码解释
系统和提出检查项，再用镜像证明实际部署内容，用运行态证明动态行为。

最终形态可能包含适配器、兼容层、drop-in daemon 或新的 Rust 组件。现在不预先决定它
一定是 sidecar、单体 daemon、多个 daemon，或者对某个现有组件的完整重写。

## 3. 非目标

- 不重写 Linux kernel、硬件驱动或整个 OpenWrt。
- 不复制旧项目的代码、模型或阶段结论。
- 不根据通用 OpenWrt 文档假定目标镜像一定包含某个包或接口。
- 不把某个组件“可以用 Rust 写”当作替换理由。
- 不以 QEMU 成功代替真实设备兼容性。
- 不在本计划中授权连接、刷写或修改物理路由器。
- 不提交镜像、解包目录、设备 dump、备份或秘密。
- 实体设备只允许 Wi-Fi、Ethernet 和现有 OpenWrt SSH；不拆机、不接 UART、不焊接或接触
  主板测试点。该边界只能由用户新的明确决定撤销。

## 4. 证据模型

### 4.1 证据等级

| 前缀 | 含义 | 可以证明 | 不能单独证明 |
|---|---|---|---|
| `DEP-*` | 实际部署镜像及伴随发布物 | 镜像中存在什么、构建声明是什么 | 设备实际运行行为 |
| `SRC-*` | 匹配的 OpenWrt/组件源码 | 实现逻辑、编译选项、补丁 | 目标设备确实走到该路径 |
| `RUN-*` | 经批准、脱敏的运行态观察 | 真实对象、状态、调用结果和时序 | 未采集场景的行为 |
| `REF-*` | 通用 fixture 或官方文档 | 方法、格式和背景 | 目标部署事实 |
| `INF-*` | 推断 | 待验证假设 | 任何完成门 |

设计结论必须能同时回答 DEP、SRC、RUN 三类依据。RUN 暂缺时，可以建立问题和测试，但
不得宣称替代设计已经兼容。

### 4.2 Claim ledger

每条重要结论至少记录：

```text
claim_id
statement
status: observed | derived | inferred | contradicted | unknown
evidence_ids
source_sha256
source_revision
tool + version
command/run id
redaction status
scope and limitations
reviewer/date
```

### 4.3 冲突处理

证据冲突时按以下方式处理，而不是简单覆盖：

1. 保存两个说法和各自证据；
2. 检查是否比较了不同镜像、版本、profile 或启动阶段；
3. 运行态描述实际行为，源码解释可能路径，镜像确定部署内容；
4. 无法消解时标记 `contradicted`，相关替换候选不得进入实现。

### 4.4 调查顺序

```text
部署身份（设备/profile/release/hash）
  → 匹配源码（buildroot/feeds/components/patches/config）
  → 源码导出的预期结构、接口和调用图
  → 实际镜像的一致性验证与差异清单
  → 必要的脱敏运行态裁决
  → 兼容合同与 Rust 切片
```

这里的镜像步骤不是开放式黑盒逆向。它只回答源码无法独自回答的部署问题：精确 package
集合、构建配置、生成文件、定制 patch 痕迹、实际二进制和发布配方是否吻合。

## 5. 工作区和安全模型

### 5.1 Git 与私有证据分离

Git 仓库：

```text
本机：项目 workspace
远端：/home/ubuntu/owrt-control-plane-rs
```

远端私有 evidence 根目录：

```text
/home/ubuntu/owrt-evidence/<image-id>/
```

建议结构：

```text
<image-id>/
├── input/          # 原始文件，只读
├── metadata/       # 下载的 checksums/buildinfo/profiles
├── extracted/      # 解包内容
├── sources/        # 固定 revision 的源码
├── runs/           # 每次分析日志
└── private-report/ # 尚未脱敏的中间报告
```

仓库只保存：

```text
docs/
manifests/          # 无秘密的来源、哈希和工具清单
reports/            # 脱敏派生报告
tools/              # 可复现分析工具
tests/fixtures/     # 人工构造或确认脱敏的 fixture
```

### 5.2 本地与远端同步纪律

在配置正式 Git remote 前：

- 本机负责代码和文档编辑；
- 远端负责镜像、源码和 QEMU 分析；
- 每次同步后比较 HEAD 和 tree hash；
- 不在两端同时产生未提交修改；
- evidence 目录永不同步进 Git 工作树。

### 5.3 分析沙箱

固件是非可信输入。分析容器/进程默认：

- 输入目录只读；
- 输出目录单独可写；
- 不使用 `--privileged`；
- 不映射 `/dev/mtd*`、磁盘或宿主 Docker socket；
- 静态分析阶段关闭容器网络；
- 不绑定宿主端口；
- 不以 root 自动执行镜像中的脚本或二进制；
- 不 chroot 并运行镜像 init；
- 不自动 mount UBI、ext4 或其他镜像到宿主；优先离线解析；
- 限制 CPU、内存、进程数和运行时间。

特殊文件先列表、后排除提取；xattr、owner、capability 和设备节点另行记录。

## 6. 总体阶段图

| 阶段 | 目标 | 当前状态 | 是否允许设备写入 |
|---|---|---|---:|
| L0 | 验证方法、环境和计划前提 | 完成 | 否 |
| I0.0 | 固化证据工具和仓库防线 | 待执行 | 否 |
| I0.1 | 接收并确认实际部署镜像 | 完成：A-user-attested | 否 |
| I0.2 | 锁定匹配源码、设备定义和构建配方 | 完成：精确 revisions、设备配方、源码接口/失败边界已登记 | 否 |
| I0.3 | 按源码预期只读验证镜像结构和文件系统 | 完成：全字节、DTB、属性和偏差 gate 通过 | 否 |
| I0.4 | 建立部署物料、文件归属和精确源码映射 | 完成：159 packages、全文件/ELF/service ownership 和 exact source/patch map gate 通过 | 否 |
| I0.5 | 还原启动、服务、配置和 IPC 链 | 完成：启动链、25 服务、配置生成链和两层 ubus ACL gate 通过 | 否 |
| I0.6 | 建立运行态问题清单 | 完成：17 项职责、15 个问题、23 条已批准命令、11 条排除命令 | 否 |
| I0.7 | 经单独批准采集必要运行态 | 完成：用户授权后执行 23 条只读命令，40 个 ubus 对象、包/配置偏移与特权实测已记录；follow-up 后强制 23/23 输入与身份门 | 否，只读观察 |
| I0.8 | 形成五类替换边界并通过 I0 gate | 完成：17 项分类（10 项停在默认类）、7 个开放问题、7 条风险；gate 由 manifest 推导并通过 | 否 |
| I0.F | 关闭 OQ-01/OQ-07 并审查 I0.5–I0.8 | 完成：rcS 合同、配置漂移和 gate 工具缺口已修正 | 否，只读观察 |
| C1 | 冻结第一个兼容合同和参考 oracle | 完成：C1-01，11 个参考用例 | 否 |
| R1 | 实现第一个最小 Rust 切片 | 完成：11/11 差分、6/6 故障、gate 通过 | 否 |
| V1 | release-matched 集成和差分验证 | 完成：匹配 SDK package、11/11 + 6/6 差分/故障、4 项 V1 注入、gate 通过 | 否 |
| H1 | 物理设备准入和 canary | 无拆机重规划完成；H1.2/H1.3b 不适用，下一步 H1.4 offline preflight | 当前否；后续逐阶段决定 |
| N1 | 按同一闭环处理下一个职责 | 等待 R05 的 H1.4 结论；可继续离线研究，实体 canary 另行授权 | 另行决定 |

## 7. L0：计划前置探索

L0 的执行证据和局限见 [L0_DISCOVERY.md](L0_DISCOVERY.md)。

- [x] 盘点新仓库与 Git 历史。
- [x] 排除旧仓库作为方案来源。
- [x] 盘点本机和 Linux 分析环境。
- [x] 同步并校验远端仓库。
- [x] 真实执行官方签名、哈希、FIT、DTB、SquashFS 和 package DB 管线。
- [x] 真实执行 image → release tag → package source revision 映射。
- [x] 核实 AX3000T 官方源码中的 stock/ubootmod profile、DTS、镜像 recipe 和 U-Boot target。
- [x] 记录目标镜像缺失这一硬输入门；随后接收并验证 AX3000T stock 精确目标。

## 8. I0.0：证据工具和仓库防线

### 输入

- L0 报告；
- 当前 `.gitignore`；
- 远端工具版本；
- Git 与 evidence 目录布局。

### 工作项

- [ ] 定义 machine-readable evidence manifest schema。
- [ ] 定义 claim ledger schema。
- [ ] 定义工具运行记录格式：argv、版本、起止时间、状态码、stdout/stderr hash。
- [ ] 建立禁止入库的文件类型、大小和秘密扫描。
- [ ] 建立 `git diff --cached` admission check，拦截镜像、dump、备份和密钥。
- [ ] 固定 Linux 分析工具版本；优先使用小型、可审计的容器定义。
- [ ] 为 FIT、sysupgrade tar、raw squashfs、UBI、ext4/GPT 和 vendor wrapper 定义 dispatcher，
      但只在遇到相应目标格式后实现对应 extractor。
- [ ] 建立“不执行镜像内容”的测试。
- [ ] 建立输出目录非输入目录、输入 hash 前后不变的测试。

### 交付物

```text
docs/EVIDENCE_MODEL.md
docs/ANALYSIS_SAFETY.md
manifests/toolchain.json
tools/evidence-intake/
tools/firmware-inspect/
```

### 退出门

- 在人工 fixture 上证明输入只读且 hash 不变；
- 工具失败会导致 run 失败，不会产出“成功”报告；
- 特殊文件、未知格式和解析器异常均以 fail-closed 结束；
- Git admission check 能拦截测试镜像和测试密钥。

## 9. I0.1：目标镜像接收与部署身份

### 必需输入

优先取得：

1. 实际最终安装的 sysupgrade 镜像；
2. 首次迁移使用的 factory/initramfs/recovery 镜像；
3. 同次构建的 `sha256sums`、签名、`profiles.json`、`version.buildinfo`、
   `feeds.buildinfo`、`config.buildinfo`、manifest/BOM；
4. 下载 URL、下载日期、设备型号和操作者记忆；
5. 如果是自定义构建：source commit、feed revisions、patches、`.config` 和构建日志。

### 接收步骤

- [x] 将输入放入仓库外 `<image-id>/input`，权限设为仅所有者可访问。
- [x] 立即记录文件名、长度、SHA-256、来源、接收时间。
- [x] 将输入设为只读；所有分析使用派生副本或只读 mount。
- [x] 验证发布 manifest 的签名链和固定 key fingerprint。
- [x] 将镜像 hash 同时与签名 manifest 和 profile metadata 比对。
- [x] 使用 `fwtool` 等只读方式提取 metadata；记录没有 metadata 也是结果。
- [x] 对照 filename、metadata、profiles 和用户记录确认 target/subtarget/profile。
- [x] 将“实际使用”“同型号参考”“候选但未确认”分开登记。
- [x] 分别记录 release tag、tag object、tag commit、image revision 和 source date epoch。

### 身份置信度

| 等级 | 条件 | 后续允许 |
|---|---|---|
| A | 原始安装文件 + 签名发布链 + profile 全部匹配 | 进入完整 I0 |
| B | 原始文件存在，但定制构建来源不完整 | 可做源码导向验证；源码缺口阻断替换设计 |
| C | 只有同版本官方参考镜像 | 仅参考分析，不得代表部署规格 |
| D | 只有设备型号或操作者记忆 | 停止镜像结论 |

### 交付物

```text
manifests/<image-id>/intake.json
reports/<image-id>/IMAGE_IDENTITY.md
reports/<image-id>/PROVENANCE_GAPS.md
```

### 硬停止条件

- hash 不匹配；
- 签名链未知或验证失败；
- target/profile 存在冲突；
- 不能证明候选镜像实际用于部署；
- 自定义构建声称来自某 revision，但 metadata/package versions 与其冲突。

## 10. I0.2：匹配源码、设备定义和构建配方

### 执行原则

I0.1 先提供足以选择版本的部署身份；I0.2 随即以官方源码为主线恢复已有实现。不能直接以
OpenWrt `main` 代替装机版本，也不能因设备型号相同就混用 stock 与 `ubootmod` profile。

在实际镜像尚未到位时，可以对候选设备做源码勘察，但所有结论标记为 `REF`，不得标记为
`SRC` 或驱动替换设计。

### OpenWrt buildroot 和设备层

- [x] 获取并验证与目标发布物匹配的 release tag 或自定义 build commit。
- [x] 分别记录 annotated tag object、peeled commit、image revision 和 source date epoch。
- [x] 验证 `include/version.mk` 与镜像 release/revision 的关系。
- [x] 固定 `version.buildinfo`、`feeds.buildinfo` 和 `config.buildinfo`。
- [x] 固定每个 feed commit；不假设 LuCI 和 packages 位于主 buildroot。
- [x] 定位准确 device profile、DTS/DTSI、image recipe 和支持的镜像类型。
- [x] 定位 target/subtarget base-files overlay、board defaults 和 upgrade implementation。
- [x] 从 DTS 和 recipe 导出预期的 compatible、存储/分区、boot chain、kernel、rootfs、
      device packages、artifact 和 sysupgrade compatibility 清单。
- [x] 对 AX3000T 分别保存 stock 与 `ubootmod` 预期，直到部署身份排除其中一个。

### 核心组件源码基线

- [x] 为 `procd`、`ubus/ubusd`、`uci`、`rpcd`、`netifd`、LuCI 和镜像中出现的其他控制面
      组件定位 package recipe。
- [x] 取得首批核心组件的 `PKG_SOURCE_VERSION` 或上游 release tarball hash。
- [x] 登记首批组件的 OpenWrt package patch、设备 target 路径、configure flags、feature
      selection 和 install recipe；kernel/driver target patch 全量物料表留在 I0.4。
- [x] 先从源码登记入口、配置 reader/writer、IPC 注册、caller、failure path 和生成器。
- [x] 把闭源 firmware blob 与控制面实现分开；存在 blob 不等于其外围接口不可研究。

### 输出

```text
reports/<image-id>/SOURCE_BASELINE.md
reports/<image-id>/DEVICE_BUILD_RECIPE.md
reports/<image-id>/SOURCE_EXPECTATIONS.md
manifests/<image-id>/source-baseline.json
```

### 退出门

- buildroot、feed 和首批核心组件 revision 均固定到不可变标识；
- device profile 和布局变体唯一，或冲突被登记为硬阻塞；
- 镜像 revision string 未被错误当成 tag commit；
- 已从源码形成下一阶段的定向检查清单；
- `main` 上的现状没有被冒充为目标版本事实。

## 11. I0.3：源码导向的镜像与文件系统验证

### 执行原则

根据 I0.2 的 image recipe 选择最小解析器。通用扫描器只用于发现未解释区域，不决定结构；
本阶段不从二进制反推一套官方源码已经明确给出的设计。

### 工作项

- [x] `file`、magic 和长度初检。
- [x] 提取 `fwtool` metadata，确认发布签名链并保持输入 hash 不变。
- [x] 根据 source recipe 验证 sysupgrade tar、kernel FIT 和 SquashFS rootfs。
- [x] 列出所有 tar member、FIT image/config 和内部 hash。
- [x] 只读提取 kernel、DTB、rootfs 和 metadata。
- [x] 每个已识别 payload 记录长度、压缩方式和 SHA-256。
- [x] 反编译 DTB，并同匹配 revision 的 DTS 比较 compatible、partition、storage 和 network。
- [x] 比较完整 DTB 的 chosen 和设备层 hardware nodes；148 项语义断言通过，3 条 common
      SoC tree dtc warning 单独登记。
- [x] 验证 rootfs 类型、压缩参数和 source recipe 的生成链。
- [x] 在提取前生成 filesystem numeric listing。
- [x] 普通用户提取 regular file/dir/symlink；特殊文件单独登记，不伪造。
- [x] 记录 1,223 个 inode 的 owner、mode、mtime、type，以及 xattr、capability、
      setuid/setgid 和唯一设备节点。
- [x] 对尾部、padding、payload、DTB warning 和分析失败建立 deviation 记录；unknown bytes
      为 0，未发现 source/image deviation。
- [x] 输出 expected/observed/delta 三列表，不把“可解析”误写成“与源码一致”。

### 输出

```text
reports/<image-id>/DEPLOYMENT_VERIFICATION.md
reports/<image-id>/SOURCE_IMAGE_DEVIATIONS.md
reports/<image-id>/PARTITION_EXPECTATION.md
manifests/<image-id>/payloads.json
manifests/<image-id>/filesystem.json
```

### 退出门

- 输入 hash 前后不变；
- 所有字节属于源码可解释结构、明确 padding 或已登记 deviation/unknown region；
- kernel、DTB、rootfs 均有独立 hash 和类型验证；
- 分区报告只描述镜像/DTS 预期，不声称是真实设备当前 MTD 布局；
- 任何 parser warning、源码偏差和非零状态均进入报告。

## 12. I0.4：部署物料、文件归属和精确源码映射

### package inventory

- [x] 自动识别目标镜像使用 APK，并定位镜像内 package DB。
- [x] 提取 159 个 package 的 version、arch、dependency、origin、license、conffiles 和文件列表。
- [x] 比对 target manifest、CycloneDX BOM、profile defaults、device packages 和 build config。
- [x] 证明 manifest 的 135 项 + 3 个 device package + 21 个依赖 = 159 个 installed package。
- [x] 找出无法归属 package 的 regular files 和 ELF；unknown 为 0，237 个 generated path 单列。
- [x] 识别 downstream/custom package 命名、override 和 vendor patch 迹象；custom/downstream 为 0，
      三个 opaque firmware payload 单列。

### binary 和控制面清单

- [x] 对 161 个 ELF 记录架构、ABI、interpreter、NEEDED、RPATH/RUNPATH、SONAME、符号和大小。
- [x] 区分 119 个 BusyBox applet、135 个 script、54 个 ucode/Lua 和 83 个独立 ELF executable。
- [x] 记录 setuid/setgid、file capability 和高权限 daemon；setid/capability 为 0。
- [x] 盘点 init/rc/preinit/hotplug、UCI defaults/migrations、procd services/triggers、rpcd/ACL、
      LuCI calls、ubus、netifd、firewall4、hostapd、dnsmasq/odhcpd 和 sysupgrade/persistence。
- [x] 建立 executable/file/service → installed package → package recipe → component revision 映射。

### 每个关键 package

- [x] 用镜像 package DB 校验首批核心组件的 package version/origin。
- [x] 取得首批核心组件的 `PKG_SOURCE_VERSION` 或 release tarball hash。
- [x] 按 exact recipe/target 确定并登记 313 个 package patch assets、623 个 kernel patches 和
      应用顺序证据；独立 patch replay 明确留到 V1。
- [x] 记录实际 build flags、feature selection、59 个显式 install recipe 与 16 个 shared macro。
- [x] 将镜像文件、package file list、1,095 个 recipe auxiliary files 和 source install recipe 对齐。
- [x] 对 237 个生成文件记录 generator、输入和生成阶段，而不是只追踪生成结果。

### 来源置信度

| 等级 | 条件 |
|---|---|
| Exact | buildroot/feed/component revision、patch、config 和部署文件全部可复核 |
| Bounded | release/package version 明确，但 vendor patch 或 build flag 缺失 |
| Approximate | 只有相近公开 release；不得进入替换实现 |
| Unknown | 无法找到可信源码；默认保留或禁止触碰 |

### 输出

```text
reports/<image-id>/SBOM.md
reports/<image-id>/FILE_OWNERSHIP.md
reports/<image-id>/PRIVILEGE_SURFACE.md
reports/<image-id>/SOURCE_MAP.md
reports/<image-id>/PATCH_MAP.md
manifests/<image-id>/packages.json
manifests/<image-id>/executables.json
manifests/<image-id>/sources.json
```

### 退出门

- 所有 executable 和 init service 已归属 package/source，或列入未知项；
- package DB、发布 manifest、source recipe 和 build config 的差异均有解释或阻塞项；
- 未将 target 级 manifest 误当作 profile 实际安装清单；
- 每个关键 daemon/library/script 均有来源等级；
- 每个替换候选必须达到 Exact；vendor/闭源边界明确标记。

## 13. I0.5：启动链、服务链、配置链和 IPC

### 启动链

至少还原：

```text
kernel command line
  → preinit/failsafe
  → storage/overlay mount
  → /sbin/init/procd
  → rc.d/init scripts
  → service instances
  → hotplug/events/reload
```

记录 START/STOP 顺序、trigger、respawn、watchdog、privilege、environment、生成配置和失败
路径。静态图和实际启动顺序分开保存。

### 配置链

对每个核心配置域追踪：

```text
UCI / defaults / migration
  → consumer or generator
  → ubus/procd/netlink/nft/file/socket
  → execution daemon
  → kernel or hardware-facing state
```

必须记录：

- 配置真源和派生文件；
- 未建模字段是否被保留；
- validate/reload/restart/commit 语义；
- 临时状态与持久状态；
- 部分失败和恢复；
- 外部 writer 和并发窗口。

### IPC catalog

- [ ] ubus object/method/event 的静态注册点。
- [ ] JSON/blobmsg policy 和返回 schema。
- [ ] Unix socket 和权限。
- [ ] signal、pidfile、exit code 和 log contract。
- [ ] netlink family/message。
- [ ] filesystem watch 和 hotplug environment。
- [ ] rpcd ACL 和 session boundary。
- [ ] service reload/restart 调用者。

### 输出

```text
reports/<image-id>/BOOT_CHAIN.md
reports/<image-id>/SERVICE_GRAPH.md
reports/<image-id>/CONFIG_FLOW.md
reports/<image-id>/IPC_CATALOG.md
```

### 退出门

- [x] 每条关键图边都能指向 DEP 或 SRC 证据；
- [x] 静态无法证明的 object、instance、时序和错误被转入 I0.6；
- [x] 没有把 grep 命中数量当作接口合同；
- [x] 没有因为源码存在某路径就声称目标运行时一定走该路径。

### 执行记录

| 项 | 值 |
|---|---|
| 日期 | 2026-08-31 |
| 工具 | [tools/i0_5_controlplane.py](../tools/i0_5_controlplane.py)，Python 3.12.3 |
| 输入 | `extracted/rootfs-files`（只读）、`sources/`（固定 revision）、`manifests/…/executables.json` |
| 命令 | `i0_5_controlplane.py --rootfs … --sources … --executables … --output … --image-id ax3000t-stock-openwrt-25.12.5 --recorded-at 2026-08-31` |
| 输出 | `boot-chain.json`、`service-graph.json`、`config-flow.json`、`ipc-catalog.json` |
| 执行目标二进制 | 无 |
| 设备连接 | 无 |

I0.5 期间为闭合 IPC 缺口，按 recipe 固定 revision 新增 5 个源码 checkout：
`ubox` `6f78fa49…`、`libubox` `7dd12784…`、`hostap` `ca266cc2…`、`odhcp6c` `07d324ee…`、
以及按 `PKG_HASH` `0c00d4e5…bc19` 校验的 `dnsmasq-2.93` 源码包。全部位于 Git 之外的
evidence 目录。

### 主要结论

1. `/etc/init.d/rcS` 不存在于镜像；`sysinit` 由 procd 内建 `rcS()` 处理。
2. `preinit_essential` hook namespace 无注册项；早期挂载在 procd `initd/early.c`。
3. `network`、`system`、`wireless`、`board.json` 均不随镜像发布，首次启动生成。
4. 25 个 init script = 13 长驻 procd + 5 一次性 procd + 7 非 procd。
5. 只有 8 个服务实现 `reload_service`，其余 `reload` 退化为重新提交服务定义。
6. ubus 有两层 ACL：ubusd 的 `/usr/share/acl.d/`（按 unix 用户）与 rpcd 的
   `/usr/share/rpcd/acl.d/`（按会话组）；socket 本身是 0666，不构成访问控制。
7. 部署侧交叉检查发现 3 类悬空边：ucitrack `affects`/`exec` 指向未安装包、
   `acme.renew` trigger 无发送方、rpcd ACL 授权了 `dsl` 与 `fingerprint` 两个无提供方对象。

### 遗留至 I0.6 的静态不可判定项

- kernel command line（DTS `chosen` 无 `bootargs`），影响 rootfs 挂载选项；
- rcS 顺序、并发与失败传播（follow-up 已由精确 procd/libubox 源码关闭；逐项耗时转 OQ-09）；
- 实际 instance 数量与 shell 变量取值；
- `ubus list` 的实际对象集合，含 `network.interface.*`、`hotplug.*`、`odhcp6c.*`、
  `wpa_supplicant.*` 的实例名；
- `udebug` 对象的提供方；
- 设备当前 UCI 内容、迁移进度与是否有用户修改；
- 方法级 blobmsg policy 字段与类型（留待 C1 冻结合同时逐方法提取）。

## 14. I0.6：候选职责和运行态问题设计

### 候选职责表

对每个可能 Rust 化的职责填写：

```text
responsibility
current implementation
inputs / outputs / protocols
all known callers
lifecycle and privilege
persistent side effects
timing / concurrency / idempotency
reload and restart semantics
failure boundary and blast radius
compatibility requirements
available DEP/SRC evidence
missing RUN evidence
recovery and fallback
```

在这一阶段不排名“最想重写”的组件，只评估证据完整度和风险。

### 运行态问题单

每个 RUN 采集项必须写清：

- 静态证据为什么不足；
- 需要观察的精确字段；
- 命令或 ubus method 是否有副作用；
- 允许执行的精确命令；
- 预期状态码和超时；
- 脱敏规则；
- 原始输出保存位置和删除策略；
- 观察结果将关闭哪个问题。

### 退出门

- [x] 不存在“顺便把所有状态 dump 一遍”的采集项；
- [x] 每个命令已经过源码审查，确认读取不会触发 reload/scan/renew/reconnect；
- [x] 未经批准不能执行 collector；
- [x] 取得 shell、连接设备或改变 stock SSH 状态不被包装成“只读采集”。

### 执行记录

| 项 | 值 |
|---|---|
| 日期 | 2026-08-31 |
| 工具 | [tools/i0_6_candidates.py](../tools/i0_6_candidates.py)，Python 3.14.7 |
| 输入 | I0.5 manifests（`service-graph`、`config-flow`、`ipc-catalog`、`executables`） |
| 输出 | `responsibility-candidates.json`、`runtime-questions.json` |
| 设备连接 | 无 |
| collector | 未生成、未批准 |

生成器把每条职责声明（artifact 路径、init 服务名、config 名、ubus 对象名）与 I0.5
manifest 交叉校验，并强制：非 `read-only` 命令不得出现在已批准问题中；每条命令必须有
源码审查依据、期望状态码和超时；每个没有运行态问题的职责必须给出书面理由。首次运行时
该校验拦截了 5 处声明错误，全部修正后才产出。

### 主要结论

1. 17 项职责中 16 项有明确的运行态问题；R17（升级/重启/恢复出厂）没有任何安全的只读
   观察，全部方法都是终止性操作，已记入书面理由并推迟到 H1 的 recovery gate。
2. 11 条"看起来像读"的命令经源码审查后被排除。最重要的一条是 `ubus call rc list`：
   它对每个 `/etc/init.d` 脚本 fork + execl。与之对照，`ubus call service list` 只遍历
   avl 树，安全。
3. 同一 ubus 对象内部安全性不一致（`luci.getInitList` 安全，`luci.setInitAction` 不安全），
   因此授权必须按方法而不是按对象。
4. 取得设备 shell 或 ubus 访问本身是状态变更，已作为与采集授权分离的独立授权项记录。

## 15. I0.7：经批准的脱敏运行态采集

用户已于 2026-08-31 明确授权设备接入与采集执行。

- [x] 先证明精确设备、当前系统和镜像身份。
- [x] 只运行 I0.6 已批准命令。
- [x] 设置单命令超时和总采集超时。
- [x] 不写 UCI、不 commit、不 reload、不重启服务。
- [x] 不读取 NAND/MTD/UBI dump。
- [x] 不导出秘密配置或私钥。
- [x] 原始输出只进入私有 evidence 目录。
- [x] 脱敏结果经过人工复核后才进入 Git。
- [x] 记录一次观察不能外推到未观察时序或故障状态。

### 执行记录

| 项 | 值 |
|---|---|
| 日期 | 2026-08-31 |
| 接入 | SSH 公钥（ed25519）；口令未出现在任何命令行 |
| 命令 | 仅 `runtime-questions.json` 的 23 条只读命令，单命令超时 30 s |
| 派生工具 | [tools/i0_7_observation.py](../tools/i0_7_observation.py) |
| 输出 | `manifests/<id>/runtime-observations.json`（脱敏自检 0 命中才写出） |
| 原始输出 | Git 之外的私有 evidence 目录 |
| 设备写入 | 无 |

### 主要结论

1. 身份门通过：25.12.5 `r33051-f5dae5ece4`、filogic、`xiaomi,mi-router-ax3000t`、
   kernel 6.12.94、squashfs，与 I0.1 基线逐项一致。用户初报的 25.12.4 已澄清为滞后信息。
2. 部署偏移已量化：包 +4/-0/版本变更 0，四个全部是 LuCI 中文语言包，不引入守护进程或
   ubus 对象，因此 I0.4/I0.5 基于 159 包的结论继续成立。这关闭了 PROVENANCE_GAPS 的相应缺口。
3. 40 个 ubus 对象；静态字面量对象**零漏注册**，三条 build gating 结论全部证实。
4. 两处静态漏报，均为方法缺陷而非笔误：`dnsmasq.dns` 只在 OpenWrt 补丁中定义（上游 0 次），
   IPC 目录未消费 patch stack；`ubus` 伪服务由 `service_start_early` 注册，没有 init 脚本。
5. kernel command line 实测无 `rootfs_mount_options.*`，I0.5 标记的 rootfs 挂载风险确认为无影响。
6. jail 声明不等于生效：`ntpd`、`dnsmasq` 获得独立 ipc/mnt/pid namespace，`wpad` 没有任何
   namespace 隔离——因为它的 `procd_add_jail` 没有 flag 也没有 mount。
7. 本次启动日志未保留。follow-up 已由源码证明 rcS 全队列严格串行及普通失败继续语义；
   精确逐项耗时仍未取得，因为默认 procd debug 0 不输出 `DEBUG(2)` duration，转非阻塞 OQ-09。

输出：

```text
reports/<image-id>/RUNTIME_OBSERVATIONS.md
reports/<image-id>/STATIC_RUNTIME_DIFF.md
```

## 16. I0.8：替换边界报告和 I0 gate

### 五类结论

每个职责只能进入以下之一：

1. 保留；
2. Rust 接入或包装；
3. 优先用 Rust 替换；
4. 延后评估；
5. 禁止触碰。

默认是保留或延后。分类必须引用候选职责表和 DEP/SRC/RUN 证据。

### I0 总交付物

```text
reports/<image-id>/I0_FINAL_REPORT.md
reports/<image-id>/REPLACEMENT_BOUNDARY.md
reports/<image-id>/OPEN_QUESTIONS.md
reports/<image-id>/RISK_REGISTER.md
```

### I0 完成定义

- [x] 镜像身份和来源可独立复核。
- [x] 容器、payload、rootfs 和分区预期已解释。
- [x] 软件物料和文件归属完整。
- [x] 启动、服务、配置和 IPC 链已成图。
- [x] 关键组件均有精确源码映射或明确阻塞。
- [x] 每个候选都有接口、调用者、失败边界和兼容要求。
- [x] 关键行为取得必要运行态证据。
- [x] 事实、推断、未知和冲突分离。
- [x] 原始材料和秘密未进入 Git。
- [x] 未接触物理机持久状态。

任何一项缺失都不能进入替换实现。

### 执行记录

| 项 | 值 |
|---|---|
| 日期 | 2026-08-31 |
| 工具 | [tools/i0_8_boundary.py](../tools/i0_8_boundary.py) |
| 输入 | I0.2–I0.7 manifests + I0 follow-up review |
| 输出 | `manifests/<id>/replacement-boundary.json` + 四份报告 |
| 实现授权 | 无 |

生成器强制：每项职责恰好分类一次；离开默认类必须有书面理由和 DEP/SRC/RUN 三类证据；
`禁止触碰`必须写明恢复约束；有未解阻塞问题的职责不得进入`优先用 Rust 替换`。
十项 gate 中七项直接由 manifest 推导；报告分层、Git admission 与设备无写入分别保留
human review、commit-time scan 与 collector attestation 标签，不再由预填布尔值冒充自动证明。

### 分类结果

| 类别 | 数量 | 职责 |
|---|---:|---|
| 保留 | 5 | R02、R06、R10、R11、R16 |
| 禁止触碰 | 5 | R01、R03、R08、R12、R17 |
| 延后评估 | 4 | R04、R07、R09、R14 |
| Rust 接入或包装 | 2 | R13 rpcd、R15 logd |
| 优先用 Rust 替换 | 1 | R05 配置变更检测与分发 |

### gate 范围限定

本 gate 针对**这一个镜像、这一台设备、这一种配置**通过。OQ-01 与 OQ-07 已由 follow-up
关闭；精确启动耗时作为不阻塞职责的 OQ-09 开放。分类结果仍不授权实现。

## 17. C1：第一个职责的兼容合同

I0 通过后只选择一个职责，不设计整个 control plane。

### 选择标准

- DEP/SRC/RUN 证据完整；
- 接口稳定且边界窄；
- 调用者已知；
- 可离线或模拟验证；
- 失败不会破坏启动、管理或数据面；
- 可立即恢复现有实现；
- Rust 能带来可说明的安全性、可维护性或正确性收益。

### 合同内容

- 输入和输出 schema；
- wire/file/ubus/UCI 格式；
- exit code 和错误映射；
- timeout、retry 和 cancellation；
- 顺序、并发和幂等性；
- start/stop/reload/restart；
- log 和审计语义；
- privilege、ownership 和 filesystem side effects；
- crash/reboot 恢复；
- 资源和体积预算；
- 兼容版本范围。

### 交付物与 gate

```text
docs/contracts/<responsibility>.md
docs/decisions/<decision>.md
tests/reference/<responsibility>/
```

- [x] 合同由现有实现证据生成，不是 Rust API 反推。
- [x] 所有调用者都有测试场景。
- [x] 未定义行为明确保持未定义，不擅自标准化。
- [x] 回退到原实现的机制已经设计并可测试。

### C1 执行记录

| 项 | 值 |
|---|---|
| 日期 | 2026-08-31 |
| 对象 | R05 配置变更检测与分发（`/sbin/reload_config`） |
| 合同 | [docs/contracts/config-change-dispatch.md](contracts/config-change-dispatch.md) |
| 决策 | [docs/decisions/0001-first-contract-is-config-change-dispatch.md](decisions/0001-first-contract-is-config-change-dispatch.md) |
| 参考测试 | `tests/reference/config-change-dispatch/`，11 个用例，参考模型 `tools/c1_reference_check.py` |
| 新增运行态问题 | Q15（含点文件名的基线处理），只读，已批准并执行；标记 `collected_in_stage: C1` |
| 对 I0 gate 的影响 | 无。加入 Q15 曾使 gate 转为不通过，因为 I0.7 完整性检查按"已批准命令总数"比对；已把该检查改为只统计 `I0.7` 阶段的命令。gate 恢复通过，且对篡改与缺失仍会失败 |
| 设备写入 | 无 |

### C1 期间取得的关键行为证据

1. **本设备 7 个含点文件名产出空基线条目。** `uci show` 把 `dhcp.bak-x` 解析为「包 `dhcp` 的
   section `bak-x`」，查找失败但 shell 重定向仍创建文件。设备实测：`/etc/config/`
   有 7 个含点文件，基线中恰有 7 条等于空文件 md5。只要相应 tuple 继续不存在，
   修改这些文件自身的内容不会触发事件。含点 tuple 若能解析则会产生非空输出，
   由 SRC-only 反例 c11 固定，禁止实现成简单的含点判断。
2. **新增静默、删除与修改同信号。** busybox `md5sum -c` 对缺失文件同样打印
   `FAILED`，因此删除与修改不可区分；而新增文件不在基线遍历范围内，完全静默。
3. **事件顺序确定。** 按基线文件行序，即 glob 字典序。合同要求复刻。

### 合同刻意不修的行为

当前 7 个无法解析的含点文件名所产生的空条目行为**必须复刻**。改成读取备份文件内容会让
这些历史文件突然变为可检测，
改变 procd trigger 的触发面——那是行为变更，不是兼容实现。

## 18. R1：参考 oracle 和最小 Rust 实现

### 先建立 oracle

- [x] 使用匹配版本的现有实现运行正常、错误和边界输入。
- [x] 录制脱敏 golden traces。
- [x] 覆盖 malformed input、超时、依赖消失、部分成功、并发边界和重复调用。
- [x] 覆盖进程中断、重复运行与 tmpfs 基线消失所代表的 reboot 语义。
- [x] 区分 reference implementation bug 和兼容要求，禁止无记录地“修正行为”。

R1.1 在一次性精确 rootfs chroot 中执行原 `/sbin/reload_config`，只把副本里的 `ubus`
替换成记录退出状态的 test adapter。11 个合同用例和 4 个故障 trace 全部通过；并发调用因
共享 `config.check` 仍明确保持未定义。机器记录与审查见
[R1_REFERENCE_ORACLE.md](../reports/ax3000t-stock-openwrt-25.12.5/R1_REFERENCE_ORACLE.md)。
该门通过前没有 crate；通过后才允许执行下节。

### 再实现 Rust

- [x] 只创建满足第一个合同所需的 crate/binary。
- [x] 不创建通用 control-plane framework。
- [x] 依赖少而固定；记录 license、source 和 binary-size 影响。
- [x] 所有外部输入有长度、类型和资源限制。
- [x] 显式处理 signal、timeout、cancellation 和 child process。
- [x] privilege 最小化；默认不写配置、不取得资源 owner。
- [x] adapter/protocol 层保持窄，便于和 reference 差分。

### R1.2 执行记录

| 项 | 值 |
|---|---|
| crate | `components/reload-config`；单一 binary `reload-config-rs` |
| toolchain | Rust 1.78.0；`aarch64-unknown-linux-musl`；`rust-lld`；静态、strip、LTO |
| 依赖 | 第三方 crate 0；license `MIT OR Apache-2.0` |
| 目标产物 | 432,248 bytes；SHA-256 `854d5ca0…a7a8c61`；预算 524,288 bytes |
| 单元/property | 5/5；其中穷举 81 个双 package 前后状态组合，并覆盖输入上限 |
| 精确差分 | 11/11；真实镜像 `uci` + BusyBox `md5sum`；事件顺序/集合与完整基线一致 |
| 故障注入 | 6/6：部分失败、缺失 uci、投递超时、畸形 UCI、并发、SIGTERM |
| 重复性 | 两次完整差分生成逐字节相同 manifest |
| 设备操作 | 无；仅服务器一次性 rootfs 副本 |

实现继续委托精确 `/sbin/uci` 做规范化、委托 BusyBox `md5sum` 生成共享基线，不重写 UCI
解析器。它复刻合同内的事件语义，同时把投递状态、依赖失败、超时和取消变成 JSONL trace
与非零退出码。未安装、未切换任何调用方，原 `/sbin/reload_config` 路径从未改变。

机器记录和审查见
[r1-candidate.json](../manifests/ax3000t-stock-openwrt-25.12.5/r1-candidate.json) 与
[R1_IMPLEMENTATION.md](../reports/ax3000t-stock-openwrt-25.12.5/R1_IMPLEMENTATION.md)。

### 退出门

- 单元、合同、property/fuzz、差分和故障测试通过；
- 所有差异有审查结论；
- 关闭 Rust 组件后原系统路径完全恢复；
- 未扩大 I0 批准的职责范围。

## 19. V1：release-matched 构建与隔离验证

### 构建

- [x] 使用目标 release 匹配的 SDK/toolchain。
- [x] 固定 target triple、linker、sysroot、CPU features 和 Cargo.lock。
- [x] 验证 dynamic/static linkage、SONAME 和 libc ABI。
- [x] 生成目标 package，但不生成或刷写整机镜像。
- [x] 默认 disabled/fail-closed；install 不取得控制权或改变运行配置。
- [x] disable、uninstall、upgrade 和 downgrade 均有测试。

### 隔离运行

- [x] 在 binfmt/QEMU + mount namespace 中运行精确 OpenWrt userspace；明确没有使用目标 kernel。
- [x] reference 和 package 实际安装出的 Rust binary 对相同输入执行差分。
- [x] 注入 SIGTERM、依赖 restart、I/O error、disk full、timeout 和 reboot namespace。
- [x] 验证 JSONL trace、资源上限和 100 次 one-shot 循环持久状态无增长。
- [x] 明确未覆盖硬件、driver、flash、bootloader、radio 和真实时序。

### V1 执行记录

| 项 | 值 |
|---|---|
| SDK | OpenWrt 25.12.5 filogic 官方 SDK；SHA-256 `ff4a38a3…e3ec4c25` |
| toolchain | Rust 1.94.0；`aarch64-unknown-linux-musl`；OpenWrt GCC 14.3.0；binutils 2.44 |
| package | `owrt-reload-config`；r1 184,099 bytes；clean repeat byte-identical |
| 安装 binary | 346,531 bytes；SHA-256 `b49b054f…0515f75`；dynamic musl PIE |
| ABI/hardening | AArch64、4 KiB LOAD、NOW/RELRO/RELR、NX stack、无 RPATH/RUNPATH |
| 生命周期 | install 默认禁用；enable、upgrade、downgrade、uninstall、reboot 回退全通过 |
| 精确差分 | 11/11；真实镜像 UCI + BusyBox；事件集合、顺序和基线字节一致 |
| 故障 | R1 6/6；V1 只读 I/O、磁盘满、依赖恢复、100 次循环 4/4 |
| 设备操作 | 无；只使用服务器的一次性 rootfs 副本和 namespace |

机器记录与审查见
[v1-validation.json](../manifests/ax3000t-stock-openwrt-25.12.5/v1-validation.json) 和
[V1_VALIDATION.md](../reports/ax3000t-stock-openwrt-25.12.5/V1_VALIDATION.md)。V1 实测纠正了
两个缺陷：apk upgrade 不执行旧包 `prerm`，因此增加 post-upgrade 强制回退；磁盘满会使
直接写正式基线留下半截文件，因此改为临时文件 + `sync_all` + 原子 rename。修正后从干净
环境重建并重跑全部 gate。

### 退出门

- 可从干净环境重复构建；
- package identity 和来源可复核；
- 默认安装无控制权、无持久副作用；
- 故障不会夺走现有执行平面；
- 结果只声明到测试过的 release/target/ABI。

## 20. H1：物理设备准入

H1 需要新的明确请求和授权。I0–V1 完成不自动授权 H1。2026-09-01 用户进一步固定：实体设备
只允许 Wi-Fi、Ethernet 和现有 OpenWrt SSH，不拆机、不购买/连接 UART、不焊接或接触主板。
该边界见[决策 0006](decisions/0006-use-a-no-disassembly-device-validation-profile.md)与
[重规划报告](../reports/ax3000t-stock-openwrt-25.12.5/H1_NO_DISASSEMBLY_REPLAN.md)。

H1.0 已在不连接设备的前提下完成；H1.1a 与 H1.1b 随后分别经单独授权执行并通过。H1.2
随后获准进入，但 exact-source 预检证明 NMBM 包装后的 MTD 读路径可条件性地擦除/复制备用块
并持久化映射，因此在接触设备前暂停。H1.3a 随后只在服务器完成：基于 exact source 构建
stock-layout initramfs recovery candidate，并通过重复构建和 FIT/DTB/initramfs 静态审计；
它没有接触路由器。H1.3b 随后获准开始，但 preflight 在接触设备前正确阻断 RAM boot。用户
明确无拆机边界后，H1.2 raw backup 与 H1.3b UART RAM boot 均改为
`not_applicable_under_no_disassembly_policy`：保留历史 false gate，不再是 R05 前置。准入与
恢复 runbook、两批只读命令、matching-feed
`nanddump` 备份工具、私有证据边界、停止条件和机器 gate 见
[H1_RUNBOOK.md](H1_RUNBOOK.md)、
[H1_READ_ONLY_PLAN.md](H1_READ_ONLY_PLAN.md) 与
[H1_READINESS.md](../reports/ax3000t-stock-openwrt-25.12.5/H1_READINESS.md)、
[H1_1A_OBSERVATIONS.md](../reports/ax3000t-stock-openwrt-25.12.5/H1_1A_OBSERVATIONS.md)、
[H1_1B_BOOT_FLAGS.md](../reports/ax3000t-stock-openwrt-25.12.5/H1_1B_BOOT_FLAGS.md)、
[H1_2_PREFLIGHT.md](../reports/ax3000t-stock-openwrt-25.12.5/H1_2_PREFLIGHT.md)、
[H1_3A_RECOVERY_DESIGN.md](../reports/ax3000t-stock-openwrt-25.12.5/H1_3A_RECOVERY_DESIGN.md)、
[H1_3B_PREFLIGHT.md](../reports/ax3000t-stock-openwrt-25.12.5/H1_3B_PREFLIGHT.md)。H1.1 gate
只证明只读身份/存储/boot branch 准入闭合；备份、reboot/failsafe、tmpfs shadow、APK 安装、
canary、device write 和 firmware flash 仍全部为 false。

无拆机路径严格按实际失败层分段，不再要求 R05 先证明它无法触发的 bootloader/NAND 恢复。
进入物理设备写入、安装或 canary 以前仍必须证明：

- 精确 board、target、storage 和当前 layout；（H1.1a 已闭合）
- 当前运行镜像与 I0 样本一致；
- 官方 known-good image 和 hash 已离线保存；
- 当前阶段的状态变化能由 SSH 清理，或由普通 reboot 清除且已经单独批准；
- H1.4/H1.5/H1.6 分别具备与自身失败层匹配的停止和回退步骤；
- 失败条件、停止条件和恢复步骤已写成 runbook；
- 首次部署不接管 WAN、LAN 管理路径、默认路由、现有 Wi-Fi 或 firewall。

建议顺序：

```text
fresh read-only identity/storage metadata
  → separately approved boot-flag reads
  → H1.2 source preflight (complete; raw backup not applicable under no-disassembly policy)
  → H1.3a offline recovery research (complete; artifact remains unused)
  → H1.3b historical preflight (RAM boot not applicable under no-disassembly policy)
  → H1 no-disassembly policy replan (complete offline only)
  → H1.4 offline preflight
  → separately approved H1.4 tmpfs-only shadow comparison
  → separately approved disabled install
  → separately approved bounded bind-mount canary
  → single approved resource ownership
```

任一步出现身份、恢复、兼容或管理可达性异常，立即回到现有实现，停止扩大范围。

当前 R05 canary 不包含 firmware flash。`ubootmod` `.itb`、OpenWrt U-Boot conversion、
`xiaomi_initial_setup`、`sysupgrade` 和所有 MTD/UBI write 在整个 H1 都明确禁止；如果未来需要
刷写，必须先由用户明确撤销无拆机边界，再创建新的恢复 gate 和新的授权，不能继承 H1。

## 21. N1：按证据闭环扩展

每个后续职责都重新执行：

```text
interface discovery
  → caller/failure boundary
  → DEP/SRC/RUN evidence
  → compatibility contract
  → reference oracle
  → minimal Rust implementation
  → release-matched build
  → isolated validation
  → separately approved canary
```

第一个组件成功不能成为相邻组件重写的证据。

## 22. 风险登记和停止规则

| 风险 | 处理 | 停止条件 |
|---|---|---|
| 错误镜像 | 签名、hash、profile、用户记录四方核对 | 任一身份冲突 |
| 自定义构建来源丢失 | 标记 Bounded/Unknown | 不能做替换实现 |
| vendor wrapper 未解释 | source recipe + 离线 parser | 存在未知写入区/boot payload |
| 提取工具静默失败 | 检查状态码、stderr、inode/count | 非零结果未解释 |
| package manifest 粒度错误 | 以镜像 package DB 为主 | 文件无法归属且未登记 |
| 静态推断运行行为 | 建 RUN 问题单 | 关键行为未观察 |
| 未知 caller | source + runtime 双向查找 | caller 集合不闭合 |
| 配置未知字段丢失 | byte/AST round-trip 与差分 | 不能证明无损 |
| 多 writer 并发 | owner 与锁/CAS 行为实证 | 无法阻止静默覆盖 |
| rollback 假成功 | 故障注入验证原始 bytes/state | 恢复只验证返回码 |
| 远端宿主资源冲突 | CPU/RAM/timeout 限制 | 影响已有服务 |
| 物理恢复未证明 | 独立 recovery gate | 不得部署或写入 |

## 23. 当前唯一优先队列

1. [ ] 执行 I0.0 的 evidence schema、工具锁和 Git admission check。
2. [x] 完成 I0.4 的 159-package source map、ELF inventory、service/privilege surface。
3. [x] 完成 I0.5，建立启动链、服务图、配置链和 IPC 目录。
4. [x] 完成 I0.6 候选职责表与运行态问题单；等待用户对设备接入和采集分别授权。
5. [x] 完成 I0.8，形成五类替换边界，I0 gate 通过。
6. [x] 完成 I0 follow-up：关闭 OQ-01/OQ-07，审查并修复 I0.5–I0.8 验收缺口。
7. [x] 执行 C1：为 R05 冻结兼容合同与参考 oracle。
8. [x] R1.1 先建立投递可观测 oracle；门通过后才创建唯一 R05 crate。
9. [x] 完成 R1.2 最小实现、精确差分、故障注入和体积门。
10. [x] 完成 V1：匹配 SDK package、默认禁用切换、ABI、生命周期、隔离差分和故障 gate。
11. [x] 完成 H1.0 离线准入：runbook、只读命令、matching backup tool、恢复层级、停止条件
    和机器 gate。
12. [x] 经用户单独授权完成 H1.1a：11/11 只读命令、stock MTD/NMBM/UBI、空间、工具与
    package drift gate 全部通过，零设备写入。
13. [x] 经用户单独授权完成 H1.1b：八个白名单变量全部存在，active rootfs 与 cmdline 一致，
    OpenWrt bootcount 分支闭合；H1-OQ-01 保留为不阻断只读备份的 bootloader 语义未知项。
14. [x] 完成 H1.2 exact-source 预检：`nanddump`、DTS、BMT/NMBM 路径与 known-good artifact
    已固定；发现 MTD 读取可条件触发 NMBM flash remap，故在连接设备前 fail-closed。
15. [x] 完成 H1.3a：exact stock profile 的 forced-read-only BMT/NMBM patch、无自动 mutation
    overlay、两次 byte-identical initramfs FIT 构建和静态 audit 全部通过；零设备接触。
16. [x] 完成 H1.3b preflight：用户已请求该阶段，candidate 已复制到 Git 外私有 staging；地址
    边界和 proposed command 已审核，但本机无 USB-UART、无 active wired link，现场供电/独立
    联网未确认，因此在设备接触前 fail-closed。
17. [x] H1.3b RAM boot 未执行并按用户固定边界关闭为
    `not_applicable_under_no_disassembly_policy`；这不是“已验证恢复”。
18. [x] H1.2 raw 私有备份未执行并退出 R05 前置链；NMBM 条件写入风险保持原判，不放宽成
    “安全只读”。
19. [x] 完成 H1 无拆机边界重规划：只允许 Wi-Fi/Ethernet/SSH，证明 R05 的 tmpfs/volatile
    失败层与 UART/NAND 恢复不相交，所有设备 gate 仍关闭。
20. [ ] 执行 H1.4 offline preflight：冻结 SSH/tmpfs shadow harness、命令、hash、timeout、
    fake ubus、清理与负向 gate；本阶段仍不连接设备。

已经确定：目标设备、stock 布局、OpenWrt 版本、release/build/feeds revisions、APK package
manager、SquashFS rootfs、R05 合同、可观测 reference oracle、最小 Rust 进程边界、匹配 SDK
package 和重启即失的显式切换机制。H1 的物理准入顺序、recovery runbook 与首个 canary 范围
已经冻结；H1.1a/H1.1b 现场证据已取得。H1.2 只完成服务器源码预检，H1.3a 只完成服务器构建
与静态审计，H1.3b 只完成离线/本机 preflight；三者没有产生新的设备操作。无拆机策略现已
把 raw backup/RAM boot 从 R05 前置链移除，但没有伪造其完成。下一项只有 H1.4 offline
preflight，设备 transfer、execution、install、mount、reboot 和 flash 全部仍为 false。
