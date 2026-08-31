# AX3000T stock / OpenWrt 25.12.5：V1 package 与隔离验证

> 日期：2026-08-31
> 阶段：V1
> 结论：**通过；V1 完成。下一阶段 H1 必须另行获得实体设备授权**
> 设备操作：无；未连接、安装、切换或写入物理路由器

机器记录见
[v1-validation.json](../../manifests/ax3000t-stock-openwrt-25.12.5/v1-validation.json)，
可复跑 gate 见 [v1_package_check.py](../../tools/v1_package_check.py)，package recipe 见
[packaging/openwrt/owrt-reload-config](../../packaging/openwrt/owrt-reload-config/)。

## 1. 固定构建输入

| 项 | 固定值 |
|---|---|
| OpenWrt | 25.12.5 `r33051-f5dae5ece4` |
| target/package arch | `mediatek/filogic` / `aarch64_cortex-a53` |
| 官方 SDK | `openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64.tar.zst` |
| SDK SHA-256 | `ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25` |
| SDK 来源 | [OpenWrt 25.12.5 filogic 官方目录](https://downloads.openwrt.org/releases/25.12.5/targets/mediatek/filogic/) |
| C toolchain | OpenWrt GCC 14.3.0；GNU binutils 2.44；musl |
| Rust 版本 | 1.94.0；matching packages feed `5caa62e0…4214dd` 的 `lang/rust/Makefile` |
| Rust target | `aarch64-unknown-linux-musl` |
| linker/sysroot | SDK `aarch64-openwrt-linux-musl-gcc` 与 SDK staging sysroot |
| CPU/link flags | `cortex-a53`、dynamic musl、4 KiB max page、NOW/RELRO/RELR、PIE |
| Cargo | `Cargo.lock`；第三方 crate 0；release LTO/strip/panic=abort |

Rust compiler commit 为 `4a4ef493e3a1488c6e321570238084b38948f6db`，Cargo commit 为
`85eff7c80277b57f78b11e28d14154ab12fcf643`。package recipe 只复制固定 crate 的
`Cargo.toml`、`Cargo.lock` 和 `src/*.rs`，不会把本机 `target/` 带入构建。

构建宿主实测是 **Ubuntu 24.04.4 LTS / aarch64**，不是最初服务器资料中的 22.04。
官方 SDK 的 host tools 是 x86-64，因此本次通过宿主 binfmt/QEMU 执行。SDK 的 `runas.so` /
`libfakeroot.so` 不能预载入原生 ARM shell，构建日志会出现 LD_PRELOAD warning；这没有被静默
忽略：最终 APK 再由 SDK apk 3.0.5 `adbdump` 验证两个文件均为 `root:root 0755`，并用干净
构建重复性核对产物。该宿主差异仍保留为 V1 范围限制，不冒充标准 x86-64 builder。

## 2. package 与 ABI 结果

recipe 生成 `owrt-reload-config`，安装：

- `/usr/sbin/reload_config_rs`；
- `/usr/sbin/owrt-reload-config-switch`。

APK metadata 固定为 `aarch64_cortex-a53`、`MIT OR Apache-2.0`，直接依赖只有
`libc/procd/ubus/uci`。安装后的 binary 结果：

| 项 | 结果 |
|---|---|
| binary 大小 | **346,531 bytes**，低于 512 KiB 预算 |
| binary SHA-256 | `b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75` |
| ELF | AArch64 PIE，dynamic，stripped |
| interpreter | `/lib/ld-musl-aarch64.so.1` |
| NEEDED | `libc.so`、`libgcc_s.so.1`；精确 rootfs 均可解析 |
| page alignment | 两个 LOAD segment 均 `0x1000` |
| hardening | NOW、RELRO、RELR、non-executable stack、无 RPATH/RUNPATH |

两次从 `package/owrt-reload-config/clean` 开始的 r1 构建逐字节相同：

| package | bytes | SHA-256 |
|---|---:|---|
| `0.1.0-r1` first | 184,099 | `02d0c977d68192c28d0ef537a704435d9814fb8e04763cd67d73e00e41e5d9b1` |
| `0.1.0-r1` repeat | 184,099 | 同上 |
| `0.1.0-r2` lifecycle fixture | 184,099 | `d29f5c76ee1a3a579214cb96fe053cf52cef5eb216dba1556a1e451d1ef0b5ae` |

r2 只用于证明真实 upgrade/downgrade 路径，不是另一个实现版本。APK 和 binary 都是构建
产物，没有进入 Git；`.gitignore` 也显式拒绝 `*.apk`。

## 3. 默认禁用与切换机制

[决策 0004](../../docs/decisions/0004-use-a-reboot-volatile-bind-mount-switch.md) 选择了显式、
重启即失的 bind mount：`enable` 先核对原 `/sbin/reload_config` 的固定 SHA-256，再把候选
挂载到同一路径；`disable` 卸载并核对原文件。原文件从未被删除或覆盖，三个已有调用方无需
修改。

在精确 rootfs 的 disposable mount namespace 中，以下路径全部通过：

| 场景 | 结果 |
|---|---|
| 安装 r1 | 默认 disabled；原路径 SHA 不变；`/etc/config` 整树 hash 不变 |
| 显式 enable | mount 与 binary 逐字节相同；原调用路径可执行候选 |
| r1 → r2 upgrade | `post-upgrade` 强制 disabled；原实现恢复 |
| r2 → r1 downgrade | `post-upgrade` 强制 disabled；原实现恢复 |
| 已启用时 uninstall | `pre-deinstall` 先 disabled；package 文件删除；原实现恢复 |
| namespace 结束/模拟 reboot | mount 自动消失；新 namespace 默认 disabled |
| 候选缺失 | enable 拒绝；原实现不变 |
| 原实现 hash 不符 | enable 拒绝；不建立 mount |

首次 lifecycle 暴露了 recipe 缺陷：只有 `prerm` 时，apk upgrade 不执行旧包的
`pre-deinstall`，mount 会继续指向旧 inode。gate 当时明确失败；最终把 disabled 后置条件
加入 live `post-install`/`post-upgrade` 后，从全新 rootfs 重跑通过。不是靠放宽 gate 通过。

## 4. package 形态的差分与故障

测试对象不是 Cargo 目录 binary，而是 r1 APK 实际安装出的 stripped binary。它被复制到
一次性精确 rootfs，继续使用镜像中的真实 UCI、BusyBox `md5sum` 与测试 ubus adapter。

- **11/11** C1 用例：候选与原脚本的事件顺序、事件集合和完整基线字节一致；
- **6/6** R1 故障：部分投递、缺失 UCI、timeout、畸形 UCI、并发和 SIGTERM 全部通过；
- package 切换用例 c10 首轮零事件，证明共享基线可互换。

V1 追加四组检查：

| 检查 | 结果 |
|---|---|
| 只读 `/var/run` | 退出 70；dependency fatal trace；旧基线字节不变 |
| 64 KiB tmpfs 磁盘满 | 退出 70；旧基线字节不变；临时文件清理 |
| ubus 缺失后恢复 | 缺失轮可见地退出 2；依赖恢复后的新变更正常投递 |
| 100 次不变输入循环 | 每轮退出 0、零事件、无残留 `config.check`；持久状态逐字节相同 |

磁盘满首次运行又发现候选直接截断正式基线，会留下半截文件。修正见
[决策 0005](../../docs/decisions/0005-commit-the-runtime-baseline-atomically.md)：先写同目录临时
文件、`sync_all`，再原子 rename；任何写失败保留旧基线。新增单元测试后，`cargo fmt`、
**6/6** 单元/property、clippy、11/11 差分、6/6 原故障和完整 package gate 全部重新执行。

## 5. V1 gate 与范围限制

V1 gate 通过：clean repeat build、package 身份、ABI/hardening、默认无控制权、全部回退路径、
差分、故障和长期循环均为 true。最终 manifest SHA-256 为
`7acd6d3cd26cec7aa7be32e71b6e617bbc739b0fbc1c9c0a4b4a8ae0ba62fb8d`。gate 自身会再次核对
四个精确 rootfs artifact hash，拒绝在其他镜像上套用结论。

两次负向门禁也通过：在 repeat APK 尾部追加 1 byte 后，byte-identical 检查为 false、gate
退出 1；在一次性 rootfs 中篡改 `/sbin/reload_config` 后，身份门在创建输出 manifest 前退出 1，
并明确指出该 artifact mismatch。

结论严格限于 **OpenWrt 25.12.5 `r33051-f5dae5ece4`、`mediatek/filogic`、
`aarch64_cortex-a53`、musl 和本 package 配置**。以下没有被证明：

- namespace 使用 Ubuntu host kernel，不是目标 OpenWrt kernel；
- 未覆盖硬件、driver、flash、bootloader、radio 和真实时序；
- 组件是 one-shot，100 次循环证明持久状态不增长，不等于常驻 daemon heap profiling；
- 未验证物理恢复链，也未接触实体路由器。

因此 V1 完成只关闭了离线集成门，**不自动授权 H1**。任何实体设备的 disabled install、
只读观察或 enable 都必须由用户另行明确请求，并先满足 H1 recovery gate。
