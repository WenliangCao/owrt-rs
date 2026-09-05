# 给 Opus 的执行指导：统一 MSRV、开发与发布 Rust 到 1.98.1

日期：2026-09-05。基线 `d1520f9`。本文件是评估与实施要求，本轮没有执行版本升级或改动配置。

## 判断

**可行，建议做；目标明确固定为 Rust 1.98.1，而不是浮动 stable。**

截至本次核查，官方 stable channel manifest 日期为 2026-09-03，rustc 为 `1.98.1 (48a229cea 2026-09-01)`。官方提供 `aarch64-unknown-linux-musl` 标准库，以及当前 macOS、ARM64 Linux 构建机和 x86_64 Linux CI 所需宿主产物。

本机原有 stable 恰好已是 **1.98.1 / LLVM 22.1.8**：七个 crate 共 70 项单元测试通过，HTTP 当前锁定依赖的 build 通过。因此不是只有“理论兼容”；源码和依赖已有这部分实际证据。但 macOS 测试不验证 OpenWrt 的 Linux FFI、musl 静态链接、SDK GCC/binutils 或 ring 的目标汇编，发布升级必须补这些验证。

最新版 1.98.1 修复了 1.98.0 的 trait-object vtable 误编译问题，不能为了统一 major.minor 而固定到 1.98.0。

## MSRV 发现的准确结论

- Opus 对 `Option::is_none_or` 的判断正确：标准库文档标注从 **1.82.0** 稳定；`checked_add` + match 的修正也正确。问题原本就是 is_none_or，而不是 checked_add 本身。
- 七个 Cargo.toml 都声明 `rust-version = "1.78"`，但发布流程固定 **1.94.0**。所以那处 API 不会导致现有 1.94 发布失败，只是破坏宣称的 MSRV。
- 修掉 API 后，**整个 httpd 仍不能用 1.78 构建**：当前 Cargo.lock 锁定的 `zeroize 1.9.0` 声明 `rust-version=1.85`、edition 2024。本机 Cargo 1.78 执行 `cargo check --locked --manifest-path components/httpd/Cargo.toml`，在依赖清单解析阶段报 `feature edition2024 is required`。
- 不应为了维持已经不真实的 1.78 声明而在本任务中回退依赖。用户已要求提高最低版本，直接把最低支持版本与固定发布版本统一到 **1.98.1**。
- `rust-version` 是最低兼容性声明，并不会选择或安装 rustc；工具链固定需要单独配置。

## 最小改动清单

### 1. 建立唯一版本来源并统一七个 crate

新增仓库根 `rust-toolchain.toml`，建议内容：

```toml
[toolchain]
channel = "1.98.1"
profile = "minimal"
components = ["rustfmt", "clippy"]
targets = ["aarch64-unknown-linux-musl"]
```

七个 `components/{ubus,uci,reload-config,logd,httpd,fw4,rpcd}/Cargo.toml`：

```toml
rust-version = "1.98.1"
```

保持 edition 2021。本次升级编译器不需要 edition 迁移，不要把 `cargo fix --edition`、全仓库格式化、依赖升级或业务重构混进来。继续保持七个独立 crate，不为版本共享引入 workspace 或通用配置框架。

根文件作为发布版本的唯一人工维护来源；七个 MSRV 声明用一个很小的检查保证与它一致，不再新设一份重复版本文件。

### 2. CI 与发布脚本显式使用同一个固定版本

| 位置 | 当前 | 要求 |
| --- | --- | --- |
| `.github/workflows/ci.yml` | `dtolnay/rust-toolchain@stable` | 必跑任务使用根文件的精确版本；可额外保留浮动 stable 探测，但不得替代固定版验证 |
| `.github/workflows/release-image.yml` | env 与 action input 两处 `1.94.0` | 两者从同一来源导出/读取，不留旧值 |
| `tools/ci_build_image.sh` | 默认 `1.94.0` | 默认从根文件读取；明确安装精确工具链及 musl target；传给 SDK 的 V1_CARGO 显式固定 |
| `tools/release.sh` | 默认 `1.94.0-aarch64-unknown-linux-gnu` | 从根文件读版本，并传到远端 cargo；默认用宿主无关的版本号 `1.98.1`，让 rustup 选择远端宿主 |
| `packaging/openwrt/*/Makefile` | `V1_CARGO?=cargo` | 核查六个 Rust 包都实际获得固定的 V1_CARGO；直接 SDK 构建也必须提供明确工具链或失败提示 |
| `Makefile` | cargo 命令来自 PATH | 保持简单；正常 rustup proxy 会遵循根文件，但验证实际 rustc/cargo 身份，不能把 PATH 中任意 cargo 当作固定版 |

**容易漏掉的边界：** package recipe 把源码复制到 `/tmp/owrt-build/<pkg>`，那里不在仓库根文件下面，单独新增 rust-toolchain.toml 不会约束它。必须沿现有 `V1_CARGO` / `RUSTUP_TOOLCHAIN` 显式传递，不能只把根文件复制给源码就结束。

远端发布与 CI 的宿主架构不同，不要把 Mac 或 ARM64 Linux 的完整 toolchain 名硬编码给所有宿主。不要更改用户的全局 rustup default。

现有 `CARGO` / `RUST_TOOLCHAIN` 覆盖入口可以用于对照实验，但正式 release 若实际编译器与固定版本不一致，应失败或清晰标为非正式产物；不得 manifest 写 1.98.1、实际用另一版本。显式 RUSTC 或系统 cargo 也可能绕开 rustup，需要记录真实身份。

CI 缓存至少把精确 Rust 版本纳入 key；带 target 产物的缓存还包括宿主/目标架构和相关锁文件，避免把旧工具链缓存当验证证据。

### 3. 依赖与构建参数保持可归因

- 继续使用现有 Cargo.lock 和 `--locked`，不要顺手 `cargo update`。必要的 lockfile 格式变化单独说明，确认包版本/checksum 没变化。
- 保留 opt-level 3、LTO、codegen-units、panic=abort、strip、SDK linker 与路径 remap，避免把编译器收益与参数变动混淆。
- 保留 static musl 目标与原内核/驱动/执行组件。升级 Rust 编译器不要求升级路由器固件、OpenWrt SDK 或设备 libc。
- 六个 Rust binary 所在 APK 都会重新构建；正式发布时按仓库包版本策略增加对应 PKG_RELEASE。`owrt-switch` 是脚本包，若内容不变无须仅因 rustc 升级强行 bump。

### 4. 发布证据与文档

更新当前操作说明 `docs/RELEASE.md`、`packaging/openwrt/owrt-reload-config/README.md` 及相关活跃注释，修正 `http.rs` 中“this crate builds on 1.78”的过时说明。

历史报告中的 1.78 / 1.94 是历史事实，不能全局替换。新增升级记录说明从哪个版本到哪个版本。

现有 `tools/ci_build_image.sh` 产出的 manifest 没有 rustc/cargo 身份。追加实际 `rustc -Vv`、`cargo -V`、目标 triple、SDK GCC/linker 版本、各 crate 锁文件哈希和相关 release 参数，使 CI 与构建机结果可追溯。不是只记录请求使用的环境变量。

## 验收顺序

1. **先独立提交业务 bug 修复**（见 R31 文档）。再提交纯工具链升级；不要在同一次性能对照里混入两类变化。
2. **固定版本 host 验证**：七 crate 全部 `cargo +1.98.1 test --locked`、适用的 clippy 检查、`make check-tools`。现有 make test 没有 --locked，验收时显式对每个 manifest 执行。新 lint 与已有格式问题分开处理，不为升级大规模改源码。
3. **Linux 验证**：在 CI 或一次性 Linux 构建环境跑相同测试及 R31 的生命周期/上传测试；macOS FFI 可编译不代表 Linux ABI 已验证。
4. **SDK clean 构建**：以同一个 OpenWrt 25.12.5 SDK、同一锁文件，为六个 Rust 包重新 clean/build，避免已有 stamp 或目标目录使 make 误判无需重建。确认 aarch64 musl ELF、静态链接状态、所有现有 hardening 参数和 ring C/汇编目标正确。
5. **精确 rootfs 差分**：运行仓库已有 UCI、fw4、rpcd、logd、httpd、reload-config 的对应 reference/fault harness，以及新的资源和上传回归。用 APK 实际发货的 binary，不能只测试 host build。
6. **离线镜像**：生成并验证包、boot-enable markers、原服务禁用状态与现有镜像检查，记录源码 SHA 和 build manifest。不得因此触发 v* tag 的公开发布动作，除非用户另外要求发布。
7. **性能/资源对照**：同一源码、依赖和编译参数，分别用 1.94.0 与 1.98.1 构建，比较体积、RSS、异常峰值、fw4/uci/httpd/rpcd 代表路径。要做旧编译器对照时，用独立临时 checkout；本任务将 MSRV 提高后，不能让 1.94 被 Cargo 门槛挡住还当作编译器回归。仅对照副本可使用旧 MSRV 或显式忽略门槛，标注其用途，不能用于正式发布。
8. **可重复性**：CI 与构建机在同一新工具链下比较产物。已有 1.94 基线是 5/6 binary 一致、httpd/ring 尚未解决；新工具链不是要求与旧 binary 哈希相同，而是要求同一输入在新工具链下可解释、可追溯，不掩盖新增差异。

物理设备替换与实际升级不属于本指导的授权；本轮的“可行”也不是目标设备验证通过。完成 SDK/rootfs/离线镜像检查后，再按单独授权执行设备窗口。

## 官方来源与本机证据

- [Rust 1.98.1 发布公告（2026-09-03）](https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/)
- [stable channel manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml)：本次读取日期 2026-09-05；manifest date 2026-09-03，rustc 1.98.1。
- [Option::is_none_or 稳定版本](https://doc.rust-lang.org/std/option/enum.Option.html#method.is_none_or)
- [Cargo rust-version 含义](https://doc.rust-lang.org/cargo/reference/rust-version.html)
- [rustup 工具链选择与覆盖优先级](https://rust-lang.github.io/rustup/overrides.html)
- [aarch64-unknown-linux-musl 平台支持](https://doc.rust-lang.org/rustc/platform-support/aarch64-unknown-linux-musl.html)
- 仓库 Cargo.lock + `cargo metadata --locked`：zeroize 1.9.0，MSRV 1.85、edition 2024。
- 本机 Cargo 1.78 实际失败：zeroize Cargo.toml 需要尚未稳定的 edition2024；本机 1.98.1 实际 70/70 host tests 通过。
