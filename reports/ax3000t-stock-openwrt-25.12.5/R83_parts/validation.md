# R83 最终验证记录

日期 2026-09-10。审计基线 `a903721`，接手提交 `068eada`。代码、工具与报告由同一工作树收尾，
本地和 `oracle:/home/ubuntu/r83-complete` 的 **135 个源码/构建配置文件摘要完全一致**：
`cb85334b08987cb5399b12cbe5355a28d75749665cfc7439428fc43c29d512c6`。
算法、各组件摘要和最终二进制 SHA-256/大小见 [artifacts.json](artifacts.json)。

这些是验证构建，不是 APK 或发布固件。没有操作实体路由器；rootfs、私有网络配置、原始日志和
TLS 密钥都留在 Git 外。本文只保留命令、结果与证据索引。原始 `/tmp` 路径是本次运行索引，
不保证长期留存；可用仓库内的夹具复跑。

## 1. 构建与静态检查

构建机为 aarch64 Linux，Rust 1.98.1（`48a229ceaefd4985c50990b14116b6d856af0985`，
LLVM 22.1.8），交叉目标 `aarch64-unknown-linux-musl`，C 依赖使用 OpenWrt 25.12.5 SDK
GCC 14.3.0。没有在 macOS 上伪称执行 Rust 测试。

| crate | 单测通过数 |
|---|---:|
| ubus | 11 |
| uci（含集成测试） | 19 |
| reload-config | 9 |
| logd | 5 |
| httpd | 20 |
| fw4 | 14 |
| rpcd | 38 |
| ubusd | 21 |
| netifd | 151 |
| procd | 71 |
| 合计 | **359** |

`make test` 全部通过。所有 crate 的 clippy lint 通过：netifd 用 `-D clippy::all`，其余用
`-D warnings`；netifd 保留供 ABI 检查使用的 UAPI 常量和示例导入模块，因此还有 dead_code
警告。所有适用二进制及 examples 的 musl release 构建通过。

其他检查：工具链 pin/负向检查通过；所有 shell/Python 语法通过；12 个测试门负向单测通过；
目标 SDK ABI 静态断言、133 个网络常量、14 个 RLIMIT 常量通过；`git diff --check` 通过。
CI 新增 `make check-harnesses`，仍先执行 Rust 测试，再检查工具。本轮没有推送或触发远端 CI。

日志：`/tmp/r83-last-make-test.log`、`r83-last-make-checks.log`、`r83-last-harness-checks.log`、
`r83-last-clippy-<crate>.log`、`r83-last-build-<crate>.log`；ABI/常量日志为
`r83-complete-abi.log`、`r83-complete-netlink.log`、`r83-final2-rlimit.log`。

```sh
cd /home/ubuntu/r83-complete
export PATH="$HOME/.cargo/bin:$PATH"
export STAGING_DIR="$HOME/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/staging_dir"
export CC_aarch64_unknown_linux_musl="$STAGING_DIR/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
export AR_aarch64_unknown_linux_musl="$STAGING_DIR/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-ar"
make test check-toolchain check-toolchain-negative check-tools check-harnesses
for c in ubus uci reload-config logd httpd fw4 rpcd ubusd netifd procd; do
    if [ "$c" = netifd ]; then lint=clippy::all; else lint=warnings; fi
    (cd "components/$c" && cargo clippy --locked --all-targets -- -D "$lint") || exit 1
    (cd "components/$c" && cargo build --locked --release --bins --examples --target aarch64-unknown-linux-musl) || exit 1
done
SDK="$STAGING_DIR" sh tools/check_abi.sh
sh tools/check_netlink_consts.sh components/netifd/src "$CC_aarch64_unknown_linux_musl"
sh tools/check_rlimit_consts.sh components/procd/src/sys.rs "$CC_aarch64_unknown_linux_musl"
```

## 2. 行为门

| 组件 | 结果 | 本次日志索引（oracle 的 `/tmp/` 下） |
|---|---|---|
| netifd | 完整 29 项通过；r50 为 200 周期，含 r46/r63、生命周期、配置、PD、无线时限及退出清理 | `r83-last-netifd.log` 和 `r83-last-netifd/` |
| netifd 门自检 | 双侧 daemon 替换成 false 后，通过实际存活门判红 | `r83-final-netifd-selftest.log` |
| procd | r65 两侧各 272 场景标记、49 pid 记录、20 次预期失败调用；差分为空 | `r83-final2-r65_procd_diff.log` 与同名目录 |
| procd 门自检 | 双死及半截驱动均被拒绝 | `r83-final2-r65_selftest.log` |
| procd 启动/执行 | r83 A/B/C、r71 PID 1、r72 hotplug/tty、r75 handover 通过 | `r83-complete2-r83_procd_r81.log`、`r83-complete2-r71_pid1_probe.log`、`r83-complete2-r72_hotplug_daemon_probe.log`、`r83-final-tty.log`、`r83-final2-r75_sysupgrade_probe.log` |
| ubusd | r36 root/ubus 用户、r42 600 次变异、r83 35 行线级门通过 | `r83-complete-ubusd-r36.log`、`r83-complete-ubusd-r36-unprivileged.log`、`r83-complete-ubusd-r42.log`、`r83-complete-ubusd-r83.log` |
| rpcd | r13 63、r17 272、r18 77、r19 11、r26 615；均无差异；bytes/defer 通过 | `r83-final-r13_rpcd_check.log`、`r83-final-r17_rpcd_core_check.log`、`r83-final-rpcd-r18.log`、`r83-final-r19_lucirpc_check.log`、`r83-final3-r26.log`、`r83-final3-rpcd-bytes.log`、`r83-final3-rpcd-defer.log` |
| httpd 正常与审计用例 | r14 61 请求、扩展兼容 31 项通过；SSE 清理独立门通过 | `r83-final-httpd-r14.log`、`r83-final6-httpd-compat.log` |
| httpd 模糊 | 133 用例、22 处已记录边界差异、0 存活失败；原始差分 rc=1，**不计为全等通过** | `r83-last-r27.log`，逐项裁定见 [httpd.md](httpd.md) |
| logd | r21 重注册 2 s，三条 marker 保留；ring_wrap 27/5/27 条一致；oversize 后两侧继续服务；r28 33 输出一致 | `r83-last-r21_logd_reconnect_check.log`、`r83-last-r83_logd_ring_wrap.log`、`r83-last-r83_logd_oversize_read.log`、`r83-final-r28.log` |
| uci | r16 175 步、r24 200 用例、r83 554 文件逐字节一致 | `r83-complete-uci-r16.log`、`r83-complete-uci-r24.log`、`r83-complete-uci-r83.log` |
| reload-config | 11 参考 + 9 故障场景，包含不变的 512 KiB 大小门，全部通过 | `r83-final-reload.log`、`r83-final-reload.json` |
| fw4 | r09 31、r29 200（含 25 ucode 崩溃例）、defaults/include 12；全部通过 | `r83-complete-fw4-r09.log`、`r83-complete-fw4-r29.log`、`r83-complete-fw4-defaults.log` |

运行中发现的新差异修正后只重跑相关门：最新 rpcd fork/HUP/精确回收代码通过 defer/bytes/r26；
logd 改用共享 shutdown API 后重新通过三项连接/环门；netifd 最后的 wireless shutdown 修复
重新通过完整 29 项。最终源树另作全 crate 单测、clippy 与构建；未因未使用的共享 API 增加而
把全部较早差分重复运行一遍。最终产物 hash 与较早的历史红证 hash 分开记录。

## 3. 主要复跑入口

所有命令在构建机执行，`rootfs` 指向不可修改的原始提取目录；harness 自己复制后再操作。
`NETWORK_CONFIG`、`WIRELESS_CONFIG` 是本地私有捕获文件路径，内容不得写进 Git。

```sh
rootfs="$HOME/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files"
netifd=components/netifd/target/aarch64-unknown-linux-musl/release
sudo -n env NETWORK_CONFIG="$NETWORK_CONFIG" WIRELESS_CONFIG="$WIRELESS_CONFIG" \
    bash tools/netifd_suite.sh "$rootfs" "$netifd/netifd-rs" /tmp/r83-repeat-netifd "$netifd/examples"
sudo -n bash tools/netifd_suite_selftest.sh "$rootfs" "$netifd/netifd-rs" /tmp/r83-repeat-netifd-selftest
procd=components/procd/target/aarch64-unknown-linux-musl/release
sudo -n bash tools/r65_procd_diff.sh "$rootfs" "$procd/procd-rs" /tmp/r83-repeat-procd "$procd/examples"
rpcd=components/rpcd/target/aarch64-unknown-linux-musl/release
bash tools/r83_rpcd_defer.sh "$rootfs" "$rpcd/rpcd-rs"
bash tools/r83_rpcd_bytes.sh "$rootfs" "$rpcd/rpcd-rs" "$rpcd/examples/raw_bytes" /tmp/r83-repeat-bytes
sudo -n python3 tools/r18_rpcd_plugins_check.py "$rootfs" "$rpcd/rpcd-rs"
httpd=components/httpd/target/aarch64-unknown-linux-musl/release/httpd-rs
python3 tools/r14_httpd_check.py --rootfs "$rootfs" --candidate "$httpd" \
    --output /tmp/r83-repeat-httpd.json --image-id ax3000t-stock-openwrt-25.12.5 \
    --recorded-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 tools/r83_httpd_compat.py "$rootfs" "$httpd" "$procd/examples/notifier"
python3 tools/r27_httpd_fuzz.py --rootfs "$rootfs" --candidate "$httpd"
# r27 保留既有边界差异，因此退出 1；需查看上表，不把 rc 改成 0。
logd=components/logd/target/aarch64-unknown-linux-musl/release/logd-rs
bash tools/r21_logd_reconnect_check.sh "$rootfs" "$logd"
bash tools/r83_logd_ring_wrap.sh "$rootfs" "$logd"
bash tools/r83_logd_oversize_read.sh "$rootfs" "$logd"
```

其余门的完整参数见各脚本开头 Usage。r36 必须有镜像 ABI 的 asuser/busprobe helpers；
netifd suite 缺少输入、probe 或只运行 SUBSET 时退出 2，不能称为完整通过。

reload-config 使用原有包链接参数的构建命令如下；没有通过调高预算修复大小门。

```sh
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CC_aarch64_unknown_linux_musl" \
RUSTFLAGS='-Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs' \
cargo build --locked --release --manifest-path components/reload-config/Cargo.toml \
    --target aarch64-unknown-linux-musl --target-dir components/reload-config/target-package
```

结果为 491592 B；无这些页对齐参数的原生 musl 构建为 528544 B。两个构建不要混用大小结论。

## 4. 没有声称覆盖的内容

本次修复完成 R81 范围内的实现和测试门收尾，完整通用 OpenWrt 替换并不是这些通过结果的含义。
保留的合同边界见 [主报告](../R83_R81_FIXES.md) §4：例如通用非 UTF-8 JSON 键/事件名、
netifd 的既有非本机配置范围、C 小环日志的越界读取和 r27 的畸形请求差异。

没有执行实体设备迁移、flash、真实重启/升级、硬件故障注入或长期 soak；没有重新生成 APK、
固件镜像或宣称通过远端 CI。logd socketpair 的 EMFILE 分支与少数 procd 时序项由读码及
相关行为门覆盖，未为每条分支单独制作故障注入。TLS 背压门采样积压阶段 RSS，不等于完整下载
或密码学审计。这些边界不藏在“全部测试通过”的措辞里。
