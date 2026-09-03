# 0017：发布构建改为 opt-level 3 + 静态链接（2026-09-03）

## 背景

计划 A5 的 uci 性能差距（`export` 全量 8.0 vs 5.9 ms、`show firewall` 4.6 vs 3.2 ms）在构建机（Ampere aarch64，
同一 rootfs 的 C uci，同一份脱敏后的设备配置）上复现不出来：同源的 cargo 构建（静态 musl）与 C 持平或更快。
差别在打包方式：六个包的 `Cargo.toml` 用 `opt-level = "z"`，打包 Makefile 用 `-Ctarget-feature=-crt-static`
（动态链接 rootfs 的 musl）和 `-Ctarget-cpu=cortex-a53`。

## 设备实测（AX3000T，N=100，含进程启动）

| uci-rs 变体 | export 全量 | show firewall | export network | get |
|---|---|---|---|---|
| C `/rom/sbin/uci` | 5.9 ms | 3.1 ms | 2.7 ms | 2.6 ms |
| r3（动态，z，a53） | 7.2 ms | 4.0 ms | 2.9 ms | 2.8 ms |
| 静态，z | 6.4 ms | 2.9–3.4 ms | — | — |
| 静态，3 | 5.3 ms | 2.6 ms | — | — |
| 静态，3，a53 | 5.6 ms | 2.6–2.8 ms | — | — |
| **r4（SDK 构建：静态，3）** | **5.5 ms** | **2.7 ms** | **1.9 ms** | **1.9 ms** |

动态链接（PIE 重定位 + 加载器）每次执行约 0.8 ms；`opt-level z` 在 A53（顺序核）上比 3 慢约 15%；
`target-cpu=cortex-a53` 没有收益（略慢 3%）。静态构建的启动比 C uci 便宜（C 要加载 libuci/libubox/libc）。

## 决定

- 六个组件 `[profile.release]`：`opt-level = 3`（保留 lto、codegen-units=1、panic=abort、strip）。
- 六个打包 Makefile 的 RUSTFLAGS 去掉 `-Ctarget-cpu=cortex-a53 -Ctarget-feature=-crt-static`，其余链接参数不变。
- 代价：二进制变大（uci-rs 355 → 494 KB，sstrip 后），不再共享 libc 页。所有组件都不依赖 dlopen 或 C 库
  （rpcd 的 crypt/getspnam 来自 musl 本身），静态链接没有语义变化；沙箱门禁一直就是用静态 cargo 构建跑的。
- 每个包 release 号 +1（uci r4、fw4 r4、reload-config r5、logd r4、httpd r2、rpcd r8），门禁用 SDK 产出的二进制重跑，
  部署另需用户授权的窗口。
