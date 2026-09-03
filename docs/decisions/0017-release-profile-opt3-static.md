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
- reload-config 例外用 `opt-level = "s"`：合同 `config-change-dispatch.md` 冻结了 512 KiB 的静态 ELF 体积预算，
  opt-level 3 的静态产物 531,175 B 超预算（r1 门禁 FAIL），其热点在子进程不在自身代码。
- 每个包 release 号 +1（uci r4、fw4 r4、reload-config r5、logd r4、httpd r2、rpcd r8），门禁用 SDK 产出的二进制重跑，
  部署另需用户授权的窗口。

## 门禁（SDK 产出的静态二进制）

| 包 | 门禁 | 结果 |
|---|---|---|
| uci r4 | r16；r24 种子 1、3 | 175/175；150/150、150/150 |
| fw4 r4 | r09 上游用例 | 31/31 |
| logd r4 | r15；r21 | passed（10 输出）；ubusd 重启后 1 s 重注册，环保留 |
| reload-config r5（opt s，490,215 B） | r1 | gate_passed（11 参考用例；opt-level 3 的 531,175 B 版本超 512 KiB 预算被拒） |
| httpd r2 | r14 | passed（38 请求，0 不同） |
| rpcd r8 | r17 / r18 / r19 | 272/272、74/74、11/11 |

## 待部署产物（SDK，2026-09-03 20:2x，sha256）

| apk | sha256 |
|---|---|
| owrt-uci-0.1.0-r4 | 11a2e6e9d57e9f5fc1d18e9f08e9608cfa34db97348440e278cd03ec161f1cca |
| owrt-fw4-0.1.0-r4 | 9005912ef48e676e36a11fa2072d4a16a6efc888b8dc04ef41d433b088f82a0c |
| owrt-reload-config-0.2.0-r5 | d7a4da43dfb5b9883a1313561697313df19c2e5431e9460a634a113232696909 |
| owrt-logd-0.1.0-r4 | 0fa64ae021171e6b8a288b619c595e4787c26a94e51c31e4c088786e90bb2b02 |
| owrt-httpd-0.1.1-r2 | c314c8196121aff84a625ccf1ce092d1f45b8ae3602fb230a45bf8baddb0a00b |
| owrt-rpcd-0.1.0-r8 | b893efa090006d640e3c501782d9569b7f333e266e139a2532ced1739119a714 |

二进制体积（sstrip 后）：uci 355→494 KB、fw4 744→? 、reload-config 396→490 KB、logd 293→?、httpd 1,108→1,486 KB、rpcd 814→1,170 KB。
overlay 剩余 55 MB。
