# R33 发布验收 — 2026-09-05

R32 之后剩下的六项验收**各自都执行了一遍**，用户逐项授权。但"执行完"不等于"达到原验收范围"：
§5 列出的四项仍未达成（httpd/ring 可重复性、1.94 对照、四个只受编译器影响的组件的 reference harness、长时间 soak）。
本轮做了**写操作**：向构建主机推送源码并构建、向 GitHub 推送提交并触发工作流、向路由器安装 6 个 APK 并重启 3 个守护进程、
在路由器上做了一次真实固件镜像上传（写 `/tmp`，**未触发 sysupgrade / reboot / restore**，测试文件与临时 CGI 已删除）。

## 结果一览

| 门 | 结果 |
| --- | --- |
| Linux 单元测试（CI，x86_64，pin 1.98.1） | **80/80**；`check-tools` / `check-toolchain` / `check-toolchain-negative` 全过 |
| Linux 端到端探针（aarch64 构建主机） | 生命周期 4/4；上传矩阵 17/17，传输期间 RSS delta **704 KiB** |
| SDK clean 重建（同一 SDK、同一锁文件） | 7 个 APK 全部重建，`build_dir`/stamp/旧 APK 事先清空 |
| 精确 rootfs 差分（**APK 实际发货的 binary**） | httpd r14 **38/38**；rpcd r17 **272/272**、r18 **74/74**、r19 **11/11** |
| 差分模糊 | httpd r27 **24 处偏差，全部是已记录集合的子集，零新增**；rpcd r26 seed 1 **615 步 0 差异** |
| 离线镜像（GitHub `release-image`） | 成功，4m09s，manifest 带上了新的 toolchain 段 |
| 可重复性（CI vs 构建主机） | **6/7 APK 字节一致**；只有 httpd 不一致（ring，与 1.94 基线同一个已知问题） |
| 设备部署 + 真实上传 | 见下 |

## 1. 精确 rootfs 差分用的是发货 binary

APK 里的 binary 与 `.pkgdir` 里的**不同**（打包时 strip）：`.pkgdir` 的 httpd-rs 是 `989e1a13…`，
APK 解出来的是 `1c5d345c…`。差分用的是后者，也就是设备上真正跑的那个。

httpd r14：38 个请求全部逐字节一致（掩码 Date/Keep-Alive/ETag inode/cookie 之后）。

r27 模糊 133 例、24 处偏差。与 `private/audit/round5/r27.txt` 记录的首轮 35 处逐名对比：

- **新增偏差：0**。当前 24 项是那 35 项的严格子集。
- 消失 11 项：R25 §3.2 修掉的 10 项，外加 **`json-1mib`** ——
  以前 httpd-rs 在 4 MiB 全局上限内"正常处理"而 uhttpd 直接 reset；
  本轮 `/ubus` 改用自己的 65536 上限后，这一例与原版一致了。**上限分端点之后反而更贴近原版。**

## 2. 可重复性

| 包 | CI vs 构建主机 |
| --- | --- |
| fw4 r6 / logd r6 / reload-config r6 / rpcd r10 / switch r2 / uci r6 | **字节一致** |
| httpd r4 | 不一致（host `29d35930…` / CI `b529ef48…`） |

与 1.94 基线的情况相同（当时 5/6 一致，httpd/ring 未解决）。**不是本轮引入的**，也不是工具链升级引入的：
唯一带 C/汇编依赖（ring）的包仍然不可重复。仍然未解决，如实记录。

CI manifest 现在带 `toolchain` 段：`channel=1.98.1`、`official=yes`、完整 `rustc -vV`（含 `LLVM version: 22.1.8`）、
交叉 gcc、target triple、Cargo.lock 哈希 —— 即 R32 第 3 项要求的"验证的身份就是记录的身份"。

## 3. 设备部署（2026-09-05 21:53–21:58）

安装前：uci/logd/reload-config/fw4 r5、httpd r3、rpcd r9、switch r2。
安装后：**uci/logd/reload-config/fw4 r6、httpd r4、rpcd r10**，switch 保持 r2（脚本包，内容未变）。

- APK 哈希与构建主机一致，逐个核对。
- `apk add` 的 uci post-upgrade 门自检：`export` 400 行、`show` 299 行、`changes` 0 行，全部 identical。
- 重启 logd / rpcd / httpd 三个守护进程；**ubus 对象列表 md5 前后完全相同**（`cfd51449…`），仍是 40 个对象。
- 3 分钟窗口：pid 不变（无 respawn），无 crash/panic/oom 日志，ubus、LuCI、`luci-rpc getHostHints` 正常。
- 设备 RSS（`/proc/<pid>/status` 的 VmRSS，不是 `ps` 的 VSZ）：
  httpd-rs **1392 kB**（r3 时 1.98 MB）、rpcd-rs 1120 kB、logd-rs 372 kB。两次 9 MB 上传之后测的。
- overlay 用量 3.3 MiB，未增长。

## 4. 真实镜像上传（设备上，R30-05 的最终验收）

镜像 `openwrt-25.12.5-…-squashfs-sysupgrade.bin`，**9400608 字节 = 8.97 MiB**，sha256 `a94ac2c7…`。

| 路径 | 结果 |
| --- | --- |
| 临时计数 CGI，Content-Length | 200 OK，字节数与 sha256 完全一致，**0.33 s** |
| 同上，chunked | 200 OK，sha256 一致，0.41 s |
| **真实 `/cgi-bin/cgi-upload` → `cgi-io`** | **200 OK，0.71 s**；cgi-io 返回 `{"size":9400608,"checksum":"acc4f907…","sha256sum":"a94ac2c7…"}`；落盘 `/tmp/r33-upload-test.bin` 9400608 字节、sha256 一致 |

会话用 `ubus call session create` + `grant` 在设备本地创建（root 本地管理操作），用完 `destroy`。
上传目标故意**不是** `/tmp/firmware.bin`，避免任何误触发 sysupgrade 的可能。
测试文件与临时 CGI 已删除，`/www/cgi-bin/` 恢复原状。

这一项在 r3 上是坏的：8.97 MiB 超过当时的 4 MiB 全局上限，连接会被静默丢弃。现在设备上已修复。

## 5. 仍未做

- **httpd/ring 的可重复性**：老问题，本轮没有尝试解决。
- **1.94 vs 1.98.1 的体积/性能对照**：需要用独立临时 checkout 把 MSRV 降回去再构建一遍，本轮没做。
  设备 RSS 有对照（httpd 1.98 MB → 1392 kB），但那同时包含了本轮的代码改动，不能单独归因于编译器。
- **uci/logd/fw4/reload-config 的差分**：这四个本轮只有编译器变化，没有重跑它们的 reference harness。
- 设备只做了 3 分钟窗口，没有长时间 soak。
