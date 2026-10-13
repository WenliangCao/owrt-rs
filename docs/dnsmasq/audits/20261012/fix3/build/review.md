# 构建与启动资源独立核验

实际运行日期：2026-10-13。比较 main `be531cee49e366bb5044443d473944dbea45b87e` 与 fix `e3a37f55b2939ee2a0c229b0ac96a2a9c407b8aa`。派生总表与原始文件 SHA 索引见 `summary.json`；没有修改产品代码。所有运行均在 Oracle 隔离 namespace，SDK 复制到本轮 private 目录，原 SDK 未改。

## 已确认新增：大量 host-record 的启动 CPU / ready 延迟增加

严重度建议 **P3（低影响、条件性启动性能成本）**；属于**本分支新增、已复现**。不存在仅靠“内存峰值已修复”就推导启动成本不退步的依据。是否按本次合并标准阻断，由总审计结合绝对成本与其他热点性能结果判断。

配置为 loopback、no-hosts、no-resolv、cache 正常启用，分别包含 0 / 1,000 / 10,000 / 50,000 个独立合法 `host-record=nNNNNN.test,192.0.2.1`，每个规模按 C/main/fix、main/fix/C、fix/C/main 轮转三次，共 36 次。等待首次 `cleared cache` 日志（5 ms 轮询）作为初始 EVENT_INIT cache reload 完成边界；这时读取 `/proc/PID/stat` 的 utime+stime，CPU 分辨率 10 ms；再验证末尾名称正确 UDP A 回答，采五次 RSS/PSS，TERM 正常退出。

| 配置规模 | main ready 中位数 | fix ready 中位数 | main CPU 中位数 | fix CPU 中位数 |
|---|---:|---:|---:|---:|
| 0 | 5.74 ms | 5.89 ms | <10 ms | <10 ms |
| 1,000 | 5.57 ms | 5.85 ms | <10 ms | <10 ms |
| 10,000 | 26.18 ms | 36.44 ms | 10 ms | 30 ms |
| 50,000 | 127.97 ms | 179.03 ms | 110 ms | 170 ms |

50,000 条下 ready 的三轮值 main 127.86 / 128.27 / 127.97 ms，fix 184.29 / 173.95 / 179.03 ms；CPU main 120 / 110 / 110 ms，fix 180 / 170 / 160 ms。ready 中位数增加 51.06 ms（39.9%），CPU 增加 60 ms（54.5%），各轮同向，差值大于轮询／CPU 分辨率。10,000 条 CPU 只宜作粗粒度辅证；不能将 10 → 30 ms 解释为精确的 3 倍回退。

代码依据：`components/dnsmasq/src/main.rs:884` 先构建 configured hosts；`main.rs:3559` 的新增 initial-cache-reload 又进入 `reload_hosts_data`；`main.rs:3168` 先释放旧 local/daemon 索引再经 `read_hosts_with_notices` 重建 configured hosts。main 初始事件只报告已读信息，不重复这次构建。该分析解释已测的额外成本，但本轮未做 allocator/call-stack CPU 归因。该成本发生在正常启动，不是每个查询；Oracle 50,000 条额外约 51 ms，未证实实际目标配置具有该规模或造成可见服务故障，不能直接外推 Cortex-A53 的毫秒数。

复现：在 `R=/home/ubuntu/dnsmasq-audit-fix3-20261013`，先运行 `build_sequence.py` 得到准确双方 release，然后参考 `runtime_sequence.py` 的 `startup-resources` argv；输出目录必须更换为新的 private 子目录。使用随本次证据保存的 `startup_resources.py`。完整配置、三轮原始值和 source/binary SHA 在 `startup-resources.json`，status/smaps/log 原始 SHA 在 `summary.json.raw_files`。

## 原峰值回退已消除，固定资源成本仍可量化

10,000 条峰值 VmHWM 中位数 main 10,696 → fix 10,756 KiB，仅 +60 KiB；50,000 条 45,632 → 45,620 KiB。稳定 RSS 10,000 条 10,276 → 10,348 KiB，50,000 条 42,056 → 42,108 KiB。0 条 RSS 1,860 → 1,908 KiB。没有复现前轮增加约 3.3 MiB 的启动峰值问题。这里是启动空闲状态，不代表高并发或长时间运行峰值。

## 已确认 main 已有：原 ELF / APK 预算持续超限

严重度建议 **P2（完整替换验收的既有障碍，本次不因其阻止合并）**。

| 产物 | main | fix | 新增成本 |
|---|---:|---:|---:|
| Oracle release ELF | 1,970,216 B | 2,056,672 B | +86,456 B，4.388% |
| SDK APK payload ELF | 1,968,915 B | 2,054,939 B | +86,024 B，4.369% |
| 真实源码编译 APK | 1,087,222 B | 1,116,748 B | +29,526 B，2.716% |

两个版本均超出原 `tools/dnsmasq/m5_final_budget.json` 的 ELF 1,000,000 B / APK 700,000 B 门限。源码编译 prepare/compile 均成功；审计驱动按原预算返回 1、明确 `failure_boundary=size-target`，没有放宽门限或把编译成功视为完整替换验收通过。

新固定体积成本分解：release `.rela.dyn` 新增 51,840 B、`.text` 增加 30,656 B；因此主要是 static PIE 及新增代码，但不能把全部差异仅归于 PIE。上表应作为修复成本披露，不应把 main 的原预算失败冒称新增。

## 构建与运行时保护核验通过

- main/fix 从精确归档源码 fresh release；Rust 1.98.1，opt3、LTO、feature-off、AArch64 musl。main SHA `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`，fix SHA `524c327f79080c789f7cdce74125c2af52f6e9c97175414a874ac6e31c9f9c2a`。
- SDK 主线一次、分支两次均为真正的源码编译，没有设置 `OWRT_DNSMASQ_FROZEN_ELF`。分支第二次归档旧 build tree 后同路径 clean rebuild，ELF 和 APK 逐字一致；源码与 SDK 输入未变，原配方均恢复。
- main SDK payload SHA `1cfce37348e4160fd5da75eb59e5eb241315860afbd97af5e61672308f226eb7`，APK SHA `fb5bf4b298bd3aa4dbe8fe4f14f747ad773216487f22df0ad61b05e9d0f77500`。
- 分支 SDK payload SHA `22ef3b951bc089aed60e22120786480d3008f7e8954f28da773fdc9ee76c9f1e`；APK SHA `90073821999ad98154bd04e3b65543feeb20ce366d17bff474e5341fc477d87f`。这与 Oracle release 是两种构建身份，不混用二者测试结论。
- 包内容、原配置所有权、生命周期脚本和依赖校验通过，无新增 libgcc 直接依赖。目标 ELF 是 ET_DYN static PIE，无 interpreter / DT_NEEDED / TEXTREL / WX LOAD / executable stack；包工具本轮 20 项测试通过。
- `packaging/openwrt/owrt-dnsmasq/Makefile:85` 的 backtick compiler lookup 穿过 Make eval 后可用，linker wrapper 的 Rust startup 对象替换实际成功。`startup_relro::protect` 在 main 前部完成保护，未发现当前固定工具链下正常构建或启动错误。
- main release、fix release、fix SDK payload 各实际启动三次，并与精确镜像 C 同环境比较 UDP/TCP A 回答。fix 两种产物均三种不同 ASLR 基址、全部 11 个 RELRO 页 `r--p`、stack 不可执行、无 writable executable mapping，正常查询和退出均成功。main 为固定 ET_EXEC 基址，其 RELRO 页仍可写；C 为三种不同基址、3 个 RELRO 页只读。这证实新保护有效。
- main 普通单测 757 lib + 74 bin = 831 通过；fix 765 + 77 = 842 通过；双方 23 ignored 未运行。使用实际 unoptimized/debug 测试 ELF，在独立 net/mount/pid namespace 与 tmpfs /tmp 中串行运行。

## 输入与工具身份

SDK build input map：main 172 文件、SHA256 `b1d2bed48938c8393ce828e10a39583b93711b5915de2adb09b136138266a560`；fix 177 文件、SHA256 `dec0b503d2f3218a82472a65da5a631285bc6212e8fb8508af2502093c49f8ed`，两次 SDK build 均相同。每个输入文件摘要及 prepare 后复制校验在 `summary.json.sdk`，其口径为产品/配方/打包工具的 `build_package.inputs`，不等于全仓库 archive 文件数。

工具：cargo 1.98.1 (`797e8a9bc 2026-08-05`)，rustc 1.98.1 (`48a229cea 2026-09-01`)，LLVM 22.1.8，host `aarch64-unknown-linux-gnu`；SDK GCC `14.3.0 r33051-f5dae5ece4`。SDK archive SHA256 `ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25`，运行比较的镜像 C ELF SHA256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`（269,305 B）。SDK 已装的 host 兼容 wrappers 单独包含在 SDK input map 中；没有声称 copy 后 SDK 与未修改 archive 解包树字节完全相同。

linker wrapper 静态复核未发现当前 pinned target 的已确认隐患：检查 actual compiler 为可执行绝对路径且不指向自身，恰有一个 `-static`，拒绝已有独立 PIE/shared 标志与 response file；恰有一份固定 Rust target/self-contained 路径的 crt1/crtbegin/crtend，替换对象需实际存在，再 `execv` 真编译器。该 wrapper 针对 pinned Rust 的当前 argv，既不承诺通用 linker 参数验证，也不承诺未来 Rust target 改动后继续工作。默认 package/release 的两条构建路径均已在本轮运行成功；没有已确认的新增 build/layout 错误。

## 尚未覆盖

Oracle 为 aarch64 主机，使用原有 x86_64 SDK 执行兼容 wrappers；SDK 日志有 inherited `runas.so` preload 架构相关警告，但编译／提取／strip 成功，输入散列和产物一致性均核验。本轮没有 canonical x86_64 CI、不同路径或不同宿主可重复性；也没有升级 Rust／linker／musl、其他页大小、完整 APK solver / procd / ujail / UCI 生命周期、目标 Cortex-A53 实测、物理路由器、长期 soak 或饱和资源压力。启动 wall 以日志轮询采样，不能作亚毫秒测量。

Git 中的两份 `*-release-layout.txt` 仅清除了 readelf 输出的行尾空白；Oracle 原始输出未改，其原始摘要仍由 `summary.json.raw_files` 与收尾核验绑定。
