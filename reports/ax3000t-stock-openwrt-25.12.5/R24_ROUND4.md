# R24：第四轮——找 bug、追性能（2026-09-03）

> 计划 §11.9。基线 [BENCHMARK](BENCHMARK.md)。原始输出 `private/bench/`、`private/audit/`。
> 设备窗口两次（用户授权）：rpcd r6 / logd r3 / reload-config r4；uci r3 / fw4 r3 / rpcd r7 + logd 短测。

## 1. 找到并修复的 bug

| # | 缺陷 | 影响 | 发现方式 | 修复 |
|---|---|---|---|---|
| 1 | **uci-rs 非 UTF-8 字节处理**：解析器用 `from_utf8_lossy`，配置值里任何非 UTF-8 字节被替换为 U+FFFD，`commit` 会把替换后的字节写回 `/etc/config`；行首出现高位字节时按字节索引 `String` 触发 panic（`panic=abort`） | owrt-uci 同时是 rpcd-rs `uci` 对象与 fw4-rs 的解析器：一个含杂散字节的配置文件会让 rpcd-rs 崩溃重启、fw4-rs 开机时中止（无防火墙规则）；libuci 允许任何 ≥0x20 的字节 | 差分模糊 `tools/r24_uci_fuzz.py`（150 例变异配置 + 原始字节 set 值，与精确 rootfs 的 `/sbin/uci` 逐字节比较）：6/150 不同，全部同源 | 值（option/list/delta/Ptr.value）改为 `Vec<u8>`，导出/CLI 按字节写，CLI argv 用 `args_os`；rpcd/fw4 在 blobmsg/JSON 边界有损转换并标注 DEVIATION（非 UTF-8 字节到总线变 U+FFFD；C 发原始字节，浏览器端 JSON 也无法表示）。修后模糊 300/300 相同，r16 175/175，fw4 上游 31/31，rpcd 门禁 272/74/11；uci r3 上线，设备 `export` 哈希前后不变 |
| 2 | **apk 升级钩子**：六个包的 postinst（为"安装即惰性"而 `switch disable`）被 apk 当作 post-upgrade 再次执行 | 升级 owrt-rpcd 时设备静默切回 C rpcd，rpcd-rs 因对象重复注册进入 crash loop（本轮部署 r6 时实际发生，`owrt-rpcd-switch enable` 恢复） | 部署时 `owrt-switch status` 显示 `error` | postinst 改为：boot-enable 打开 → 保持接管并重启（daemon）或重挂载（bind mount）；关闭 → 惰性。rpcd r7 用新钩子升级验证通过 |
| 3 | **子进程等待轮询**：reload_config（10 ms）、rpcd `file exec`（10 ms）、`rc list`（5 ms） | 每个子进程多至一个时钟片延迟；reload_config 无变更一次 404 ms（38 个子进程） | benchmark 发现 reload_config 慢 5.4 倍 | 阻塞等待 + 超时线程（reload-config r3、rpcd r6 `procwait`）；reload_config 404 → 96 → 65 ms（原脚本 78），`file exec /bin/true` 6.0 ms |
| 4 | **netlink 接收缓冲**：每次 `recv` 分配并清零 64 KiB（每请求两次） | iwinfo 每次 netlink 往返多约 0.3 ms，`info` 28 vs 19 ms | 进程内逐 op 对照（`rpcd-rs --iwinfo-bench` vs 同机 C libiwinfo 计时程序）：请求数相同，单次更慢 | 每线程复用缓冲（rpcd r6）：`info` 24.0 ms，`getWirelessDevices` 60 ms（C 19.0 / 48.8） |

## 2. 排查后判定不是 bug 的

- **panic 面**：125 处 `unwrap`/`expect` 逐处复核，非测试代码全部有前置守卫（fw4 sections.rs 10 处、rpcd rtnl/lucirpc/luci、ubus blob.rs 长度检查）。
- **clippy**：uci 9、logd 2、httpd 1、fw4 21、rpcd 23 条，全部风格类。
- **其余 sleep**：rpc-sys 延迟重启/升级、`passwd` 管道 `sleep 1`、uci apply 回滚计时，均与 C 原实现相同。
- **`logread` 全量 60 vs 26 ms**：不是差距。控制行数后（两边环内各 500 行，`logread -l 400` ×20）C logd 0.44 s、logd-rs 0.44 s 完全相同；
  沙箱 strace（`tools/r25_logd_stream_probe.sh`）显示帧长相同（152 B/条）、客户端系统调用相同；之前 C 的环里行数更少。
  顺带做的 socketpair + BlobBuf 复用（logd r3）保留：一次 60 KB 写入替代 400 次小写。

## 3. 性能收口（设备实测，2026-09-03 晚）

| 用例 | 原版 | 第四轮前 | 第四轮后 |
|---|---|---|---|
| `reload_config` 无变更 | 77.6 ms | 404 ms | **64.9 ms** |
| `ubus call iwinfo info` | 19.0 ms | 28.2 ms | 24.0 ms |
| `ubus call luci-rpc getWirelessDevices` | 48.8 ms | 73.0 ms | 60.0 ms |
| `ubus call file exec /bin/true` | — | ≤ +10 ms 轮询 | 6.0 ms（ubus CLI 底 3.8 ms） |
| `logread -l 400`（等行数） | 22 ms | — | 22 ms（相同） |
| `fw4 print` | 205 ms | 19.5 ms | 不变 |
| httpd 静态/JSON-RPC/TLS | — | +18% / +18% / +80% | 不变 |

仍慢于原版：iwinfo（约 +25%，剩余在 `htmodelist` 2 次请求 vs 1 次、`noise`）、uci 解析/导出（r3 重测：`export` 全量 8.0 vs 5.9、`show firewall` 4.6 vs 3.2 ms；进程启动相同，见 BENCHMARK §9）。

## 4. 工具新增

`tools/r24_uci_fuzz.py`（差分模糊）、`tools/r25_logd_stream_probe.sh`（流式路径 strace 对照）、`rpcd-rs --iwinfo-bench <ifname>`（逐 op 计时 +
netlink 请求计数）、`private/bench/iwbench.c`（同机 C libiwinfo 逐 op 计时，dlopen 方式绕过 sstrip 库无法链接的问题）。

## 5. 未完成 / 待办

- A5：**已解决（决策 0017）**——差距是 `opt-level z` + 动态链接造成的，不是解析器；opt-level 3 + 静态的 uci r4 在设备上全面快于 C（BENCHMARK §10）。六组件同改（uci r4、fw4 r4、reload-config r5、logd r4、httpd r2、rpcd r8），待部署窗口。
- B4 余项：rpcd 里 `read_to_string` 读 `/etc/ethers`、`/etc/board.json`、`/etc/resolv.conf` 等的地方遇到非 UTF-8 会整文件放弃（C 逐行按字节），改为按字节读。
- B5 余项：fw4（变异防火墙配置 → `print` 差分）、rpcd（随机参数）、httpd（畸形请求）、logd（畸形报文）的模糊。
- B2：clippy 清零。
- 设备当前版本：uci r3、reload-config r4、logd r3、httpd 0.1.1-r1、fw4 r3、rpcd r7；发布镜像需按 `docs/RELEASE.md` 重新生成。

## 6. 部署记录（第二个窗口，2026-09-03 22:04，用户授权"三件部署 + logd 短测"）

| 步骤 | 结果 |
|---|---|
| owrt-uci r2 → r3（switch disable → apk → enable） | `uci export` 全量哈希 `a53947a0e80f7ed8` 升级前后相同，且与 `/rom/sbin/uci` 相同 |
| owrt-fw4 r2 → r3 | enable 门禁通过；`fw4 print` 哈希 `d756aeddbdf70786` rs 与 rom 相同 |
| owrt-rpcd r6 → r7（新 postinst：boot-enable 打开 → 保持接管并重启） | "9 objects ok"，单个 rpcd-rs（pid 12656），status enabled r7——升级钩子 bug 的修复在设备上验证 |
| logd 短测：C logd ↔ logd-rs 各 `logread -l 400` ×20 | 0.44 s / 0.44 s（环内 500 / 503 行）；结束时 logd-rs r3 重新接管（pid 13458） |
| 3 分钟探针 | rpcd/logd/httpd running，pid 不变，无 crash loop，ubus 40 对象，六组件 enabled/on，LuCI 登录页 403+表单正常 |
| uci r3 重测 | BENCHMARK §9 |

设备当前：uci 0.1.0-r3、reload-config 0.2.0-r4、logd 0.1.0-r3、httpd 0.1.1-r1、fw4 0.1.0-r3、rpcd 0.1.0-r7、switch 0.1.0-r2。

## 7. 部署记录（第三个窗口，2026-09-03 22:4x，用户授权"六件部署 + benchmark"，决策 0017）

六个包按 uci → fw4 → reload-config → logd → httpd → rpcd 顺序 `apk add`，每个升完即查，全部通过：

| 包 | postinst 行为 | 检查 |
|---|---|---|
| uci r3 → r4 | 重挂载，enable 门禁 export/show/changes 全部 identical | `uci export` 哈希 `0f160a8175289da1` 不变；`/sbin/uci` 已是 494,339 B 的静态二进制 |
| fw4 r3 → r4 | 重挂载，enable 门禁 identical（203 行，sha256 89eb8765…） | `fw4 print` 哈希不变 |
| reload-config r4 → r5 | 重挂载 | `/sbin/reload_config` 490,215 B；无变更一次 30 ms |
| logd r3 → r4 | enable + restart | 新 pid 13166；`logger` 一条后 `logread` 可读 |
| httpd r1 → r2 | enable + restart | 新 pid 13486；LuCI 登录页 403+表单，79 ms |
| rpcd r7 → r8 | enable + restart | 新 pid 13797，单进程，9 个对象，`luci getFeatures` 正常 |

overlay 用量 21.9 → 23.1 MiB。3 分钟探针与 side-by-side benchmark 见 BENCHMARK §11。
