# R92：第 2–5 批已完成，续接入口

截至 2026-09-15（Europe/Berlin），原计划剩余四批已完成：正式构建与回归、性能量化、
已授权的 Wi-Fi 部署、四个冷启动与完整负载、最终设备核验、公开派生证据及发布整理。
当前设备运行 R92；没有待放行的测试队列或尚待完成的部署步骤。

本文件可独立续接。会话 ID 是会话标识，不是系统 PID，也不保证其它模型能读取历史。

## 1. 固定身份

- 项目：`/Users/USER/Developer/owrt-control-plane-rs`。
- 分支：`codex/r92-recovery-compat`；当前 HEAD 包含后续验证工具与报告，部署身份以以下正式提交为准。
- 运行时提交：`ca1a9121df0380448a19d474e29796066b6734e8`。
- [release-image 34874442503](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/34874442503)。
- 固定性能基线：正式 R89 `d9c1048` / release-image `34724293710`。R90 是上一完整验收版本。
- 九个二进制、七个 APK、core archive、生成镜像和 manifest 链见
  [canonical_build.json](../reports/ax3000t-stock-openwrt-25.12.5/R92_parts/canonical_build.json)。
- 后续注释、工具和报告提交没有重新构建或替换上述运行时；原版 freqlist 缓冲问题只修正了注释。

## 2. 主要报告

- [四批验收](../reports/ax3000t-stock-openwrt-25.12.5/R92_REMAINING_BATCHES.md)：结果、验证、实机与采集事故。
- [逐项处置](../reports/ax3000t-stock-openwrt-25.12.5/R92_COVERAGE.md)：R88 每个遗留问题的修复、保留或撤销理由及回归门。
- [性能报告](../reports/ax3000t-stock-openwrt-25.12.5/R92_PERFORMANCE.md)：全部正差值、尾延迟、同机 HTTP、停放及内存控制。
- [部署证明](../reports/ax3000t-stock-openwrt-25.12.5/R92_parts/deployment.json)：恢复门、四 boot、安装与最终健康。
- [包保留与回退](R92_RELEASE_AND_ROLLBACK.md)：C/R89/R90/R92 的位置及 R90 APK 回退顺序。

## 3. 正式验证已经完成

69 道门中 68 道必需门全部通过。原版 C procd busy 的既有丢尾控制失败仍保留；它不属于候选必需门。
Rust 为 449 个不同 crate 内测试名、450 次执行，wake-pipe 测试在 rpcd lib/bin 重复编入。
十 crate Clippy、netifd 31/31、HTTP 133 例、fw4 上游 31/31 与 r29 200/200、UCI r16/r24 1000 例及
修正 r83 均通过。r71 确实启用 `R90_HOTPLUG_PROBE=1`。
离线冷切换/救援 5/5，同版本 APK 升级 4/4；收尾工具语法、21 个 harness 和 33 个 benchmark Python 测试通过。

三处正式夹具失败已经修正并用同一正式二进制复跑：sudo 丢 HELPERS 误用旧 probe、fd 基线早于 EOF
清理、UCI r83 未应用非法 UTF-8 rename 原子拒绝合同。原失败和最初 52 道门后断连的采集记录均保留。
不要重跑已经有效的完整验证，只在新变更或新失败需要时补对应检查。

## 4. 实机完成状态

最终设备证明时间：**2026-09-14 23:27:33 UTC**。
四窗口 Rust-1→C-1→C-2→Rust-2，每窗口 500650 次被测操作、五轮及前后各 120 秒 idle；
九组件三侧四轮共 888 条测量，ubusd/procd CPU 0 affinity 共 216 条测量。

无线四窗口 212 调用、4 次扫描、28 组；两个 radio 的精确动态库缓冲控制通过。
固定邻居六阶段每侧 20 断言、262144 个固定 HT IE、三组同启动完整 HostHints JSON 均通过。
HTTP 同机四侧、两方法、各四轮共 320000 次被测请求全部通过，活动 HTTPD 未重启。

最终九组件身份、C 原件、安装文件、配置、内核 6.12.94、执行面、归一化 nft 规则、客户端 DHCP、
双频 AP 桥、本地 HTTP/HTTPS、IPv4/IPv6 DNS/HTTPS 与 watchdog 通过。
R89/R90/R92 保留包各 29 个文件与 7 个 APK 逐项核验。六个诊断文件核验后删除；临时目录及
pending/reverting/canary 清除，overlay 可用 28936 KiB。没有刷固件。

设备位置：

| 内容 | 路径 |
|---|---|
| 当前 R92 | `/root/r84` |
| 正式 R89 | `/root/r89-before-r90` |
| 已接受 R90 与旧 APK | `/root/r90-before-r92` |
| 自动回退 C | 精确 `/rom` 及保留原件 |

回到 R90 要先以 `--no-scripts --no-network --force-reinstall` 安装其旧 APK，再调整 bundle 并冷切换。
`stack-switch` 没有 `status` 子命令。恢复门和客户端健康要求继续适用于之后的新部署。

## 5. 不能丢失的结论边界

- 相对本轮 C，固定整批 CPU −23.39%、mixed 吞吐 +12.05%、mixed CPU/操作 −14.20%。
  相对历史正式 R89，HTTP lane CPU +9.38%、log +29.49%、mixed +4.35%，mixed 吞吐 −3.73%。
  两个窗口均出现增幅，不能称全面无回退。
- 固定语料 logd 没有复现整机日志增幅。历史真实日志正文未冻结，不能定量归因全部日志成本。
- 同机新启动 HTTPD：R92 相对 R89 自身 CPU，configs +1.42%、get +1.66%；活动 R92 比临时 R92
  高 28.34%、15.95%。运行环境、进程历史和监听端点仍是变量，不能宣称证明唯一原因。
- c4 绑核同时限制客户端、服务端与依赖，部分范围收窄、部分扩大，p99 更差；保留生产双核。
  syscall trace 不等于 perf/IRQ 跟踪，不能认定唯一调度根因。
- 50 ms 停放/线程重建在构建机及路由器均可达。TLS 高延迟 clone 增加，fresh 明文 HTTP 没有同样增长。
  gap 不是 RTT；netem 只在构建机私有 namespace，未改管理链路或安装内核模块。
- R92 500 次连接开关后半 250 轮 RSS 增长 0/4 KiB，fd/线程回初值；仅覆盖该有限实验。
- MemAvailable 差 6466 KiB（6.31 MiB），RSS 中位数之和 9606→5320 KiB，是不同口径。
  非运行副本页确实 7508→0→7508→0→7508 KiB，但逐出没有增加 MemAvailable，不能把全部差额
  等同于静态二进制缓存或泄漏。
- freqlist 随机 flags 来自原版未初始化 caller buffer；R92 与清零 C 一致，保留确定的内核限制位。
  跨 boot 的 IPv6 成员与两条 HT width 差异有固定输入控制，但历史邻居表/原始扫描 IE 未采，
  不能称历史帧重放，也不能证明 AP 当时真的切换带宽。
- 直接子进程回收、模拟非 PID 1 watchdog 与有限无线覆盖，都不外推为任意孙进程、硬件复位或所有硬件场景。

## 6. 采集事故与本机证据

以下失败从未改写为成功样本：

1. C deleted udebug 映射不能按旧路径 mincore；失败归档后修正 collector，有效冷窗口未重跑。
2. rpcd 第五轮 SSH exit 255；远端已 COMPLETE，下载逐文件 hash、18 workloads、CPU 区间与健康核验
   通过后保留样本，`run_candidate.py --resume` 续跑其余轮次。
3. HostHints 首次在调用前因设备不支持 `sleep 0.1` 失败；失败目录读回校验后清理，整数等待重跑通过。
4. HTTP 同机探针首次准备阶段把成功但没有 DATA 的 grant/destroy 回复当 JSON；修正后完整重跑，
   旧日志及空临时目录清理证明保留。

原始数据、二进制、镜像、配置、无线标识、session、备份只在 ignored `private/r92/`；不入 Git。
构建机工作区为 `/home/ubuntu/r92-recovery-compat/`。本机关键目录：

- `derived/formal/`、`validation-effective.json`：正式验证证据。
- `device/recovery-01/`、`deployment-r92/`：恢复资料及发布包。
- `device/windows/`、`device/components/`、`device/affinity/`：全部测量。
- `device/http-diagnostics/`、`device/tail-traces/`、`device/reference-cache/`、`device/http-live-pair/`：实机控制。
- `oracle-evidence/`：构建机诊断六份归档，已逐成员重新验证解包内容。
- `device/final-01/`、`device/FINAL_COMPLETE`：最终设备证明；所有 COMPLETE 均已满足。
- `derived/acceptance-final/`：经审核后原样发布到 `reports/…/R92_parts/` 的派生结果。

复核只需已有原始证据，不需要再次部署：

```sh
python3 tools/benchmark/analyze_r92.py private/r92 private/r92/derived/review-new \
  --history reports/ax3000t-stock-openwrt-25.12.5/R89_parts \
  --final private/r92/device/final-01
private/r92/plot-env/bin/python tools/benchmark/render_r92.py private/r92/derived/review-new
```

分析器拒绝复用输出目录。`r92_finalize_device.py` 已完成实际清理，不要把它当成可重复的只读检查再次执行；
需要当前健康时使用 `r84_device_probe.py --mode rust --interface en0`。
