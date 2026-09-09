# R74：P3.3 设备窗口执行完毕（procd-rs 在真机上做过 PID 1）

2026-09-09。授权窗口内在 Xiaomi AX3000T（OpenWrt 25.12.5, r33051-f5dae5ece4,
kernel 6.12.94）上把 procd-rs 作为真实 PID 1 启动、观察、回退，全程按 R72
清单执行。**终态：设备已回到出厂 C procd，无残留。**

## 候选

- procd-rs md5 `b194261d4222f085ef115c2b4c906f75`（e64223c 干净树，含全部
  R73 修复；opt-3 静态 musl）。
- 上机前门槛全绿（oracle，同一 md5）：131+24 单测、r65 v-final 267 markers×
  双侧 diff 0、selftest 双注入能红、r71 双侧机械判定 ok。
- 设备侧 `p33_switch.sh` -h imposter 探针：exit 1 + procd marker present。

## 执行流水（R72 清单逐条）

| 步 | 动作 | 结果 |
|----|------|------|
| 1 | status 基线 | pid1 `/sbin/procd` md5 49ab0576，staged:no |
| 2 | stage 候选 | `/sbin/procd`→b194261d，原件存 `/sbin/procd.c-orig`，运行中 procd 保留旧 deleted inode |
| 3 | reboot #1 | **procd-rs 成为 PID 1**（见下），干净 |
| 4 | ~3 min 观察 | 稳定，无 crashloop |
| 5 | reboot #2 | 二次启动与首次一致（重复性） |
| 6 | undo + reboot | 回到 C procd（49ab0576），staged 清除 |

## reboot #1/#2：procd-rs 作为 PID 1

- `readlink /proc/1/exe` = `/sbin/procd`，md5 = b194261d（Rust）。
- **启动状态行进 /dev/kmsg**（R73 6(f) 修复在真机验证）：
  ```
  - early -          9.28s
  - watchdog -       9.28s / 9.92s
  - ubus -           9.92s
  - init -           9.99s
  - init complete -  18.55s   (#1 18.51 / #2 18.55，稳定)
  ```
  与 C 基线（early 9.23 / ubus 9.79 / init 9.86）在 ~0.1s 内一致——200ms
  poll 主循环没有引入可观测的启动延迟。
- **服务集与 C 逐项相同**：19 个服务全在（cron dnsmasq dropbear firewall
  gpio_switch network odhcpd owrt-httpd owrt-logd owrt-rpcd packet_steering
  sysntpd system ubihealthd ubus ucitrack urandom_seed urngd wpad），14 个
  running:true（其余为 one-shot）。
- `system board`：kernel 6.12.94 / Xiaomi Mi Router AX3000T ✓。
- `system watchdog`：running, timeout 30, frequency 5, magicclose false——与
  C 基线字节相同；/dev/watchdog 在真正被喂。
- wifi OpenWrt-Test 双频起，3 个客户端重连（1+2）。
- `logread` 无任何 procd 相关 error/fail/crash/segv。

## ~3 min 观察窗

- PID 1 存活，uptime 775→1012s 连续推进（未重启）。
- dnsmasq PID 3156 全程不变——无 respawn 抖动/crashloop。
- 14 running:true 不变，watchdog running 不变，客户端保持。

## 回退演练

- 一个操作教训：`/tmp` 是 tmpfs，重启即清；第一次 undo 因脚本被清而失败
  （但 reboot 仍触发，无害地又起了一次 procd-rs——已证过两次）。`c-orig`
  在 overlay 上持久，重传脚本后 `undo` 正常：`/sbin/procd`→49ab0576、
  staged:no、`c-orig` 被 mv 消费。
- 末次 reboot 确认 **C procd 回到 PID 1**（49ab0576），19 服务、wifi、
  客户端全部恢复。设备处于出厂状态。

## 一个真实风险，已知并已处置

reboot #1 后设备约 8~9 分钟才恢复网络可达（真机全服务集 + coldplug
udevtrigger 比命名空间 fixture 慢得多；ns 里 <20s）。这段时间设备失联、
只能物理 failsafe（mesh 键 + lan4 进 /rom）。本次是正常慢启动而非故障，
但**下次窗口应预留 ≥10 分钟不可达预算，并确保有人能物理接触设备**。
（我方 ssh 轮询还踩到本机临时端口耗尽 "Address already in use"——探测循环
要用间隔较大的独立短连接，别高频重试。）

## 结论

P3.3 完成。procd-rs 已在真实硬件上作为 PID 1 完整启动两次、稳定运行、
干净回退，启动时序与服务面同 C 无差。设备现回到 C procd。

**长期跑 procd-rs 的唯一前置**：`sysupgrade`/`validate_firmware_image`
仍是拒绝的（合同记录），刷机前必须先 `p33_switch.sh undo` 回 C——这是
P3 之后独立的一项功能工作，不属于本次窗口。
