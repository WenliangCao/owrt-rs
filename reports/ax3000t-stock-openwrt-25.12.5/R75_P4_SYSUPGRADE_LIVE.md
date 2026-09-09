# R75：P4 完成——sysupgrade 面实现，procd-rs 转正为设备常驻 PID 1

2026-09-09。P4 两半都收口：`validate_firmware_image`/`sysupgrade` 从
拒绝变为完整实现（合同 §11 已改写），并在授权窗口把 procd-rs 留在
AX3000T 上长驻。**终态：设备 PID 1 = procd-rs（md5 a5e5b70e），回退件
/sbin/procd.c-orig（C 原件，49ab0576）保留在 overlay。**

## 实现（sysupgrade.rs，提交 79d45b3）

- `validate_firmware_image`：fork/exec `/usr/libexec/validate_firmware_image`，
  stdout 管道 + stdin/stderr→/dev/null；vjson 语义（首个完整 JSON 对象获胜、
  尾随忽略、非对象 = "result is not an JSON object"、空管道/exec 失败 =
  "no JSON input"）；子进程交主循环 reaper，与 C 一样不 wait。
- `sysupgrade`：path+prefix 必填；三布尔门（valid/forceable/allow_backup
  必须齐且为 bool 型）；错误应答表与状态码逐字节同 C（broken→NOT_SUPPORTED
  "…broken and cannot be installed"；invalid 无 force→"Firmware image is
  invalid"；valid 但拒备份→"…doesn't allow preserving a backup"）；然后
  `service_stop_all`（全实例 halt + inittab kill(respawn=-1) + 最长
  term_timeout 睡眠）→ `exec_upgraded`：chroot(prefix)、WDTFD 移交
  （cloexec 清除）、UPGRADE_BACKUP、UPGRADE_OPT_*（大写、含非法字符整项
  丢弃、仅整数、%u）、execvp /sbin/upgraded 替换本进程；exec 失败按 C
  清理并回 UNKNOWN_ERROR 无错误表。
- 已知文本偏离：JSON 解析错误消息的细节来自各自解析器（仅当校验脚本
  输出损坏 JSON 时可见），合同已记。

## 门槛（oracle，候选 md5 a5e5b70e）

- **r75（新，双侧 ns 真 exec 移交探针）首跑即绿**：同一 fixture 下 C 与
  Rust 各自作 PID 1，假校验脚本按序给出 broken/invalid/backup-denied/valid
  四种 JSON——三条错误应答字节同、第四条真的 exec 了 /sbin/upgraded（假件
  记录 argv=`/sbin/upgraded /tmp/fake.img stage2-cmd`、pid=1、
  UPGRADE_BACKUP、UPGRADE_OPT_SAVE_PARTITIONS=1；坏名字/字符串选项未泄漏；
  无 watchdog 时 WDTFD 不导出）——upgraded.txt 与 drive.txt 双侧 diff 0。
- r65 v15 ×2 绿（272 markers，新 F21：validate 全 JSON 回显字节比 + 安全
  错误路径）；selftest 双注入能红；r71 双侧机械判定绿；66 单测；clippy 0。

## 设备窗口（第 5~6 次受控重启）

1. stage a5e5b70e（-h imposter 探针过），`reboot` 同步调用生效
   （nohup/后台链会随 dropbear 会话死——记进 gotchas）。
2. 本次 ~2 分钟即恢复可达（R74 的 8-9 分钟是波动上界，预算仍按 ≥10 min）。
3. 启动时序与 R74 持平：early 9.25 / ubus 9.89 / init 9.96 /
   init complete 18.29s；19 服务（14 running）、watchdog running、双频
   wifi、0 procd 错误。
4. **真机安全半边验证**：`validate_firmware_image` 对垃圾文件回显校验脚本
   JSON（valid:false/forceable:true）；`sysupgrade` 无 force 拒绝——
   `{"error":{"message":"Firmware image is invalid"}}` + rc 248
   (NOT_SUPPORTED)，procd 存活未 exec。真刷机路径不在本窗口验证（r75 已在
   ns 双侧证过 exec 移交）。
5. 3 分钟观察窗：uptime 197→407s 连续、dnsmasq 3155 不变、14 running、
   watchdog running、客户端 2+3、0 错误。
6. **不执行 undo——procd-rs 转正。** 回退路径：`/tmp` 里的 p33_switch.sh
   会随重启消失，但回退只需
   `mv /sbin/procd.c-orig /sbin/procd && reboot`（或 failsafe 进 /rom）。

## 此后的设备事实

- 设备 PID 1 常驻 procd-rs；刷机（sysupgrade CLI/LuCI → ubus system
  sysupgrade）自此走 Rust 代码路径，语义已双侧差分。
- 下一步（P5）：ubusd 冷切换（随重启换 /sbin/ubusd，绕开决策 0015 的
  热切换禁令；先重跑 r22）。netifd wireless + 接管为 P6。
