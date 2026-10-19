# 任务：去掉 AX3000T 开机时多余的 MT7531 探测（约 1 秒）

先读 `AGENTS.md`、`docs/reviews/DEPLOYMENT_V0_3_1_20261019.md` 和
`tools/ci_build_image.sh`。不在 Mac 上构建；构建走 CI 或 `ssh oracle`。

## 已确认的事实（2026-10-19，只读取证 + oracle 离线试做）

- 真机 dmesg：`[1.612] 8021q ...` 之后 `[2.643] mt7530-mdio mdio-bus:1f: reset timeout`、
  `[2.648] probe ... failed with error -110`，随后 `[2.978] an8855-switch` 正常起来。
  中间约 **1.03 秒**是 MT7531 驱动在等一颗不存在的芯片。
- 原因：OpenWrt 25.12.5 的 AX3000T 是一个通用镜像，
  `target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-common.dtsi:78` 同时声明了
  `switch@1f`（`mediatek,mt7531`，MDIO 地址 31）和 `mfd@1`（`airoha,an8855-mfd`）。
  我们这台是 AN8855 硬件版本（`/sys/bus/mdio_bus/devices/mdio-bus:1f` 没有驱动，
  `mdio-bus:01 -> an8855`）。C 系统下也一样，与 Rust 组件无关。
- AN8855 不依赖 MT7531 探测时顺带的复位：`files-6.12/drivers/net/dsa/an8855.c:2236-2255`
  自己拉 GPIO39 复位并轮询 HWTRAP；MFD probe 不碰硬件。
- Image Builder 不会重编内核：`include/image.mk:745` 在 IB 模式下直接使用预制的
  `build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/xiaomi_mi-router-ax3000t-kernel.bin`
  （一个 FIT：lzma 内核 + DTB）。只改 `image-*.dtb` 文件不会生效，必须重新打包这个 FIT。
- oracle 离线试做（`/home/ubuntu/dtb-trial-20261019/`）：
  1. 用 `dumpimage -T flat_dt -p 0/1` 从原 FIT 中取出内核和 DTB；取出的 DTB 与 IB 的 `.dtb` 逐字节相同。
  2. 运行 `fdtput -t s new.dtb /soc/ethernet@15100000/mdio-bus/switch@1f status disabled`。
     dtc 反编译后与原版对比，只多出一行 `status = "disabled";`。
  3. 用 IB 自带的 `.its`（只把两个 `/incbin/` 路径换成新文件）运行 `mkimage -f` 重新打包。
     新 FIT 里的内核负载与原版逐字节相同（sha1 `a422b6a6bfff051626511cdaf910bdae50365105`），
     DTB 部分等于 `new.dtb`，`mkimage -l` 通过。新 FIT 比原版大 24 字节。
  4. 未做：没有用这个 FIT 打镜像，也没有上机。

## 要做的事

1. **构建改动**：最终发货镜像由 `tools/ci_integrate_image.sh` 组装，用的是官方 stock
   sysupgrade 里的 kernel 卷，并且有"最终 kernel == 官方 kernel"的 cmp 门。所以改动范围是
   `tools/ci_integrate_image.sh` 和 `tools/native_image.py`，`ci_build_image.sh` 的
   IB 产物不是发货镜像。新 FIT 必须从官方 stock kernel 卷派生；若它与 IB build_dir 中的那份
   不同，先报告。原来的 cmp 门改为三条：官方 kernel sha256 等于固定值；最终 kernel 等于新 FIT；
   新 FIT 的内核负载与官方逐字节相同、DTB 只差一行。其他要求：
   - 失败即停（fail closed）。先断言输入的 DTB 和 FIT sha256 等于固定的 25.12.5 值，
     并断言 `switch@1f` 的 compatible 是 `mediatek,mt7531`、原本没有 `status` 属性。
     IB 一旦变化，构建直接失败，不能静默跳过。
   - 打包后断言：内核负载 sha1 不变；DTB 与原版的 dts diff 只有那一行。
   - 设置固定的 `SOURCE_DATE_EPOCH`，例如取 IB 原 FIT 的时间戳，保证两次 CI 构建逐字节相同
     （决定 0018）。注意 `cp` 不会保留 mtime。
   - 在 manifest 中记录原/新 DTB 和 FIT 的 sha256，以及这项改动。
   - 不改内核、不改其他 DTS、不改任何组件 ELF；dnsmasq 的冻结身份门必须照常通过。
   - 镜像构建出来后用两次 release-image CI 运行确认可复现。
2. **离线验证**：对新的精确镜像跑 `native_boot_check`、`native_image_check`、守卫与 APK 检查，
   和 v0.3.1 相同的整套资格检查。另外从镜像的 kernel 卷中取出 FIT，确认 DTB 中
   `switch@1f` 的状态为 disabled。
3. **刷机**：必须先得到用户在对话里明确同意才能刷，按 v0.3.1 的同一流程走（刷前完整备份、
   回滚目标为 v0.3.1 镜像 `099db992…`、守卫、约 3 分钟客户端健康确认、再做一次用户物理断电重启）。
   - `stage` 前在设备上核对硬件确实是 AN8855：`readlink /sys/bus/mdio_bus/devices/mdio-bus:01/driver`
     必须指向 `an8855`。这个镜像从此只适用于 AN8855 版本的机器；MT7531 版本刷上去会没有有线网口。
   - Wi-Fi 管理不受影响。如果交换机起不来，WAN 健康检查会失败，守卫会自动回滚。
   - 分离运行不要用会自动重启的 `launchctl submit`（v0.3.1 时被重启了 78 次），
     完成后立即删除任务。
   - **不要读 `/proc/kmsg`**。它是取走式读取，会和 logd 抢内核日志。只用 `dmesg`。
4. **验收**（两次启动都要记录）：
   - dmesg 中没有任何 `mt7530` 行；
   - `an8855-switch` 的首行时间、`DSA: tree 0 setup` 的时间，与本次基线（2.978 s / 3.352 s）
     对比，预期提前约 1 秒；
   - wan、lan2–4 的链路状态与现在一致；
   - 客户端健康检查全部通过。
   报告中给出两次启动的实测时间差，不要估算。
5. 在 `docs/reviews/` 写一份简短记录，每个任务完成后单独提交（按路径 stage，提交前先看一下
   `git log`，避免把其他会话的改动带进来）。
   推送和发布版本号（是否叫 v0.3.2）由用户决定。

## 不在范围内

不改上游 DTS 文件本身，不自编内核，不改 `-ubootmod` 变体，不顺手做其他优化。
