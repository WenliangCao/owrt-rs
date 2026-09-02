# AX3000T stock / OpenWrt 25.12.5：H1.5 disabled install preflight

> 日期：2026-09-02
> 状态：`passed_ready_for_authorized_disabled_install`
> 当前设备变化：无；本报告前只执行了 H1.5 只读状态检查

## 判定

H1.5 可以执行。用户已在 H1.5 被明确说明会写 overlay/package database 后明确同意继续；授权
只允许离线安装 V1 的精确 r1 APK，并要求安装结束时保持 disabled。它不允许 enable、bind
mount、真实 ubus、配置修改、baseline 修复、重启或刷机，也不继承到 H1.6。

设备仍处于 H1.4 收尾状态：candidate/package/switch 均不存在，原 dispatcher、baseline、
`/etc/config` tree 和 package database hash 与 H1.4 一致，mount count 为 0。依赖 `libc`、
`procd`、`uci`、`ubus` 已安装，overlay 可用 58,768 KiB，远高于 348,430-byte installed size。

## 固定 artifact

APK 从服务器 V1 构建产物复制到 Git 忽略区，服务器与本地副本一致：

```text
owrt-reload-config-0.1.0-r1.apk
size        184099
mode        0400
SHA-256     02d0c977d68192c28d0ef537a704435d9814fb8e04763cd67d73e00e41e5d9b1
arch        aarch64_cortex-a53
version     0.1.0-r1
```

安装后的 binary 和 switch 必须分别匹配 H1.4/V1 binary hash 与 Git 中 package switch hash，且
必须都是 `root:root 0755`。APK 自身不提交 Git。

## 冻结的动作顺序

1. 再次核对 board/release/kernel、APK、dispatcher、baseline、config、package DB、world、
   scripts、triggers、mount 和可用空间；候选必须仍未安装。
2. 只把 APK 与固定 harness 传到两个固定 `/tmp` 路径，设备端重新计算 hash。
3. 先运行 `apk --no-network add --simulate --allow-untrusted`；simulation 后 package DB/world/
   scripts 和 candidate 文件必须仍未改变。
4. 运行同一 local APK 的真实 `apk --no-network add --allow-untrusted`。
5. 核对 package metadata、三个精确 file-list entry、binary/switch hash、owner/mode。
6. `owrt-reload-config-switch status` 必须输出 `disabled` 并返回约定码 3；dispatcher hash 和
   mount count 必须仍是 original/0。
7. config tree、真实 baseline 和 triggers 必须不变；只允许 APK 管理的 package DB、world、
   scripts 及两个 executable 发生持久变化。
8. 删除所有 `/tmp` artifact，再独立 SSH 验证 installed-but-disabled 状态。

## 失败回退

任何实际安装后的断言失败，harness 和 runner 都会先调用 switch `disable`，再执行：

```text
/usr/bin/apk --no-network del owrt-reload-config
```

回退必须证明 package、candidate、switch 均不存在，原 dispatcher 可见且 mount count 为 0。
不会直接编辑 APK database，也不会调用 `--force`、更新 repository、下载依赖或手工删除受包
管理的文件。

## 安全边界

preflight 已在精确 OpenWrt 25.12.5 rootfs 的 BusyBox ash 中做 syntax check，runner 通过 Python
compile。脚本只包含 `apk add --simulate`、一次实际 `apk add`、失败时 `apk del` 和只读校验；
不存在 enable、mount/umount、ubus、service、network reload、reboot、sysupgrade 或 flash 命令。

机器 gate 的八类负向篡改全部拒绝：删除授权、伪造 H1.6、伪造已安装、移除 offline 限制、
强制 rollback、授权 activation、扩大清理路径和篡改 APK hash。

`h1_5_disabled_install=false` 在本报告中表示实际安装尚未执行。当前授权允许 preflight gate
通过后执行这一轮 H1.5，但 `h1_6_canary=false` 始终保持关闭。

## 证据

- [H1.5 preflight manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-5-preflight.json)
- [device harness](../../tools/h1_5_disabled_install_device.sh)
- [SSH runner](../../tools/h1_5_run.py)
- [H1.4 device result](H1_4_SHADOW.md)
- [V1 validation](V1_VALIDATION.md)
