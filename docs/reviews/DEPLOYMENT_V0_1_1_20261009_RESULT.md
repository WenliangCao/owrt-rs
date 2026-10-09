# v0.1.1 保留配置刷入结果

2026-10-09，按用户简化流程完成 Wi-Fi 升级与快速验收。

- 已于 2026-10-09 09:33:35 UTC 正式发布并标为 Latest：[v0.1.1 · OpenWrt 25.12.5 · AX3000T](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.1.1)。
- 使用 CI `37902724239` 原始字节，仅改文件名；源码 `d72928c9a7d9ed28a9aa2c8d749d31e2a9ed6d33`，内部包 `owrt-control-plane 0.1.0-r3`。
- 固件 SHA-256：`bd6db93f2a7eb5efab226f882d25baa6740b04f6548ee9d051ef2a0ccccfcc68`。
- 当次配置备份：本工作树 `private/deploy-v0.1.1/simple/config-backup.tar.gz`，9,666 bytes，SHA-256 `b74a28a388ec29b482e427c80f3624851af556533f242932312091fc1b0ef5ac`；完整读取归档，四份关键配置与备份吻合。
- `setsid` detached 执行 `sysupgrade -v /tmp/owrt-v0.1.1-sysupgrade.bin`，不加 `-n`；Mac launchd 等待新启动，约 71 秒回连，未超过五分钟。
- 刷前/刷后 WAN ping 均 3/3；2.4/5 GHz AP 正常；LuCI HTTPS 内容和登录页通过（未登录页面按原行为返回 403）。
- 九组件磁盘及 ROM SHA 全部匹配 v0.1.1；六个常驻进程通过 `/proc/PID/exe` 校验，另三个一次性 CLI 按已核对路径执行只读命令通过。
- `/etc/config/{network,wireless,dhcp,firewall}` 字节不变；dnsmasq 的磁盘及实际运行映像仍为原版 C，`ujail` 监督进程另行识别，未操作 dnsmasq 服务。
- 123 份旧 fw4 转储在刷前保存到 `private/deploy-v0.1.1/simple/old-fw4-cores.tar.gz`，未执行清理；刷后抽查未发现新 fw3/fw4 core。未改日志配置，未使用 oracle。
- 无设备端自动回退；没有执行回退。手动回刷使用已核验 v0.1.0（SHA `144c1283da1fb3ead5e4ee7b8b55f66b7d9e872f785892f87cadf9fca6ed0720`）：上传后执行 `sysupgrade -v /tmp/owrt-v0.1.0-rollback.bin`。旧镜像与官方救援镜像均保存在同一私有目录，failsafe 备用为 mesh + lan4。

本次为快速验收，未执行连续三分钟健康窗口或断电测试。原始回连与检查记录保存在同一私有目录。用户取消三分钟采集后，按简化流程重新执行；未发生路由器或网络健康失败。

发布后复核：标签仍指向 d72928c9，八件附件服务端 SHA 与本地一致，旧 v0.1.0 发布及附件未变，v0.1.1 未触发重建；已卸载本机 launchd 回连等待任务。
