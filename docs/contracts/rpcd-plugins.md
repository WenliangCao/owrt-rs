# 合同 C5：rpcd 插件层对象 `file` 与 `luci`

> 冻结日期：2026-09-02
> 依据：rpcd 2026.06.04~28faf640 `file.c`、`ucode.c`、`session.c`；LuCI 26.180 `/usr/share/rpcd/ucode/luci`
> 与 `/usr/share/ucode/luci/sys.uc`；设备实测 `ubus -v list file|luci`。

## 1. `file` 对象

| 方法 | 参数（类型） | ACL（scope `file`） | 回复 / 状态码 |
|---|---|---|---|
| read | path S, base64 B, ubus_rpc_session S | read | `{data}`；文件 ≥ 262144 字节 → NOT_SUPPORTED(8)；读到 0 字节 → NO_DATA(5)；sysfs 大小 0 按 4096 读 |
| write | path S, data S, append B, mode I32, base64 B, ubus_rpc_session S | write | 无数据；缺 data → INVALID_ARGUMENT(2)；`open(O_CREAT|O_WRONLY|O_TRUNC/APPEND, mode 默认 0666, umask 0)`，写后 fsync + sync |
| list | path S, ubus_rpc_session S | list | `{entries:[{name, type,size,mode,atime,mtime,ctime,inode,uid,gid,user?,group?, target?:{name,…}}]}`，用 lstat；符号链接附 target（stat 失败则 `type:"broken"`） |
| stat / lstat | path S, ubus_rpc_session S | list | `{path, type,size,mode,atime,mtime,ctime,inode,uid,gid,user?,group?}` |
| md5 | path S, ubus_rpc_session S | read | `{md5}`；非普通文件 → NOT_SUPPORTED |
| remove | path S, ubus_rpc_session S | write | 目录递归删除；无数据 |
| exec | command S, params A, env T, ubus_rpc_session S | exec：先查规范化可执行路径，再查 "路径 参数..."（≤1024 字节，≤253 个参数） | `{code, stdout?, stderr?}`；有会话且带 env → PERMISSION_DENIED(6)；命令不存在 → NOT_FOUND(4)；单流 > 262144 字节 → NOT_SUPPORTED；超时（rpcd `-t`，设备 30 s）→ TIMEOUT(7) |

通用：path 先按 file.c 规则规范化（合并 `/`、消解 `.`/`..`、去尾 `/`）；无 `ubus_rpc_session` 时不做 ACL
检查（本机 root 调用）；errno → 状态码：EACCES→6、ENOENT→4、ENOTDIR/EINVAL→2、其它→9。参数类型不符
或未知参数由 ubusd/调用方约定，本实现按 blobmsg 策略只取已知字段。

## 2. `luci` 对象（21 方法）

getVersion、getInitList(name)、setInitAction(name, action)、getUnixtime、setLocaltime(localtime I)、
getTimezones、getLEDs、getUSBDevices、getConntrackHelpers、getFeatures、getSwconfigFeatures(switch)、
getSwconfigPortState(switch)、setPassword(username, password)、getBlockDevices、setBlockDetect、
getMountPoints、getRealtimeStats(mode, device)、getConntrackList、getProcessList、getBuiltinEthernetPorts、
getOdhcp6cStats。返回对象逐字段与 ucode 脚本一致（含 `{ result: … }` / `{ error: … }` 包装、缺省值
`null`、整数在 int32 范围内为 u32 否则 u64、布尔为 u8）；返回非对象时状态 NO_DATA。参数校验同
ucode.so：未知参数或类型不符 → INVALID_ARGUMENT，`ubus_rpc_session` 例外。

## 3. 验证

1. 离线：在精确 rootfs 副本中，同一组请求（每方法至少一例，含错误路径）对原 rpcd（file.so、ucode.so）
   与 rpcd-rs 的回复做结构比较（忽略时间戳、计数类易变字段），状态码必须相同。
2. 设备：`enable` 后用 `ubus call file|luci …` 只读子集复核；LuCI 登录后页面可用由用户确认；
   `disable` 恢复原插件。
