# v0.3.2 日志配置迁移

## 来源和边界

最早现存 `private/backup/2026-09-03/cfg-backup.tar.gz` 的 system 配置已经包含
`log_size=128`、`conloglevel=8`。匹配 OpenWrt 25.12.5 的 `config_generate`
只生成 `log_size=128`，没有生成 conloglevel；stock image 没有预生成的
`/etc/config/system`。因此不能把 8 说成 25.12.5 的 UCI 默认值，也没有证据确定
它由谁、在哪次操作写入。

匹配 procd `58eb263d` 的 `initd/init.c`、`initd/early.c` 及其余源码没有
`kernel_init`、`klogctl` 或 conloglevel/printk 设置路径，更没有把 8 写回 UCI。
精确 image 的 `/etc/init.d/system` 读取已有 conloglevel 后运行 `dmesg -n`；
这个选项调控制台输出等级，不删除 dmesg 缓冲中的内容。

## 迁移合同

`06-owrt-log-settings` 首次运行把缺省或旧 `log_size=128` 改为 2048 KiB，
把缺省或旧 `conloglevel=8` 改为 4；其他用户值保留。提交并同步 UCI 后，原子写入
独立 `/etc/owrt-log-settings-v1`。缺少 system section 时脚本失败且不写 marker，
由 uci-defaults 在下次启动重试。

`/lib/upgrade/keep.d/owrt-log-settings` 单独保留该 marker。后续运行和保配置升级
都会跳过迁移，因此用户以后主动改回 128/8 也不会再被固件覆盖。无配置升级会重新
生成 stock system 配置并应用本默认值。现有服务布局 marker 保持其原语义。

实验模型是“恢复的旧配置覆盖镜像默认值”，以实际 UCI 值和精确 sysupgrade 的
keep.d 收集结果为判断，未运行真实 sysupgrade、init 服务或内核日志读取器。
`tools/check_log_settings_migration.py` 只在 Oracle 的临时 chroot 中执行；使用
上一版完整 native rootfs 及其中原版 C/Rust UCI，不改宿主或物理设备。

## 验证

Oracle `/home/ubuntu/v032-log-settings-20261019/red-green-final-4x/` 保存四轮
修前/修后 × C/Rust UCI，共 16 组。修前每轮仍为 128/8；修后每轮为 2048/4。
自定义 4096/5、后续主动改回 128/8、marker 被精确 keep.d collector 收入后恢复配置、
stock config_generate 后首次应用和缺失 system section 的重试边界均通过。
最终精确镜像还需确认脚本和 keep.d 文件实际安装，且镜像不预置 marker；该门纳入
完整镜像验收，不把这里的临时脚本安装当成最终产物证明。

`native_image.py` 的 packages 字段改按包名排序。直接提取生产序列化表达式，用
`PYTHONHASHSEED=1/2` 输出的 JSON SHA-256 均为
`f334b493eb0772fc50cb79773524e92024b4357e38b08317e57c47a0f85d28ce`。
原始输出为同一 Oracle 目录 `packages-final-seed-{1,2}.json`。
首次 fixture 未沿用 stock collector 外层的 sort 管道，因不存在的可选 keep 路径退出；
保留 `red-green-4x.log`。SSH 短暂中断及早期 hashseed 工具错误均未计通过。
