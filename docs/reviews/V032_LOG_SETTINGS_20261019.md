# v0.3.2 日志配置迁移

## 来源和边界

最早现存 `private/backup/2026-09-03/cfg-backup.tar.gz` 的 system 配置已经包含
`log_size=128`、`conloglevel=8`。匹配 OpenWrt 25.12.5 的 `config_generate`
只生成 `log_size=128`，没有生成 conloglevel；stock image 没有预生成的
`/etc/config/system`。因此不能把 8 说成 25.12.5 的 UCI 默认值，也没有证据确定
它由谁、在哪次操作写入。

进一步核对精确镜像的 LuCI：`view/system/system.js` 把 conloglevel 的第一个
选项设为 8，未设显式 default；`form.js` 的 ListValue 默认 optional=false，并把
原 keylist 顺序传给 `ui.Select`。`ui.js` 在这种情况下不插入空选项，原配置缺省时
select 会落到第一项；表单 parse 会把与缺省配置不同的非空值写入 UCI。
因此保存 LuCI System 页面是一个能写入 8 的明确代码路径，而不是 config_generate
的默认值。**这是源码解释的可能来源，不能证明历史上实际发生过哪次页面保存。**
当前设备与 09-03/09-10 两份完整 overlay 备份均没有 `.ash_history`，无法进一步归因。
三份精确 JS SHA256 分别为 system.js
`de84bf99630270a5a4acb4e267dbc1daaa62aac288f7490932b7e9d0ff7e68b0`、form.js
`b68bebcbb5eef7256790b9dcb821bf6b1d4104b72fb076dda2e67268d7254787`、ui.js
`8deb2472a0da3a8cb50b0b45a9fb8e7b1b0bf4b7f6fa141aa7233b5387664441`。

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

## 部署窗口的迁移指纹

旧 `native_deploy_window.py` 在新 boot 仍要求 system 的旧字节 hash，合法迁移会一直
无法确认。gate 现在可携带固定的 `log_settings_migration` 对象，且只能包含
`system_sha256`、`marker_sha256` 两个小写 SHA256；它们必须来自最终镜像加实际备份
的离线迁移预演。stage-ready 记录该对象，activate/observe 要求原样匹配。

stage/activate 前仍核对原来的全部配置和保护文件。仅新 boot 初次身份校验及最终
确认前的两次检查，将已有 `/etc/config/system` 的期望替换为绑定 hash，并要求
`/etc/owrt-log-settings-v1` 精确匹配 marker hash。没有任意路径例外，其他配置与保护
文件仍逐项完全相等；无迁移字段保持原行为，最终确认收据保留采用的迁移指纹。

Oracle `/home/ubuntu/v032-deploy-migration-20261019/evidence/` 保存同一最终测试代码的
`red-final.json`、`green-final.json` 及每轮日志 hash。合法迁移用例在旧 driver 四轮均
退出 1；修后 11 个 ObserveOnly 方法（含子场景）四轮全绿，完整既有工具套件
**25/25**。覆盖 19 配置/12 保护、错误或缺失 marker、system/network/保护文件篡改、
首次健康后到最终确认前的改动、stage 前拒绝新 hash、空/坏/多键 schema 和 stage
收据变化。SSH/scp/Popen 全部由 fixture 拦截，时钟受控；这不是设备 180 秒健康观察，
也没有连接路由器或刷写。独立只读 diff 复核未见新增阻断。

修后 driver SHA256：
`d9bbba1a5e7c4cb484db03bdbe3662fc5227b8e536c03936248fa659841bd2f6`。
仅工具和测试改变，组件源码与既有 ELF 资格不变。
