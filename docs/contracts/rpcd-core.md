# 兼容合同 C7：rpcd 核心对象 `session`/`uci`/`rc`（阶段 7）

> 来源：rpcd @ 28faf640（`session.c`、`uci.c`、`rc.c`、`main.c`），只读副本 `private/stage5/src/rpcd/`；
> 决策 [0013](../decisions/0013-rpcd-core-objects-in-rust.md)。签名以设备 `ubus -v list` 为准。

## 1. session

- `create {timeout:int32}`：默认 300 s；随机 32 位十六进制 id（/dev/urandom 16 字节）；回复
  `ubus_rpc_session`、`timeout`(u32)、`expires`(u64，剩余秒，无计时器为 0)、`acls`（scope→object→
  [function]，scope 与 object 按 strcmp 排序、同一 object 连续归组）、`data`（按键名排序，原始类型）。
- `list [sid]`：无 sid 时逐个会话各发一条 DATA；sid 不存在 → NOT_FOUND；查询即触碰（重置超时）。
- `grant/revoke {sid, scope="ubus", objects:[[obj,fun],…]}`：缺 sid → INVALID_ARGUMENT；无 objects
  → revoke 删整个 scope（grant 时 object/function 为 NULL → INVALID_ARGUMENT）；重复 grant 去重。
- `access {sid, scope="ubus", object, function}`：有 object+function 时回 `{"access":bool}`，匹配规则
  `fnmatch(acl.object, object, FNM_NOESCAPE) && fnmatch(acl.function, function, FNM_NOESCAPE)`；
  否则回 ACL 全表；sid 不存在 → NOT_FOUND。
- `set {sid, values:table}`：空名跳过，同名覆盖，值保持原 blobmsg 类型；`get {sid, keys}`：回
  `{"values":{…}}`，无 keys 回全部；`unset {sid, keys}`：无 keys 清空。
- `destroy {sid}`：默认会话 → PERMISSION_DENIED；销毁时清除该会话的 uci delta 目录。
- `login {username, password, timeout}`：读 `/etc/config/rpcd` 的 `login` 节；密码为空串 → 通过；
  `$p$user` → `/etc/shadow` 中 user 的哈希再校验；否则 `crypt(password, hash) == hash`。失败 →
  PERMISSION_DENIED。成功后按 `/usr/share/rpcd/acl.d/*.json`（glob 排序）建 ACL：组的 `read`/`write`
  表；登录节 `list read/write` 模式先匹配 `!`否定（跳过后续空白）再匹配肯定，`read` 权限隐含
  `write` 检查；scope 为表时 object→[function]，为数组时 function=权限名；每个 scope 另
  grant("access-group", group, perm)。会话 `data.username` 设置为用户名；若存在同名用户的待
  apply 会话则复用它。
- 超时：每次查询触碰；到期销毁。SIGHUP/SIGUSR1：冻结非默认会话到磁盘并重启自身，重启后解冻并
  按用户名重建 ACL。

## 2. uci

- 每次调用先按 sid 设置 delta 目录 `<prefix>/uci-<sid>`（无 sid 用 `/tmp/.uci`），再查
  `session access(sid, "uci", config, read|write)`；缺 config → INVALID_ARGUMENT；无权限 →
  PERMISSION_DENIED；libuci 错误映射 INVAL→INVALID_ARGUMENT、NOTFOUND→NOT_FOUND、其它→UNKNOWN_ERROR。
- `get/state {config, section, option, type, match}`：`state` 额外把 `/var/state` 设为 savedir（追加到
  delta 链末尾）。包级回 `values` 表：每节 `.anonymous`(bool) `.type` `.name` `.index`(u32) 与选项
  （字符串或字符串数组）；节级无 `.index`；选项级回 `value`。`type`/`match` 过滤：match 值按
  string/int64(%PRIu64)/int32(%u)/int16(%u)/int8(!!) 格式化，列表任一项相等或字符串按空白分词任一
  相等；缺失/不完整查找 → 无 DATA，状态按 libuci 错误。
- `add {config, type, name, values}`：type/name 校验；匿名或命名新增；values 中数组→add_list、其它→
  set，非法名 → INVALID_ARGUMENT（继续处理），查找失败 → NOT_FOUND；成功回 `{"section":name}` 并 save。
- `set {config, section|type|match, values}`：`rpc_uci_merge_set`：数组值删旧再逐项 add_list（无有效项
  → INVALID_ARGUMENT）；列表选项遇标量删列表再 set；标量仅在不同时 set。无匹配节 → NOT_FOUND。
- `delete {config, section|type|match, option|options}`、`rename {config, section, option?, name}`、
  `order {config, sections:[…]}`：按 C 语义与错误优先级。
- `changes {config?}`：有 config 回 `{"changes":[[op, section, option?, value?],…]}`（op ∈ add/set/
  remove/rename/order/list-add/list-del，order 的值为 u32）；无 config 回 `{"changes":{cfg:[…]}}`
  仅含有变更且会话可读的包。
- `revert/commit {config}`：存在待 apply 会话 → PERMISSION_DENIED；commit 后发 `service event
  {"type":"config.change","data":{"package":cfg}}`。
- `apply {rollback, timeout=60, sid}`：快照 `/etc/config/*` 与会话 delta 到 snapshot 目录（跳过 `.`
  开头与空文件；不足 3 个 glob 项 → NO_DATA；任一包无写权限 → PERMISSION_DENIED）；逐包 commit+
  事件；rollback 时记 apply_sid 并起计时器。`confirm {sid}`：无 apply → NO_DATA，sid 不符 →
  PERMISSION_DENIED。`rollback {sid}`/计时器到期：恢复快照文件并 commit+事件，会话仍在则恢复 delta。
- `configs`：`uci_list_configs` 排序列表；`reload_config`：2 秒后执行 `/sbin/reload_config`。

## 3. rc

- `list {name, skip_running_check}`：遍历 `/etc/init.d`（readdir 顺序），跳过非 root:root、
  不可执行或 o+w 的脚本；从前 11 个"行首"读取 `START=`/`STOP=`/`USE_PROCD=`；`enabled` =
  `/etc/rc.d/S%02d<name>` 存在且 u+x；`running` 仅在未跳过且 USE_PROCD=1 时执行 `<script> running`
  （3 秒超时，超时则不列出该项）。回复为 name→{start(u16),stop(u16),enabled,running?}。
- `init {name, action}`：name 含 `..` 或 `/` → INVALID_ARGUMENT；脚本权限同上 → NOT_FOUND/
  PERMISSION_DENIED；action ∈ disable/enable/stop/start/restart/reload；执行完成后回 OK（不看退出码）。

## 4. 参考用例

精确 rootfs 双沙箱差分（原：完整 C rpcd；候选：rpcd-rs 注册 session/uci/rc/file/luci + C rpcd
插件目录裁剪）：session 全方法含 login（沙箱内添加测试登录节与 `$1$`/`$5$` 哈希）、ACL 表；uci
全方法在设备 6 个真实包上的读、写、changes、revert、commit、apply/confirm/rollback；rc list（含
skip_running_check）与 init（enable/disable 一个无副作用脚本）。会话 id 与 expires 遮罩。设备门禁
只读：`session list`/`access`（默认会话）、`uci configs/get/changes/state` 原候选相同。

## 5. R92 字节与匹配边界

ACL 复杂模式交给镜像目标 libc fnmatch；ACL 使用 FNM_NOESCAPE，login 授权组/否定组及文件 glob
使用 flags=0。未闭合 `[`、首字符 `]`、POSIX 类、转义星号均由精确原版对照确定。
两侧 daemon 都在 C locale；`?` 不匹配双字节 `é`，R88 对这一点的差异推测撤销。

object 名支持原始字节。function 和会话 id 仍要求 UTF-8：grant/revoke 先选前两个 STRING，
无效第二项使该 pair 跳过，第三项不得递补成另一项授权/撤权；无效 SID 返回 INVALID_ARGUMENT，
而原版为 NOT_FOUND。无效 UTF-8 ACL 文件整份跳过并记日志，不得用 U+FFFD 改写授权标识符；
原版 json-c 可接受这些原始字节。这些为有意的拒绝侧差异，正常文件和其它文件继续加载。

UCI 的 scalar/list 转储（包括 get/state）保留原始值字节；名字校验与 UCI 合同一致。
回归：`r92_compat_probe.py` 的 `rpcd_compat`，覆盖 login 正/负模式、字节值、无效授权及撤权。

## 6. 总线断连时保留回滚（R93）

精确原版使用 libubus 默认 `connection_lost` 回调结束 uloop，进程退出并丢失内存中的
apply 回滚计时器。候选有意改进该故障边界：总线断开或一秒服务端 I/O 预算用尽时关闭旧
连接，保留会话、UCI savedir、apply 状态和受监督的延迟子进程，每秒尝试重连并注册全部对象。
离线仍处理会话过期、子进程回收和 apply 到期；连接和每个对象注册分别有一秒上限，注册之间
检查计时器。明确的 SIGHUP/SIGUSR1 流程继续沿用原有 freeze/re-exec/exit 行为。

到期回滚先恢复所有文件，再排队通知；手动 rollback 也先恢复所有文件，再尝试同步通知。
总线不可用时不依赖 `service event` 成功才完成恢复。未发送成功的
`config.change` 按包名去重保留，在线每秒最多轮转重试一个包，单个永久失败的包不阻塞后面的包，直到 `service event` 回复 OK；
成功项移除，不周期重发。回复丢失可能使 procd 收到重复事件，因此是至少一次交付；事件表示
读取包的当前配置，不保存旧配置内容。总线/procd 恢复前，磁盘已恢复并不意味着执行面已重载。

恢复文件失败时保留快照、apply 所有者和回滚状态，每秒重试；手动 rollback 返回
UNKNOWN_ERROR。配置及仍有效会话的 delta 全部恢复后才清除快照并通知 procd。
恢复一旦开始，所有者的 unchecked apply 与 confirm 也返回 UNKNOWN_ERROR，保留重试；
尚未开始回滚的待确认 apply 仍可由所有者取消保护或确认。单文件先写
同目录临时文件，检查写入及同步，再 rename 并同步目录；保留已有目标的 uid/gid、权限和已有符号链接的
目标。悬空符号链接导致恢复失败并保留快照，目标重新出现后重试；不会用普通文件替换链接。
因此 ENOSPC 不会先截断当前文件。该保证限于当前 rpcd 进程存活期间，不是跨进程
崩溃或多文件断电事务。回归 `tools/test_rpcd_restore_failure.py` 在私有 namespace 中覆盖
手动/定时回滚、配置/delta 目录只读、4 KiB 文件系统写满、恢复中 apply/confirm 拒绝、
非 root 文件 uid/gid 保留、悬空链接及解除故障后的自动恢复。

每次总线连接独占 deferred 完成通道。关闭连接同时丢弃旧 receiver，旧 worker 即使稍后完成，
也不能把旧 peer/sequence/object 的回复发送到新连接；原命令继续按其既有超时/回收规则结束。
该修复不把待完成外部命令自动重试，也不承诺跨进程崩溃持久化未送达事件。

回归 `tools/r93_rpcd_reconnect.py` 在精确 rootfs 的 mount/net/PID namespace 中运行，覆盖
断连及半帧输入下的 apply 文件回滚、会话保留/过期、通知补发及成功后不再重复、旧 worker
完成后的服务；还覆盖在线通知失败、多包回滚不被回复拖延、永久失败包不饿死后续通知。
旧 receiver 隔离另由 channel generation 单测验证。不会连接或更改物理路由器。
