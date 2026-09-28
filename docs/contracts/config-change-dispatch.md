# 兼容合同 C1-01：配置变更检测与分发（R05）

> 状态：冻结
> 日期：2026-08-31
> 现有实现：`/sbin/reload_config`（`procd` package，17 行 shell）
> 分类依据：[REPLACEMENT_BOUNDARY.md](../../reports/ax3000t-stock-openwrt-25.12.5/REPLACEMENT_BOUNDARY.md) §3
> C1 原始实现授权：**无**。R1.1 门通过后仅授权仓库内实现；不授权部署或设备切换。

> R1 勘误：C-03 已按 [决策 0002](../decisions/0002-correct-dotted-name-contract-boundary.md)
> 收窄；R1.1 可观测 oracle 通过后，后续提交可创建唯一的 R05 crate。

## 0. 合同来源声明

本合同**由现有实现的证据推导**，不是从某个 Rust API 反推。每条行为标注证据等级：

| 等级 | 含义 |
|---|---|
| DEP | 部署镜像中的文件内容 |
| SRC | 固定 revision 的上游源码 |
| RUN | 本设备只读观察（I0.7 / C1 Q15） |

未被证据覆盖的行为**保持未定义**，见 §8。不在本合同中擅自标准化。

## 1. 职责边界

**输入**：`/var/run/uci/` 与 `/etc/config/` 两个目录的文件集合，以及上一轮的基线
`/var/run/config.md5`。

**输出**：对每个"与基线不一致"的条目发一条 ubus 事件，并重写基线。

**不负责**：判断配置内容是否合法、决定哪个服务该重载、执行重载。那些分别属于
各服务的 `validate` 与 procd 的 trigger 匹配。

## 2. 算法（DEP：`/sbin/reload_config` 全文 17 行）

```text
1. rm -rf /var/run/config.check ; mkdir -p /var/run/config.check
2. for config in /var/run/uci/* /etc/config/* :
     跳过非普通文件
     name = basename(config)
     若 /var/run/config.check/<name> 已存在则跳过        # 先到先得
     uci show "<name>" > /var/run/config.check/<name> 2>/dev/null
3. 若 /var/run/config.md5 存在：
     对 md5sum -c 输出中每个 FAILED 行取路径，basename 后
     发 ubus call service event {"type":"config.change","data":{"package":"<name>"}}
4. md5sum /var/run/config.check/* > /var/run/config.md5
5. rm -rf /var/run/config.check
```

## 3. 必须复刻的行为

### C-01 扫描集合是"目录里的文件"，不是"有效的 UCI 包"

`/etc/config/` 下**每个普通文件**都进入扫描，无论它是不是合法 UCI 包。

- 证据：DEP 算法第 2 步；RUN：本设备 `/etc/config/` 有 19 个文件，基线记录 19 条。

### C-02 `/var/run/uci/` 优先于 `/etc/config/`

同名文件先到先得，glob 顺序决定 `/var/run/uci/` 在前。

- 证据：DEP 第 2 步的 `[ -f … ] && continue`。
- RUN 限制：本设备 `/var/run/uci` **不存在**，该分支未被观察。标为 SRC-only。

### C-03 本设备 7 个无法解析的含点文件名产出空条目

`uci show <name>` 把含点参数当作 `package.section.option` 元组解析。名为
`dhcp.bak-codex-disable-ipv6-…` 的文件被解析为「包 `dhcp` 的 section
`bak-codex-disable-ipv6-…`」，查找失败，`UCI_LOOKUP_COMPLETE` 未设置，
返回 `UCI_ERR_NOTFOUND`；但 shell 重定向**无论退出码都会创建文件**，
于是基线条目是空文件。

- 证据：SRC `uci/cli.c:package_cmd` 的 `uci_lookup_ptr(ctx,&ptr,tuple,true)` 与
  `CMD_SHOW` 分支；
- 证据：**RUN（C1 Q15）**——`/etc/config/` 有 **7** 个含点文件，基线中恰有 **7** 条
  哈希等于空文件 md5 `d41d8cd9…427e`，其余 12 条各不相同。

**推论 C-03a：在对应 tuple 继续无法解析的条件下，这 7 个文件自身的任何内容改动都
不会触发事件**（它们的内容根本没有被读取，空 vs 空恒等）。
**推论 C-03b：若其中之一被改名为合法包名，它会作为新增包静默进入下一份基线；
此后的内容变化才可检测。旧的含点条目则按删除发一次事件。**

**边界 C-03c：含点号本身不等于空条目。** 如果 `package.section` 或
`package.section.option` 能完整解析，`uci show` 会输出对应元素。例如已有 section
`dhcp.state` 时，同名目录项会得到非空规范化输出。源码反例由参考用例 c11 固定。
替换实现必须复刻 `uci show` 的查找结果，禁止把 `"." in filename` 当成空条目判据。

这是本组件"静默失败"的具体形态，也是选它作为替换候选的直接理由。
替换实现**必须复刻当前 7 个 tuple 的查找失败与空输出**，不得改成直接读取备份文件内容；
否则会改变 procd trigger 的触发面。

### C-04 新增、修改、删除三者不对称

| 事件 | 基线中有条目？ | 生成检查文件？ | `md5sum -c` | 是否发事件 |
|---|---|---|---|---|
| 修改已有配置 | 是 | 是（内容不同） | `FAILED` | **发** |
| 删除配置 | 是 | 否 | `FAILED` | **发** |
| 新增配置 | 否 | 是 | 不在比对范围 | **不发** |

删除与修改**信号完全相同**，调用方无法区分。

- 证据：SRC busybox 1.37.0 `coreutils/md5_sha1_sum.c:322-330`——
  `hash_value = hash_file(...)` 对缺失文件返回 NULL，条件
  `hash_value && strcasecmp(...)==0` 为假，走 `printf("%s: FAILED\n", …)`。
  校验和来源包 hash 已核对（`3311dff3…43a4`）。
- 推论：删除只会触发**一次**事件；第 4 步重写基线后该条目消失。

### C-05 首次运行不发任何事件

`/var/run/config.md5` 不存在时整个第 3 步被跳过，只建立基线。

- 证据：DEP `[ -f $MD5FILE ] && { … }`。
- 运行含义：基线在 tmpfs 中，**每次重启后第一次调用只建基线**。
  这正是 `/etc/init.d/boot` 启动时那次调用的作用。

### C-06 比较的是规范化输出，不是文件字节

比较对象是 `uci show` 的输出，不是 `/etc/config/<name>` 的原始字节。
注释、空白和排版差异不产生事件。

- 证据：DEP 第 2 步。
- 合同要求：替换实现必须产出**与 `uci show` 逐字节一致**的规范化输出，否则基线
  在新旧实现之间不可迁移。该等价性由 V1 差分验证，不由本合同断言。

### C-07 事件载荷格式固定

```json
{"type": "config.change", "data": {"package": "<name>"}}
```

经 `ubus call service event` 发往 procd 的 `service` 对象。

- 证据：DEP 第 3 步；RUN：I0.7 Q05 观察到 `service.event` 签名为
  `{"type":"String","data":"Table"}`。

### C-08 顺序确定但无重试、无确认

事件逐条发出。**顺序是确定的**：`md5sum -c` 按基线文件的行序遍历，而基线由
`md5sum /var/run/config.check/*` 生成，即 shell glob 的字典序。所以事件顺序 =
变更条目在基线中的字典序。

但**不重试、不等待订阅方确认**。发送失败不影响后续条目，也不影响第 4 步的基线重写。

- 证据：DEP 第 3、4 步的无条件顺序执行；SRC busybox `md5_sha1_sum.c` 的
  `while (xmalloc_fgetline(...))` 逐行遍历。
- 合同要求：替换实现**必须复刻这个字典序**，因为订阅方是否隐式依赖它尚未验证
  （见 §8）。不得改为并发或其他顺序。
- **风险 RK-01 的根源**：基线在事件发送成功与否之外被无条件重写，
  因此一次失败的投递会被基线"吸收"，此后永不重发。

## 4. 调用方（每个都需要测试场景）

| 调用方 | 触发时机 | 证据 |
|---|---|---|
| `/etc/init.d/boot` 的 `boot()` | 每次启动，`uci_apply_defaults` 之后 | DEP `/etc/init.d/boot:60` |
| rpcd `uci.apply` / `uci.reload_config` | LuCI 提交配置 | RUN：I0.7 Q05 `uci` 对象有 `reload_config` 方法 |
| 人工调用 | 管理员在 shell 中执行 | DEP |

**订阅方**是 procd 的 config.change trigger 集合，本设备实测 10 条 ucitrack 注册
加各服务自身的 `procd_add_reload_trigger`（I0.7 Q06）。

## 5. 失败边界与爆炸半径

| 维度 | 内容 |
|---|---|
| 失败模式 | **静默**。漏发事件不报错，目标服务继续使用旧配置 |
| 爆炸半径 | 一个配置包对应的服务；不影响启动、不影响数据面转发 |
| 持久副作用 | 仅 `/var/run/config.md5`（tmpfs），重启即失 |
| 恢复 | 删除 `/var/run/config.md5` 后下次调用重建基线；无不可逆状态 |
| 权限 | 以 root 运行；只写 `/var/run/` 下两个路径 |

## 6. 回退机制（gate 要求）

替换实现必须满足：

1. 原 `/sbin/reload_config` **保持在镜像中不被删除**；
2. 新实现以不同路径安装，通过一个显式开关切换调用方；
3. 回退动作是"把调用方改回 `/sbin/reload_config`"，不需要重启、不需要重刷；
4. 两个实现共享同一基线文件格式（`md5sum` 输出格式），使得**任意时刻切换都不会
   产生虚假事件风暴**——这是 C-06 逐字节等价要求的实际理由。

第 4 条是可测试的：切换后第一次运行必须产生**零**事件。

## 7. 资源与版本范围

| 项 | 值 |
|---|---|
| 目标 | `aarch64_cortex-a53`，musl |
| 兼容版本 | OpenWrt 25.12.5 `r33051-f5dae5ece4`，busybox 1.37.0，uci `66127cd7` |
| 体积预算 | R1 冻结为 **512 KiB** 的 stripped AArch64 静态 ELF；当前产物 432,248 bytes |
| 运行频率 | 每次启动一次，加每次配置提交一次 |

## 8. 明确保持未定义的行为

以下行为**不在本合同范围内**，替换实现不得依赖，也不得擅自标准化：

| 项 | 为什么未定义 |
|---|---|
| `/var/run/uci/` 存在时的优先级实际效果 | SRC 可推导，但本设备该目录不存在，无 RUN 证据（C-02） |
| 同一配置在一次运行中被并发修改 | 无跨进程写锁；窗口需制造才能观察（OQ-05） |
| `uci show` 对畸形配置文件的输出 | 未观察；本设备 12 个合法包全部正常 |
| 事件投递失败时的行为 | 现有实现不检查 `ubus call` 的退出码 |
| 订阅方是否依赖事件顺序 | 顺序确定（C-08），但没有证据表明任何订阅方依赖它；因此复刻顺序是保守要求，不是已知需求 |
| 基线文件被外部损坏 | 未观察 |

## 9. 与 RK-01 的关系

RK-01 要求：**替换实现必须先让"变更已送达"可观测，再改变检测方式。**

本合同据此规定实现顺序：

1. **先**在不改变 §3 任何行为的前提下，增加投递结果的可观测性
   （至少记录：本轮比对的条目数、判定为变更的条目、每条事件的发送结果）；
2. 用该可观测性证明新旧实现在同一输入上产生**相同的事件集合**；
3. **之后**才允许考虑改变检测机制本身（例如更细的粒度）。

第 3 步不在本合同范围内，需要新的合同。

## 10. 参考测试

见 [tests/reference/config-change-dispatch/](../../tests/reference/config-change-dispatch/)。
每个用例标注证据等级，SRC-only 的用例不得被当作已验证行为。

R1.1 的精确 rootfs oracle、golden traces 与故障观察见
[R1_REFERENCE_ORACLE.md](../../reports/ax3000t-stock-openwrt-25.12.5/R1_REFERENCE_ORACLE.md)。

R1.2 候选用同一精确 rootfs 的真实 `uci` 与 BusyBox `md5sum` 对跑：11/11 用例的事件
顺序、事件集合和完整基线字节均与原实现一致；6/6 故障注入通过。见
[R1_IMPLEMENTATION.md](../../reports/ax3000t-stock-openwrt-25.12.5/R1_IMPLEMENTATION.md)。

## 11. 资源边界与转义（R92）

候选最多扫描 4096 个去重后的配置 basename，合并两个目录计数；隐藏文件与非普通文件不计入，
重复 basename 只计一次。超过 4096 立即报 invalid input，在调用 uci/md5sum/ubus 之前终止，
清除本轮 config.check，保留既有 config.md5。原 shell 没有此硬上限；保留它用于限制小设备资源，
不是把溢出条目静默忽略。基线和 md5sum 输出上限为 4096×320=1310720 字节。

原 CLI 投递路径的 payload 与 trace 复用同一个 JSON escaping 实现，统一引号、反斜杠及所有 ASCII 控制字节。
进程内投递直接生成等价 blobmsg 字符串，保留原始文件名字节，不经过 JSON 或有损转换。
trace 接口是 UTF-8，文件名展示仍使用既有有损转换，
因此不能用 trace 展示值作为原始文件名证据。原 shell 不转义这一缺陷不复刻。
边界单测验证 4096/4097、重复/隐藏文件、失败后基线保持以及全部 32 个控制字节。

## 12. R95：进程内规范化的等待边界

规范化在进程内执行，不要求启动 `uci` 子进程。每个扫描条目使用一次
`--timeout-ms` 预算（默认 10 秒），配置、覆盖配置与 delta 文件的锁共用同一个截止时刻，
不在每个锁上重新计时。只有本调用方显式启用 UCI 的预算；普通 CLI 和其他库调用方维持原阻塞行为。

持锁竞争时使用非阻塞 flock，每次重试间隔最多 10 ms，并检查 SIGINT/SIGTERM 的取消标志。
文件读取和解析循环也协作检查预算；这不宣称能抢占任意内核文件系统操作，或在调度延迟下提供硬实时保证。

超时 trace 为 `normalization/timeout`，本条目按已经渲染的字节归一化，继续后续包和既有基线推进策略；
配置/delta 锁加载阶段尚未渲染，所以输出为空，等同旧版在该阶段终止 `uci show` 的情形。
不得把 delta 锁超时吞成“没有增量”，也不得缓存部分加载的包。下一次加载须能观察完整 delta。

规范化期间取消时退出 75、不投递事件、不推进基线；投递期间取消仍按既有规则停止后续投递并保留基线，
已经发送的事件不会被撤销。实机覆盖配置/delta/覆盖配置三种锁的超时、SIGTERM、重试恢复及基线/事件断言，
见 [R95 修复记录](../reviews/R95_DEFECT_FIXES.md)。


## 13. 2026-09-29：进程内顺序事件投递

投递复用共享 ubus wire client，没有新增第三方库或常驻进程。每条事件单独启动
`--timeout-ms` 预算，连接/HELLO、对象查询与最终 STATUS 共用绝对截止时间；每条重新查询
`service`，只复用成功连接。等待 STATUS 代表 service.event 请求完成，不代表服务重载完成。

取消检查贯穿连接队列、HELLO、发送背压、完整帧读取及等待回复；等待中最多每 10 ms 检查，
属于协作式边界，不承诺调度或内核操作的硬实时抢占。进入下一条投递和基线
提交前再次检查。超时或投递失败丢弃连接，继续后续条目，按既有策略推进基线；状态不明的
事件不重试。旧连接在尚未发送事件的对象查询阶段断开时，可在原截止时间内重新连接查询。

调用权限仍由原 ubusd 根据进程凭据执行；对象查询与调用错误采用精确镜像非 tty ubus CLI
的退出码映射：连接失败 255、查询失败 +status、调用失败 (-status)&255。本地总预算耗尽
仍记录 delivery/timeout；远端 STATUS_TIMEOUT 是调用失败，不能伪装成本地超时。CLI 的
30 秒内部调用上限保留。进程内调用没有 exec/spawn 阶段；删除 ubus CLI 文件不再是运行依赖故障。

payload 直接编码成 blobmsg 字符串，保留原始文件名字节和既有 JSON 解析后的值。
trace 仍按 §11 使用原有 JSON 展示规则。故障门通过私有精确 C ubusd 与无触发器的 service
协议接收器注入状态、延迟和断连；不再依赖替换 ubus 命令才能覆盖实际投递路径。
