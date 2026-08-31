# 兼容合同 C1-01：配置变更检测与分发（R05）

> 状态：冻结
> 日期：2026-08-31
> 现有实现：`/sbin/reload_config`（base-files，17 行 shell）
> 分类依据：[REPLACEMENT_BOUNDARY.md](../../reports/ax3000t-stock-openwrt-25.12.5/REPLACEMENT_BOUNDARY.md) §3
> 实现授权：**无**。本合同不授权创建 crate。

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

### C-03 文件名含点号者，基线条目必为空

`uci show <name>` 把参数当作 `package.section.option` 元组解析。名为
`dhcp.bak-codex-disable-ipv6-…` 的文件被解析为「包 `dhcp` 的 section
`bak-codex-disable-ipv6-…`」，查找失败，`UCI_LOOKUP_COMPLETE` 未设置，
返回 `UCI_ERR_NOTFOUND`；但 shell 重定向**无论退出码都会创建文件**，
于是基线条目是空文件。

- 证据：SRC `uci/cli.c:package_cmd` 的 `uci_lookup_ptr(ctx,&ptr,tuple,true)` 与
  `CMD_SHOW` 分支；
- 证据：**RUN（C1 Q15）**——`/etc/config/` 有 **7** 个含点文件，基线中恰有 **7** 条
  哈希等于空文件 md5 `d41d8cd9…427e`，其余 12 条各不相同。

**推论 C-03a：这 7 个文件的任何改动都永远不会触发事件**（空 vs 空恒等）。
**推论 C-03b：若其中之一被改名为合法包名，它会立刻变为可检测。**

这是本组件"静默失败"的具体形态，也是选它作为替换候选的直接理由。
替换实现**必须复刻这一行为**，不得"顺手修好"——修好会改变 procd trigger 的触发面。

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
| 体积预算 | 现有实现 17 行 shell；替换实现不得超过 base-files 中同类工具的量级，具体阈值在 R1 定 |
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
