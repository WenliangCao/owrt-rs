# AX3000T stock / OpenWrt 25.12.5：R1 精确参考 oracle 与投递可观测门

> 日期：2026-08-31
> 阶段：R1.1
> 结论：**通过；允许开始创建唯一的 R05 Rust crate**
> 设备操作：无；全部运行在服务器上的一次性 rootfs 副本

机器记录见
[r1-reference-oracle.json](../../manifests/ax3000t-stock-openwrt-25.12.5/r1-reference-oracle.json)。

## 1. Oracle 是什么

工具 [r1_reference_oracle.py](../../tools/r1_reference_oracle.py) 对精确镜像 rootfs 先做
四个 SHA-256 身份门，再复制到临时目录：

| artifact | 用途 |
|---|---|
| `/sbin/reload_config` | 原始 17 行 detector，未修改 |
| `/sbin/uci` | 精确规范化与 tuple lookup |
| `/bin/busybox` | 精确 shell、glob、`md5sum -c` 与管道行为 |
| `/bin/ubus` | 先核对镜像 hash，再只在副本中替换为 test adapter |

test adapter 不改变 detector；它记录每次 `ubus call service event` 的 package 与退出状态，
并按用例返回配置的状态。这样可以观察：本轮比较条目数、变更条目、每次投递尝试的结果。
它只能证明 ubus 调用成功或失败，**不能证明所有订阅方已经处理事件**。

运行使用 `sudo chroot`，写入只发生在临时副本的 `/etc/config`、`/var/run` 和 `/tmp`。
没有访问或修改路由器。

## 2. C1 合同勘误

R1 进入审查发现 C-03 把设备事实错误外推成了“所有含点文件名都为空”。精确 UCI 源码
实际规则是：含点参数按 `package.section.option` lookup；lookup 完整时输出对应元素，
不完整时才为空。

本设备的 7 个备份名仍然全部为空，Q15 结论不变。新增 SRC-only 反例 c11 后，符号模型与
精确 rootfs oracle 都确认 `dhcp.state` 在 section `state` 存在时得到非空条目。勘误见
[决策 0002](../../docs/decisions/0002-correct-dotted-name-contract-boundary.md)。

同时修正来源归属：`/sbin/reload_config` 由 `procd` package 安装；
`temporary hack until configd exists` 注释位于 base-files 的 boot 调用点，不在脚本自身。

## 3. 11 个合同用例的精确差分

符号模型原有 10 个用例，加上 c11 源码反例，共 11 个。工具把 token 转成合成 UCI package，
在精确 rootfs 中先建立基线、再施加输入，比较原脚本实际事件顺序和新基线条目集合。

结果：**11/11 通过**，其中 DEP 5、RUN 2、SRC-only 4。关键事件集合：

| 场景 | 原实现事件 |
|---|---|
| 修改 `dhcp` | `dhcp` |
| 新增 package | 无 |
| 删除 `network` | `network` |
| 修改无法解析的 `dhcp.bak-x` 内容 | 无 |
| 将 `dhcp.bak-x` 改名为新 package | `dhcp.bak-x`；新 package 本轮静默加入基线 |
| `/var/run/uci/dhcp` override | `dhcp` |
| 仅注释变化 | 无 |
| 可解析的 `dhcp.state` | 首次运行无事件，条目非空 |

这一步证明符号模型的事件集合与精确实现一致，也固定了字典序；不证明未来 Rust
规范化输出与 `uci show` 的逐字节一致性，后者仍属于 V1。

## 4. 四个故障 trace

| ID | 精确行为 | 合同地位 |
|---|---|---|
| f01 | 两个事件中第一个返回 7、第二个返回 0；脚本仍退出 0 并重写基线，下一次零事件 | RK-01 的“失败被吸收”得到可执行证据 |
| f02 | `uci` 消失时所有检查文件变空，已有 package 全部发事件，空 hash 被写入基线，脚本仍静默退出 0 | C1 §8 未定义；记录但不擅自作为兼容要求 |
| f03 | `ubus` 永久阻塞时脚本停在投递，基线尚未重写；杀死进程后下一次会重试 | C1 §8 未定义；区别于“返回失败” |
| f04 | 畸形 UCI 使检查输出为空，发一次事件并把空 hash 写入基线 | C1 §8 未定义；留给 V1 差分裁决 |

并发调用仍不进入兼容合同：两个进程共享并删除同一个 `/var/run/config.check`，现有实现
存在竞态。R1 只能把该边界明确标成未定义，不能把一次非确定实验写成合同。

## 5. RK-01 门禁结论

合同 §9 要求的三个观测字段已经具备：比较数、变更条目、逐条投递结果。11 个正常/边界
用例的原实现事件集合已成为 golden trace，4 个故障路径也已记录。

因此 R1 的顺序门通过：**从下一提交开始才允许创建唯一的 R05 crate。** 这不授权部署、
切换调用方或接触设备；也不授权改变 C1 §3 的检测行为。
