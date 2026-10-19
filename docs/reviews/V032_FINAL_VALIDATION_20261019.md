# v0.3.2 最终组合验证

冻结源码 `3fd79124be7ff5228d63a2540a2db6101e6a53f2` 的 Oracle 全组件测试
**1717 通过、0 失败**。另有 benchmark 的 **14 个 Rust + 57 个 Python** 测试及
三个 C 语法检查通过。实际 daemon 回归另列；未修改物理路由器。

## 身份与方法

完整 `git archive` 解包到 Oracle
`/home/ubuntu/v032-final-validation-20261019/source/`，由 `SOURCE_COMMIT` 标记提交。
源码 tar SHA256 为
`c2c291ac7cdee5fba2d9df03a324e4602fde8d4f254a60867085e213bd98109f`。
`identity.json` 保存 archive 内所有普通文件的 hash，测试前后逐项验证未改动。
构建目录独立；DNS platform 的离线派生 lock 另记 hash，不冒充原始输入。

Oracle 是 **aarch64 Linux**。直接调用冻结 `tools/ci_check_core.py` 的现有
`host()` 与 warning 检查函数，执行原有 12 组件 test/doc/example
和 benchmark 工作负载；没有更改该工具要求 x86_64 的 CLI 入口。canonical SDK
构建由独立 CI 执行。Rust 编译器固定 1.98.1，Rust/Rustdoc 均 `-Dwarnings`。

失败判据为退出码、测试结果、warning 分类、实际 daemon 输出及身份；不报告性能收益。
每个顶层 Cargo harness 只计最后一个 summary，子进程重跑自身测试的嵌套 summary
不重复累加。诊断 examples 是编译检查，不算额外业务测试。

原始命令、执行脚本、结果、逐日志 SHA256 保留于上述 Oracle 目录；已同步本地
ignored `private/v032-final-validation-20261019/`。原始日志和 ELF 不进入 Git。

## 全组件结果

| 组件 | passed | failed | 默认 ignored |
|---|---:|---:|---:|
| platform | 10 | 0 | 0 |
| ubus | 73 | 0 | 0 |
| uci | 50 | 0 | 0 |
| reload-config | 20 | 0 | 0 |
| logd | 21 | 0 | 0 |
| httpd | 62 | 0 | 0 |
| fw4 | 19 | 0 | 0 |
| rpcd | 68 | 0 | 0 |
| ubusd | 58 | 0 | 0 |
| netifd | 175 | 0 | 0 |
| procd | 89 | 0 | 0 |
| odhcpd | 79 | 0 | 2 |
| dnsmasq 默认 | 971 | 0 | 26 |
| dnsmasq 显式隔离测试 | 18 | 0 | — |
| dnsmasq/platform | 4 | 0 | 0 |

12 组件为 724 passed；dnsmasq 一组为 993 passed。默认合计 28 ignored 中，18 个
DNS/DHCP/TFTP/接口测试随后在独立 namespace 分别执行并通过，**剩余未执行 10 个**：
8 个依赖外部精确 C 输入的 dnsmasq 配置/缓存差分入口，以及 odhcpd 私有总线和
私有网络 socket 的两个显式环境测试。没有把 ignored 计为 passed。

`core/result.json` SHA256：
`2c0ece8367e1fd18c4119b7918dca5ba8e204dfd5c73110c9134f751613e2b0a`。
`dnsmasq/result.json` SHA256：
`caea24321a6b4844543a537b47a470b722296d7e3175e08cc3a4173a93d9063a`。
两份结果包含逐日志 hash；core 的全部 doc/examples 和 benchmark 命令 exit 0，
compiler/unclassified warnings 为 0。DNS 每个独立场景也无编译 warning。

## canonical 产物与实际 daemon 回归

使用 [core-safe-check 39325243288](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/39325243288)
的 **10 个实际 SDK ELF**，head 是 `c3a770cc52deef4b919192cfcea6dd0127cb83d0`。
它相对 `3fd79124` 仅修改发布进度文档；components、packaging、tools、Makefile、
toolchain 和 workflows 均无差异，比较记录在 `ci-source-equivalence.json`。
下载后核对 CI head/status、10 个 ELF 的 SHA256 与 AArch64 头、core archive hash
和 image manifest 链；收据为 `core-artifacts-verified.json`。

产物目录 `core-c3a770cc/core-candidates/`。`core-target-check.json` SHA256 为
`4efc826fe2f22651277500669bf0d3dad25c2c6c321328b8cc804d5d6d7b7c33`；
`core-manifest.json` 为
`36fea6bf056ea096e8c76cfb2b4304afa43087bef3ab85edb86a025b9e3605d1`。
目标侧全部 recipe、test/example 编译检查通过，compiler/unclassified warnings 为 0，
SDK 元数据 warning 仍保留在原报告，未算成产品编译警告也未删去。

回归只在精确镜像副本及私有 mount/net/PID namespace 中进行。procd 启动夹具仅运行
测试 init 脚本；rpcd/netifd 公共夹具用空设备遮蔽内核日志入口，不读取真实 `/proc/kmsg`。

| 最终 ELF 回归 | 结果 |
|---|---|
| procd 启动恢复 | 7 个初始故障点及空 respawn，8/8；PID 1、sysinit、核心对象、后续 watch 动作均检查 |
| procd 按钮 | C/Rust 各 4 轮 press-only 与 press/release，16/16，动作次序完整比较 |
| procd 本次静态修复 | 类型/instance.update/自身删除/负 timeout 四轮零差异；include 四轮执行、缓存与循环控制通过 |
| rpcd 快照/owner/恢复 | 三套命令通过；恢复含 10 类场景：健康、手动、timer、delta、full、cancel、部分恢复后取消/确认、uid/gid、悬空链接 |
| rpcd MD5 / passwd | 各 4 轮通过；MD5 包含 64 MiB/128 MiB 内存约束和 ACL 控制，passwd 包含成功控制及每轮 5 次失败后无 child |
| rpcd 本次静态修复 | 最终 musl 候选 36 个真实 RPC/文件断言 × 4 轮，144/144；覆盖 freeze、非法 SID、UCI 失败返回、base64、空 name |
| netifd 协议/桥/前缀 | 7 场景 × C/Rust 双方 = 14/14 |
| netifd 无线 | 两边 indices/data/ifname 均通过，核对实际 bridge master 及 typed teardown 输入 |
| netifd R90 生命周期 | 最终 candidate 11/11；本轮未重复 C 的 11 例，不写成 22 例 |
| odhcpd 端口恢复 | UDP/547 释放后主动恢复；健康 RA/socket identity 保持 |

上述五组 **21 条回归命令均 exit 0**，不把它们重复加入 1717 单测计数。
每个 `regressions-*/result.json` 记录最终 ELF hash、完整命令和所有日志 hash：

| 结果文件 | SHA256 |
|---|---|
| regressions-procd/result.json | `2659a96463fab850529121f4872a35bfa6d6aa2e981466c5cec65b81feea98d2` |
| regressions-rpcd/result.json | `91173f3469142862d768ea910a146c6ec7293fb6ac69ac15592603eb6ac95c3b` |
| regressions-rpcd-static/result.json | `5140c703f6cc7f7815a637e7ef7b30f001bb01038334dc3375b5a53260c9c704` |
| regressions-netifd/result.json | `1849253727ae636e64e8dfc0bd84691528a37e5ac04da1edc966226e3f010f41` |
| regressions-other/result.json | `28cae1885ee137434e4af98b7c0eb474aa38c9cf96fe571a014b2a0c998a8e99` |
