# R90：第一批生命周期修复

日期：2026-09-13。代码起点 `39e5d89`，冻结性能基线为 R89 正式构建
`d9c1048` / release-image `34724293710`。仅修改 netifd 与 procd。

本轮状态：开发候选已通过 12 个生命周期场景的原版/候选对照；既有回归、
正式构建与性能矩阵正在进行。**未修改物理路由器，未完成新版本实机验收。**

## 1. 范围与源码身份

| 项 | 处理 |
|---|---|
| netifd F2 | DOWN、无载波但持有主设备 claim 的接口，ifdown 释放设备 |
| netifd F3 | UP/DOWN 时的 data-only 更新也合并，变化才发 IUF_DATA/ifupdate |
| netifd F4 | setup_failed 保留 autostart，LINK_LOST → teardown → 重试 |
| netifd F5 | teardown/abort 期间的 renew 不遗留给下一次 setup |
| netifd F10 | 新 helper 清 task_killed，恢复自动 SIGTERM；这是对原版既有问题的有意改进 |
| netifd F11 | 旧协议的 teardown、notify、回收保留旧配置，连续 reload 使用最后的新配置 setup |
| netifd F12 | available 通知驱动完整生命周期，而非仅修改布尔值 |
| procd F3 | state(spawn=false) 不升级强杀；delete 的强杀期限仍生效 |
| 已修项回归 | 接口删除实际调用 teardown、终止 helper；R89 节拍与 hotplug 修复保持 |

R88 的 netifd 审计混用了较新 `netifd-c/proto-ext.c`。本轮改用镜像匹配的
`cbb83a1857407a28a63dc09412a1f209195914ef`，构建机 Git 工作树 clean。
本地 `netifd-ref` 与它的两个文件逐字节一致：

- `interface.c` SHA256 `3404ca8b45b2e9cd638f11852f52f5dc33f338502a0a9e06a88d68f4ebfc1829`
- `proto-shell.c` SHA256 `414456fcddd798f590d6a9c9c196f0645f1d026933d11100c34ea1dc8aa2a668`
- 镜像 `/sbin/netifd` SHA256 `8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90`
- procd 源码提交 `58eb263d5abe03f8c1280bdfa65a3b052614215d`

R88 F10 在精确原版同样存在。测试明确期待原版在 1 秒内不自动 TERM、最终由
5 秒期限清理，候选则要求及时 TERM 和清理；不将这项改进冒充逐字节等价。
netifd 的缺失方法、全局 restart/re-exec、netlink 溢出、日志等不纳入本批。

## 2. 修复边界与性能保护

- procd 只改到期处理对 halt 的判断；R87/R89 的只读请求分类、维护截止时间、
  就绪等待保持原实现，避免重新引入每查询一次维护或节拍饥饿。
- netifd 不修改状态查询、netlink 订阅、热路径扫描或无线编排。
- 旧配置只在 reload 时临时保存，释放旧协议状态时一并释放；连续 reload 不覆盖
  最初的运行配置，也不增加常驻配置副本。
- data 合并去掉临时 Vec 和已有键的名字分配，仅在新增键时排序。
- helper 正常退出不再等待强杀期限，时间记录保存在专项探针 `timing.json`。

## 3. 验证与红证

入口 `tools/r90_lifecycle_probe.py ROOTFS BINS OUTPUT`：每场景各自的 rootfs 副本、
mount/net/PID namespace，实际进程身份与必需断言集合检查，失败和缺失用例均报红。
`tools/r90_netifd_lifecycle.sh` 把 11 个网络场景纳入 netifd_suite；procd 单独一个场景。

开发候选的 12 场景 × 原版/候选两侧全部符合各自合同；同一探针对 R89 正式
二进制的 12 场景有 10 场景报红（renew_abort 和已经修好的 remove 通过）。
场景含无载波释放、数据变化/重复/迟到、失败重连、teardown/abort renew、二次 helper、
普通/连续/切换协议 reload、remove、available、state-stop 后 delete。

`R90_HOTPLUG_PROBE=1 tools/r71_pid1_probe.sh ...` 延迟 ubusd 5 秒，令 coldplug
命令在连接重试期间退出，再发送后续 lo 事件。原版和开发候选通过；R87 正式
procd 被准确判为 hotplug 队列停滞。默认 r71 不挂载 sysfs；专项模式只运行自制
lo 触发器，不运行构建机硬件的 udevtrigger。

测试开发期间的失败输出全部留在 `private/r90` 对应的构建机工作目录：最初 proc
挂载不匹配 PID namespace；随后把 TEARDOWN 的状态布尔值误当完成；无载波用例
的 veth 对端受设备发现影响。已分别改为 namespace proc、清理/回收断言和隔离对端。
这些夹具失败不作为产品缺陷或通过证据。

## 4. 验收待补

正式构建身份、完整回归结果、R89 对照的 22 项性能矩阵与资源数据在完成后追加。
构建机结果不能替代 AX3000T 实机性能与冷启动验收；后者需要独立部署授权及恢复核验。
