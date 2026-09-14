# R92：剩余四批续接与证据台账

起点 `8b64f1d`（R91 本地候选），最后实机验收版本 R90；性能比较固定为 R89 正式产物。
任务是完成原计划第 2–5 批，包括正式构建、恢复验证、已授权的 Wi-Fi 部署和实机验收。
用户已明确授权全部访问、Wi-Fi 调试及实机运行；部署仍需备份、身份、自动回退和客户端健康门。
本文件是进行中的台账，不能把开发验证表述为实机已完成。

## 第 2 批：异常恢复与资源边界

| 项目 | 开发处置和证据 |
|---|---|
| ubusd U-2 | EOF 后撤销读就绪，待回复排空后关闭；R89 0.79 CPU s/0.8 s 空转反例、候选恢复门通过 |
| ubusd U-8 | 挂起 lookup 用路径下界续传；R89 重复回复，精确 C 原版删除游标时崩溃，候选无重复 |
| netifd F7 | ENOBUFS/截断触发有界扩容及完整设备/载波重同步，失败 dump 待重试；真实溢出门通过 |
| procd F5 | 总线断连仍排空日志、维护计时器并重连；原版/R89/候选对照完成 |
| procd F6 | 非 PID 1 模式继续喂狗；精确 C 也有缺口，属于共有缺陷改进；仅模拟 watchdog 文件 |
| httpd H-07 | 批量 RPC 逐项序列化发送，写失败停止后续调用；原版也有放大问题 |
| rpcd F2/F3 | 保留有界生命周期：提前关管道仍等待/超时回收，超限立即关闭两管道再回收；与 C 的早回复/存活子进程不同 |
| logd F4 | 1 MiB/流、4 MiB 总排队、64 流；断开滞后者；原版同样无界，作为共同资源治理 |

`raw/red-01`、`green-01/02/04/05`、`recovery-03`、`lookup-delete-04` 保留原始控制项与绿证。
原版行的 passed 只表示符合该行明确写出的原版预期，不能称原版满足候选的不变量。

## 第 3 批：协议与数据兼容

开发修复与原版对照已覆盖：HTTP 错误/redirect/100 顺序、403 handler、监听地址、TLS 端口、
CGI Status、ubus 状态；ubusd 属性长度、重复字段、类型、ACL、签名补齐；rpcd fnmatch、ACL 文件
非法 UTF-8 拒绝、原始对象及 UCI 值字节；logd 原始字节/1023 字节截断；fw4 退出/警告/特殊值；
reload-config 共用 JSON 转义及 4096 配置项边界；netifd 全局 restart 同 PID 延迟 re-exec；
procd bundle-only、看门狗复位诊断。

有意差异逐项写入 `docs/contracts/`：HTTP 22 项旧畸形请求差异以
`tests/reference/httpd/r92-deviations.json` 固定；133 例相对 R89 只允许 header-ctrl 和
chunked-huge-size 两项转为立即拒绝（`httpd-fuzz-07`）。保留 HTTP 超时/重连、RPC 子进程回收、
非法授权标识拒绝等边界。UCI 非 UTF-8 rename 原子拒绝，已纠正“C 同 batch 显示原始名字”的旧判断。

fw4：`fw4-05` 16/16、`fw4-upstream-05.log` 31/31、`fw4-r29-05.log` 200/200，
原版 23 次 ucode 崩溃单独记录。原版 ucode 的 stale errno 不复制，候选报告实际 errno。

## 第 4 批：性能与内存

仍待完成：c4 尾延迟离散度与调度追踪、HTTP JSON-RPC c4 CPU、高 RTT 下停放/线程重建、
多轮连接关闭的内存斜率、静态二进制文件页成本。构建机诊断与路由器验收必须分别记录。
路由器缺少 tc/netem/perf 工具及模块；不得为测量更换内核或修改管理链路。

## 第 5 批：覆盖和发布

- 保留 R90 hotplug 专项存活门，netifd 套件当前 31 场景。
- r26 使用同样受控的 apk 版本输出消除 EOF/SIGCHLD 夹具竞争，另保留真实 apk 与信号注入门。
- 已修复 getFeatures 非 ASCII 版本切片崩溃；R89 正式二进制反例已取得。
- 新增 iwinfo 全部 device 方法缺参/不存在设备及 100 次失败探测 fd 稳定检查；
  PTR 截断、坏 additional、指针环、无关 ID、短包后的恢复；两侧通过 `plugin-green-09`。
- 内部复核发现 luci-rpc 畸形 DHCP 标识跨字节切分导致进程退出。原版存活，R89 panic；
  候选按字节切分后通过实际 ubus 回归，租约显示沿用有损 UTF-8 策略并明确入合同。
- UCI 缓存、delta/文件事务、快速/一般解析器继续通过原有内部测试；完整镜像差分正在运行。
- HTTP 缓存合同已改为精确 musl 镜像行为（IMS/IUS 被忽略；ETag 生效）。
- 未完成：正式构建、正式产物全回归、离线安装/回退、发布文档、设备包整理、冷启动验收及实机性能。

## 当前状态与位置

分支 `codex/r92-recovery-compat`。ignored `private/r92/` 保管原始数据；构建机目录
`/home/ubuntu/r92-recovery-compat/`。source-08 的九组件开发构建、十 crate 单元/Clippy、
Python 门测试通过；development-09 只更新 rpcd 的租约切分修复，其余二进制同 development-08。
`plugin-green-09` 五组 × 两侧通过。source-08 的完整功能/恢复/兼容组合仍在跑；
组合期间新增了插件门工具，正式验收将以固定提交重新验证，不能把其混合工具身份当同源正式验收。

实机目前只有只读盘点（`private/r92/device/inventory-01`）：九组件、DHCP、双频 AP、双栈访问健康。
最后已部署的仍是 R90；尚未进行 R92 设备修改。overlay 可用约 13 MiB，五份历史 bundle；
整理前必须逐份归档读回校验，保留精确 C、R89 基线、R90 回退及新候选。
