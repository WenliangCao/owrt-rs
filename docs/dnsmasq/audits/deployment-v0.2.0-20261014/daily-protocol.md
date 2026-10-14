# v0.2.0 部署前后日常占用观察

本协议固定在两次采集之前。目的为比较这台路由器刷写前 C 与刷写后 Rust 在当时家庭日常流量下的占用，**不测性能高低**。两段不同时间的实际请求量、客户端活动和缓存冷热不能保证一致，差异不能归因于语言或单次查询成本。

## 固定方法

- 每侧连续 **600 秒**，每 **5 秒**读取一次，含首尾共 **121 个样本**。不发合成负载，不强制客户端断连、续租或清空缓存。部署后等正常验收与重启完成、服务稳定后再开始 Rust 段；记录启动后年龄，不把 C 的长期运行状态与 Rust 的新启动状态误称等价。
- 使用相同源码、编译选项和同一 SHA256 的 `daily_usage_probe`，临时位于路由器 `/tmp`。由 Mac 上一条持续的 SSH 连接收取 JSONL。此进程只读 `/proc` 和租约文件，不向 dnsmasq 发信号或修改配置。
- 主审先确认实际 daemon 的 PID、`/proc/PID/stat` 第 22 字段 starttime 和 `/proc/PID/exe` 哈希；不要把 ujail/procd 当成 daemon。探针必须显式传入 PID 与 starttime。目标消失、PID 被复用、读取失败或输出失败时退出，原始失败保留；不自动换 PID 拼接窗口。
- 每点只遍历一次 `/proc` PID→PPID 关系，随后读取 daemon 及本次发现的子进程的 `stat`、`status`、`fd`。进程上限 8192、目标树上限 256；超出则明确失败。**不读取 smaps/smaps_rollup、不运行 ps/top、不按每个子进程重复扫描全 /proc。**
- 保留每个进程的 self user/system、waited-child user/system 累计 ticks、starttime、RSS、RssAnon、FD 数、线程数。计算主进程各指标的 min/median/max，另给进程树采样范围。RSS 和 RssAnon 不等于 PSS/USS；树 RSS 会重复计算父子共享页。
- CPU 给出主进程 self 累计秒数、平均单核占比、每 5 秒 self 占比范围，并单列已回收子进程累计 CPU。`main + waited children` 只有首尾采样都没有活跃/丢失子进程时才附“采样端点无子进程”的条件性口径；`/proc` 并非原子快照，短命 C TCP 子进程可能只体现于 waited counters。存在端点子进程时明确该值不是完整服务树 CPU，不补猜遗漏成本，不把 live CPU 与 waited CPU 粗暴相加造成回收重复。
- `clock_ticks_per_second` 由探针 `sysconf(_SC_CLK_TCK)` 记录；CPU 百分比以一个 CPU 核心为 100%，**不以整机 CPU 占比替代 dnsmasq 成本**。低占用时保留 tick 量化误差：单 tick 的平均占比为 `100 / (HZ × 600)` 个百分点。
- 每点另记探针自身 self ticks、一次采样耗时和进程表规模，汇总采样器自身 CPU 与 wall 范围。这个成本不包括 SSH、Mac 健康探测及分析；不声称它代表所有观测开销。
- 每点仅统计 dnsmasq lease 文件中数字开头的记录数量，排除 DUID 头；文件不可读记 `null`，不能记作零。配置/静态租约/hosts 数量由主审采集脱敏计数，报告不记录地址、MAC、主机名、Wi-Fi 名或密码。

## 低频健康与窗口判断

主审复用 Mac 上的 DNS、LuCI、IPv4/IPv6 HTTPS 健康检查，每 30 秒一组，刷前刷后同方法。健康结果独立保存，不能由资源采样成功推断健康。DNS 探测问题、目标及公网端点按刷前固定输入，避免比较时换探测条件。有效答复延迟记录原值；HTTP 状态的预期按原版现场基线确认。

健康失败时立即停止部署验收进展、检查是否需要按总部署恢复方案回滚，保留失败数据。日常占用采样不做负载，整机 CPU 不是自设停测或输赢门槛。

离线汇总默认要求 121 个连续索引、相同 PID/starttime、稳定 HZ、单调 CPU、持续时间与采样间隔误差不超过 1 秒；无效窗口显式失败。任何补采必须标成新窗口，并保留原始文件。计数器结果本身不证明健康检查通过。

## 命令与证据

由主审在已有 OpenWrt SDK 中编译；不安装包：

```sh
"$SDK_CC" -O2 -std=c11 -Wall -Wextra -Werror -static \
  tools/dnsmasq/daily_usage_probe.c -o private/daily_usage_probe
```

上传 `/tmp` 并核对哈希后，由 Mac 执行（PID/starttime 使用现场值）：

```sh
python3 tools/dnsmasq/daily_usage.py collect \
  --ssh openwrt --probe /tmp/DEPLOY_DIR/daily_usage_probe \
  --pid PID --starttime STARTTIME --lease-file /tmp/dhcp.leases \
  --output private/deploy-v0.2.0/daily-c
python3 tools/dnsmasq/daily_usage.py summarize \
  private/deploy-v0.2.0/daily-c/usage.jsonl \
  --output private/deploy-v0.2.0/daily-c/summary.json
```

Rust 段只改变现场 PID/starttime 和输出目录 `daily-rust`；持续时间与间隔不变。原始 JSONL、stderr、SSH 返回码、起止时间和 SHA256 留在电脑 `private/deploy-v0.2.0/`，不进 Git。部署报告记录产物身份、精确采集时段、服务年龄、脱敏汇总和限制；正式发布验收与这些日常占用数值分别判断。
