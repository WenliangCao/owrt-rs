# 决策 0007：R05 以开机 bind mount 转正，trace 改写 syslog

> 日期：2026-09-02
> 状态：已定
> 阶段：阶段 1（R05 收官）

## 背景

H1.6 canary 证明 0.1.0 候选在真实 caller、真实 baseline、真实 ubus 下与原实现一致。要让它成为
开机默认路径，还差两件事：bind mount 重启即失，没有人在启动后重新挂载；候选把 JSONL trace 写到
stderr，而原 `/sbin/reload_config` 对 stderr 完全静默，接管后 CLI 调用者会看到多出来的输出。

## 决策

1. **trace 默认写 syslog**：候选 0.2.0 把每行 JSONL 作为一条 `daemon.info` 报文发到 `/dev/log`，
   tag `reload_config`，致命行用 `daemon.err`。`--trace-stderr` 保留 stderr 输出供 harness 与手工
   调试。`/dev/log` 不可用时普通行丢弃、致命行回落 stderr。不引入第三方 crate。
2. **不替换文件，只在开机后重新挂载**：package 增加 `/etc/init.d/owrt-reload-config`（START=11）。
   S10 `boot` 那一次调用仍由原实现处理，S11 之后的所有调用走候选。原 `/sbin/reload_config` 文件
   永不修改，`disable` 或断电即回到原实现。
3. **开机接管有独立开关**：`owrt-reload-config-switch boot-enable on|off|status` 管理
   `/etc/owrt-reload-config.boot-enable`。安装、升级默认关闭；卸载时关闭并移除 init 脚本符号链接。
4. **验证方式**：R1/V1 harness 增加 `--trace-stderr` 与 init 脚本/boot-enable 生命周期断言，其余
   11 个合同用例、6 个故障用例与 package 生命周期检查沿用。设备侧一个约 3 分钟窗口。

## 后果

- 开机接管后，`reload_config` 的行为差异只剩 syslog 中多出的 trace 行；`logread -e reload_config`
  成为观察投递结果的入口。
- 候选出错不会影响启动：启动期那一次调用始终由原实现完成。
- 开机接管把 bind mount 从"一次性实验"变成"持久默认"，因此它需要用户单独授权一次。
