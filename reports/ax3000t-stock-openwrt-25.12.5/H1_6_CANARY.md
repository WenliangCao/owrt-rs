# AX3000T stock / OpenWrt 25.12.5：H1.6 短时 bind-mount canary

> 日期：2026-09-02 10:30Z–10:32Z（用户当日授权）
> 设备效果：候选真实接管 `/sbin/reload_config` 约 1 分钟并向真实 ubus 投递 2 个事件；结束时 switch
> 恢复 `disabled`，原实现、baseline、配置树、daemon 全部不变。原始输出在 Git 外 `private/h1-6-20260902/`。

## 结论

R05 Rust 候选已在实际设备上以真实 caller 路径、真实 baseline、真实 ubus 完成一轮完整 canary：
稳态零事件、新增静默、修改恰好一次、删除恰好一次、切回原实现后静默。C1 合同 c01/c02/c03/c04/c10
的语义在生产环境得到重现。R05 的实机验证到此完成。

## 三批结果

| 批 | 操作 | 观察 |
|---|---|---|
| A | `switch enable` | mount count 0→1，`/sbin/reload_config` SHA-256 变为候选 `b49b054f…`，status `enabled` |
| A | 候选稳态调用 ×3 | 每次 compared 19、changed 空、delivery_failures 0；baseline SHA-256 `da010536…` 三次不变 |
| B | 新建 `h1_canary_probe` 后调用 | compared 19 → baseline 20，零事件（creation-silent） |
| B | 修改后调用 | changed `["h1_canary_probe"]`，delivery success status 0，恰好一次 |
| B | 再次调用 | 零事件 |
| B | 删除后调用 | changed `["h1_canary_probe"]`，delivery success，baseline 回到 19 条且字节等于收口后的 `da010536…` |
| C | `switch disable` | mount count 0，`/sbin/reload_config` 恢复原始 `f1527a79…`，status `disabled`/rc 3 |
| C | 原实现调用一次 | 零事件，baseline 字节不变（切回静默） |
| C | 复核 | drift 0/19，`/overlay/upper/etc/config` 无残留，`/tmp` 无残留，netifd/odhcpd/dnsmasq pid 与启动时间不变，package 仍 installed |

## 爆炸半径实测

- 两个真实 `config.change` 事件的 package 是 `h1_canary_probe`，无任何 procd trigger 订阅，设备无响应。
- 唯一残留是候选创建的 0 字节 tmpfs 锁文件 `/var/run/reload-config-rs.lock`，重启即消失。
- 覆盖层写入仅限一个约 30 字节的临时 UCI 文件，已删除。

## 尚未验证

- 候选尚未经历**启动时**调用（`/etc/init.d/boot` S10 那一次）；当前 bind mount 重启即失。
- 候选把 JSONL trace 写到 stderr，原实现完全静默；接管默认路径前需要把 trace 改到 syslog。
两点由执行计划阶段 1 处理。
