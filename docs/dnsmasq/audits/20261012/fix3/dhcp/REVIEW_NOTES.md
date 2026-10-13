# DHCP / startup 独立审计记录

执行日期：2026-10-13。比较 main `be531cee` 与 fix `e3a37f55`；使用本轮重新构建的 release ELF。未修改产品代码，未访问物理路由器。

## 已确认：启动普通 hosts 文件的权限要求收紧

**P2，本分支新增、已复现。** Root 启动并通过 `--user=nobody --group=nogroup` 降权，`addn-hosts` 指向 root:root 0600 文件时，main 初始加载成功，fix 初始加载失败；原来启动即可使用的 DNS 名称消失。修复分支将普通 hosts 读取从降权前移到 EVENT_INIT，因此该文件现须对运行身份可读。

源码：`components/dnsmasq/src/main.rs:880` 只生成 configured hosts，`:1343` drop privileges，`:3558` EVENT_INIT 调用 `reload_hosts_data`，`:3175` 打开实际 hosts 文件。引入提交：`2d9c09ca1`。

这不是疑似：`hosts_permissions.py` 启动真实三方 daemon，用 `/proc/PID/status` 确认实际 UID，并发送 A 查询和 SIGHUP。文件内容仅 `192.0.2.7 secret.test`，基本配置为：

```text
-k -C /dev/null --user=nobody --group=nogroup --pid-file=
--log-facility=- --no-resolv --no-hosts --listen-address=127.0.0.1
--bind-interfaces --port=15353 --addn-hosts=FIXTURE/hosts
```

| 模式 | 实际 UID | C 初始 / HUP | main 初始 / HUP | fix 初始 / HUP |
| --- | --- | --- | --- | --- |
| 0600，`-k` | 65534 | 无答案 / 无答案 | **有答案** / 无答案 | **无答案** / 无答案 |
| 0644，`-k` | 65534 | 有 / 有 | 有 / 有 | 有 / 有 |
| 0600，`-d` | 0 | 有 / 有 | 有 / 有 | 有 / 有 |

所有普通模式中，随后 `chmod 0644` 并 SIGHUP 均恢复答案；全部 daemon 正常退出 0。完整 UID、日志、查询响应及 argv 见 [hosts-permissions.json](hosts-permissions.json)。修复分支记录 `failed to load names from ...: Permission denied`，不是启动进程崩溃。

**边界：** 此变化与目标 C 2.93 一致；C 本来就要求降权后可读，所以它并非 C 兼容性倒退。然而本次用户的合并标准明确为“相对 main 没有新增的功能回归”，不能用 C 一致性掩盖实际的 main→fix 能力收缩。main 的 0600 名称在 HUP 后原本就消失；该既有 reload 问题不算本分支新增。常见 0644 hosts、不降权运行及 debug 模式不受影响。修复建议由主报告决定，本审计未更改产品或权限策略。

复跑（命令中所有输入均为隔离测试产物）：

```sh
R=/home/ubuntu/dnsmasq-audit-fix3-20261013
IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
sudo sh "$R/source-fix/tools/dnsmasq/run_isolated.sh" \
  python3 "$R/private/hosts_permissions.py" \
  --source "$R/source-fix" --image "$IMAGE" \
  --main "$R/private/release-main/dnsmasq-rs" \
  --fix "$R/private/release-fix/dnsmasq-rs" \
  --out "$R/private/dhcp-permissions-RERUN"
```

本轮输出：`$R/private/dhcp-permissions-02/result.json`。脚本见 [hosts_permissions.py](hosts_permissions.py)。

## 修复真实性与回归检查

新编写的 [hostname_matrix.py](hostname_matrix.py) 复用既有 DHCP socket transport/decoder，独立生成 100 组场景，包括普通 REQUEST、rapid commit、普通/FQDN 文本/FQDN wire/首点名称、ignore/generate/tag-if、configured/hosts 权威名称、已存在租约名称保留、无配置名的多 MAC 接管和续租。三方均使用真实 loopback DHCP，完整逐项比较 reply options、lease identities/names、DNS publication、进程存活和退出状态；续租 T1/T2 仅在验证 C 规定的相同随机偏移关系后归一化。

结果：**fix 100/100 与 exact image C 相同，main 80/100；20 处行为变化全部朝 C 修复，无该矩阵覆盖内的新倒退。** [完整派生结果](hostname-matrix.json)。具体确认：多 MAC 租约接管不再因为二次 allocate 失败；rapid commit 在真正选中地址/context 后应用 authority、ignore 和 generated-name；普通 DHCP 路径保持一致。

另独立复跑已有审计探针，均使用本轮 release-fix 与 exact C：

- [hostsdir-startup.json](hostsdir-startup.json)：poll / no-poll / no-resolv 三模式的初始 hostsdir 加载中发 DHCPREQUEST，均等发布完成才 ACK，返回权威名称，DNS/lease 文件一致。
- [helper-startup.json](helper-startup.json)：normal-resolv / large-resolv / held-fifo 三模式 restored lease helper 顺序和最终状态一致；held FIFO 关闭前均无回调。
- [handoff-helper.json](handoff-helper.json)：5 个 rapid/renew/selecting 多 MAC 接管和同 MAC rapid 场景，helper argv 和 DNSMASQ metadata 均一致。

复跑已有探针使用：

```sh
sudo sh "$R/source-fix/tools/dnsmasq/run_isolated.sh" python3 \
  "$R/source-fix/docs/dnsmasq/audits/20261011/fix2/dhcp/hostsdir_startup.py" \
  --source "$R/source-fix" --image-root "$IMAGE" \
  --rust "$R/private/release-fix/dnsmasq-rs" \
  --out "$R/private/dhcp-hostsdir-RERUN" --require-match
sudo sh "$R/source-fix/tools/dnsmasq/run_isolated.sh" python3 \
  "$R/source-fix/tools/dnsmasq/audit_fix_20261011_hosts_startup.py" \
  --source "$R/source-fix" --image-root "$IMAGE" \
  --rust "$R/private/release-fix/dnsmasq-rs" \
  --out "$R/private/dhcp-helper-startup-RERUN"
sudo sh "$R/source-fix/tools/dnsmasq/run_isolated.sh" python3 \
  "$R/source-fix/docs/dnsmasq/audits/20261011/independent/dhcp_handoff_helper.py" \
  --source "$R/source-fix" --image-root "$IMAGE" \
  --rust "$R/private/release-fix/dnsmasq-rs" \
  --out "$R/private/dhcp-handoff-helper-RERUN"
```

本轮 SHA256：

- C `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`
- main `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`
- fix `524c327f79080c789f7cdce74125c2af52f6e9c97175414a874ac6e31c9f9c2a`

## 本分工未覆盖

未覆盖真实广播网络、多接口 relay、真实客户端固件、掉电/持久化设备、物理路由器、超长时间租约循环、32 位或非 Linux runtime。性能、构建、配置、DNS cache/hosts parser 由其他审计分工处理；信号复跑由主审计完成。此次只在运行身份 nobody 验证 root-owned ordinary addn-hosts 权限边界，未枚举 ACL、Linux capabilities、SELinux/AppArmor 或目录权限组合。
