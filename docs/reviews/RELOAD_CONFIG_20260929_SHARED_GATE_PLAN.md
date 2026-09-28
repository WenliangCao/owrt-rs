# reload-config：共享 ubus 消费者最小正式门计划

状态：待主代理填写执行结果。该计划只补本轮共享库变更的必要功能回归；不重开前七个组件的性能矩阵，不代表整栈部署验收，不操作路由器。

`owrt-ubus` 新增显式可取消连接和绝对deadline接口。已有消费者继续使用默认None回调；但底层发送/接收函数和连续可读时的截止检查共同编译，所以必须用新库实际重建已有消费者，不能拿旧ELF复用通过记录。UCI自身不依赖ubus，无需因此重新开启UCI研究。

## 冻结和执行前提

复用本轮clean canonical构建产物，从实际APK提取相应ELF；ubusd/procd/netifd使用canonical直接构建产物。创建私有 `runtime-bins`，包含 `ubusd-rs`、`procd-rs`、`httpd-rs`、`rpcd-rs`、`netifd-rs`、`logd-rs`、`fw4-rs`；每个记录源码commit、共享ubus源码hash、构建运行、容器/SDK输入、期望/实际SHA、AArch64 ELF头。包括同SHA的无实质代码变化产物也要证明本次确实重建。

沿用UCI的 `private/uci-next-20260928/construct-formal-runtime.py` 已有方法：执行前/后核验原镜像、源码、输入和复制ELF、ns-exec身份；每门独立namespace、失败日志及SHA保留。无需再造通用runner。`r92_validate.py --gates` 会记录明确的部分范围和实际二进制身份；它不会自动替代上述canonical期望身份核验。

原始镜像保持OpenWrt25.12.5 r33051-f5dae5ece4，精确C ubusd/依赖不改。RPCD的apply/rollback单独用安全rootfs副本，只替换 `/sbin/reload_config` 为marker并记录原/替身SHA，阻止真实触发器；其他门与reload-config R1继续用pristine根，避免把替身当精确原版。

## 七消费者与最小覆盖

| 消费者 | 已有门 | 检查共享库相关行为 | 不由此宣称 |
|---|---|---|---|
| UBUSD | `ubusd-r36`、`ubusd-r36-user` | 真实C CLI对象/调用/事件及root/ubus身份；helpers源/ELF校验 | 不重跑R136全性能矩阵；不替代全部恶意协议模糊门 |
| PROCD | `procd-r65` | `service`对象、事件/通知、服务状态、完成状态回复，真实C参考与notifier | 不涉及PID1、watchdog、重启/升级部署验收 |
| HTTPD | `httpd-r14` | HTTP JSON-RPC与真实C ubusd/rpcd转发、回复/错误路径 | 不重新评估H12吞吐或TLS资源模型 |
| RPCD | `r17_rpcd_core_check`，独立安全rootfs | session/ACL、UCI apply/confirm/rollback、请求等待及对象服务 | marker只表示reload_config被请求，不表示服务已重载 |
| NETIFD | `r83_config_diff.sh`，`r92_compat_probe.py --cases netifd_restart` | 实际配置重载、接口/设备回复、重新exec后的对象恢复 | 只在私有namespace触碰内核网络，非物理Wi-Fi验收 |
| LOGD | `logd-r15`、`r21_logd_reconnect_check` | 读取/流接口及ubusd重启后重新注册，保留前/中/后记录 | 不重测七百余LOGD性能窗口 |
| FW4 | `fw4-image`，补 `fw4-upstream` | 精确镜像真实ubus查询输出与上游确定性规则字节 | `fw4-image`只作功能证据，忽略其采样性能数值，不执行生产nft变更 |

上述共11门覆盖7个消费者；若一个门本身失败，保留失败并根据具体原因补最小定向门，不能用组件其它通过门覆盖。native unit/clippy与这些canonical运行门分开记录。

## 调用模板

以下是主代理串行执行的命令模板，变量必须指向已核验的私有路径；此文不表示命令已执行。

```sh
python3 "$SOURCE/tools/r92_validate.py" "$ROOTFS" "$BINS" "$OUT/shared-core" \
  --baseline "$R89_BUNDLE" --examples "$EXAMPLES" --helpers "$HELPERS" \
  --fw4-source "$FW4_SOURCE" --network-config "$NETWORK_CONFIG" \
  --wireless-config "$WIRELESS_CONFIG" --target-dir "$OUT/native-target" \
  --groups functional \
  --gates ubusd-r36 ubusd-r36-user procd-r65 httpd-r14 \
          logd-r15 r21_logd_reconnect_check fw4-image fw4-upstream
```

`r92_validate`自动把每个功能门放入冻结ns-exec，含私有loopback。`ubusd-r36*`要求先重建 `asuser`、`busprobe` 并保留manifest，`procd-r65`要求源匹配的notifier。不要从旧目标目录默默捡已有helper。

```sh
python3 "$SOURCE/tools/r92_validate.py" "$RPCD_MARKER_ROOTFS" "$BINS" "$OUT/shared-rpcd" \
  --baseline "$R89_BUNDLE" --examples "$EXAMPLES" --helpers "$HELPERS" \
  --fw4-source "$FW4_SOURCE" --network-config "$NETWORK_CONFIG" \
  --wireless-config "$WIRELESS_CONFIG" --target-dir "$OUT/native-target" \
  --groups functional --gates r17_rpcd_core_check

sudo -n "$NS" python3 "$SOURCE/tools/r92_validate.py" --namespace-command \
  env NETIFD_TEST_NS_EXEC="$NS" bash "$SOURCE/tools/r83_config_diff.sh" \
  "$ROOTFS" "$BINS/netifd-rs" "$OUT/netifd-r83-config"

sudo -n "$NS" python3 "$SOURCE/tools/r92_validate.py" --namespace-command \
  python3 "$SOURCE/tools/r92_compat_probe.py" "$ROOTFS" "$BINS" \
  "$OUT/netifd-restart" --cases netifd_restart
```

共享结果至少记录 `gate / actual_ELF_SHA / source_SHA / exit / log_SHA / rootfs_mutation_scope / image_unchanged / artifacts_unchanged / namespace_cleanup`。正式报告只列实际通过项；尚未执行、身份不符、替身根误用和超时分别明确记录，不能标“已由旧测试覆盖”。
