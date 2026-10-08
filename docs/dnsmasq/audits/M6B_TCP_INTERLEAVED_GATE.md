# 方案 A 错峰与发布交错门

工具：[m6b_tcp_interleaved.py](../../../tools/dnsmasq/m6b_tcp_interleaved.py)。
本提交仅准备执行入口和收据校验，未在本机或 Oracle 执行；未完成资格。
公共产品及 `m6b_tcp_internal.py` 未修改。root 串行运行实际 Oracle 门。

| profile | 固定调用链与预期 | 来源与边界 |
| --- | --- | --- |
| `staggered-conflicts` | 父 A=.7，accept1；父强制更新=.8，accept2。子1仍=.7。子1 DO 查询由 TCP 上游 hold；父更新=.10，子2仍=.8。放行子1=.9并导入，父=.9；子1=.9，accept3=.9，子2仍=.8。关闭并将父恢复=.7。 | S1/S3/S4/S6/S7：`dnsmasq.c:2102–2197/1935–1958`、`forward.c:2716`、`cache.c:843–918/969–1056`。每个 accept 都由真实 image UBus `tcp_connections` 确认，非 connect 成功或 sleep。 |
| `reload-held-import` | 空 hosts；accept1、上游 hold 子1查询。父写同名 hosts=.9并 HUP，确认父=.9；放行子1上游=.7，父当前 local 冲突阻止导入覆盖。子1私有=.7；accept2=.9。关闭后 HUP 空 hosts。 | S1/S3/S6：同上；精确 C `cache_recv_insert` 使用父当前 local-match。HUP PID、文件原文/SHA、发送时钟、DNS确认保留。不是 FIFO known difference。 |
| `lease-held-import` | 父有 seedlease；accept1、上游 hold leaseold 查询。父收到同 MAC 120s DHCP ACK，名字变为 leaseold=.42；父 DNS=.42。放行子1上游=.7；父当前 lease 阻止覆盖，子1私有=.7；accept2=.42。关闭后同 MAC 恢复 seedlease。 | S1/S3/S6：C fork 继承旧 lease；parent import 使用当下发布。真实 DHCP query/reply/ACK identity、120s lease、地址、monotonic 时钟与 DNS答案均保留。 |

每 profile/侧使用 fresh image namespace，容量150，父与 child 的 TTL上限600s，lease TTL上限120s。profile先作一个结构预热批，再固定10批，名字和最终父状态不增长。每批保留上游 pending 时的真实 `clients/G/dns_work/views/tcp_pending/udp_pending`、成功 import 后全部独立 view、私有 content 根，以及排空行。最终公共资源和内部 trace均保留0/1/5/15/60s；内部值需归零，扣 observer registry 后的 live requested、对象和全部容量/版本余额与预热基线逐项相等。不能以 C child=0 替代 Rust view/txn 归零。

执行接口（路径用 root 当次冻结替换，所有输出必须 fresh ignored private）：

```sh
tools/dnsmasq/run_isolated.sh python3 tools/dnsmasq/m6b_tcp_interleaved.py run \
  --image-root "$IMAGE" --rust "$DIAGNOSTIC_ELF" --bound-receipt "$BOUND" \
  --profile staggered-conflicts --side c --out "$PRIVATE/c-staggered-01"
tools/dnsmasq/run_isolated.sh python3 tools/dnsmasq/m6b_tcp_interleaved.py run \
  --image-root "$IMAGE" --rust "$DIAGNOSTIC_ELF" --bound-receipt "$BOUND" \
  --profile staggered-conflicts --side rust --out "$PRIVATE/r-staggered-01"
python3 tools/dnsmasq/m6b_tcp_interleaved.py collect \
  --c-run "$PRIVATE/c-staggered-01" --rust-run "$PRIVATE/r-staggered-01" \
  --controls "$ACTUAL_SIX_CONTROLS/controls.json" --out "$PRIVATE/staggered-result.json"
```

另外两 profile 使用同样的三命令各自 fresh 目录。`--rust` 始终是 bound receipt所绑定的同源诊断 ELF；C侧实际启动的是镜像097a9e21，而非诊断 ELF。collector 要求双方同源/同镜像底座、工具哈希、raw/marker一致、全量11次hold/release与上游实际 query/response序列一致、三族具体 A答案/TTL、公共UBus/FD drain和实际6条method control收据。无法执行的批或负控不得写 qualified。

`m6b_tcp_internal` 依赖接口：`binding/trace_rows/stable_trace/drain_row/product_live/BALANCE_FIELDS/CONTROLS/save`；`m6b_tcp_pressure` 依赖接口：`Caller`的真实UBus/FD/采样、`root_provenance/validate_profile`。不依赖兄弟容量/pin工具，工具依赖均冻结到每run的`drivers/`。原有实际6条method controls是诊断方法的真实正/负控；本collector另要求保留view/txn、一字节leak、缺批、短60s、相位重排6项证据负控必须拒绝。

收据中的 `interleaved_internal_qualified` 仅证明本门；`product_cpu_pss_qualification=false`。诊断强制1Hz trace、全局System计数及observer registry改变开销，绝不可用于产品CPU/PSS门。最后同一feature-off产品ELF的canonical M5相关族、S1–S8服务及资源/CPU门仍独立必需。对比中只将合法生命周期内的answer TTL设为有界标记：回答内容和RR顺序严格；完整固定accept-clock/精确TTL由canonical S2门负责，原始TTL仍全保留。

S8日志-only/TERM仍由后续独立入口补齐；不能因为本工具三个profile通过就称设计5.6全部完成。
