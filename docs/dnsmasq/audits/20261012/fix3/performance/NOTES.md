# FIX3 性能审计结论

## 已确认的本分支新增问题：TCP 缓存命中随无关 dns-rr 配置线性增贵（P2，按本次合并标准阻止合并）

`dns/daemon.rs:1846` 把 TCP 缓存命中路径改为先调用 local resolver；`dns/local.rs:1284` 的 `add_raw` 在比较 RR 类型前，遍历并 canonicalize 每条配置记录的名称。后者的线性扫描在 main 已存在，但 main 的 TCP 缓存命中优先返回，未支付此扫描成本。此次把旧有慢路径带入 TCP 命中主路径，属于新增回退。保持修复后的本地记录优先语义与避免不相关记录的逐条扫描并不冲突；本审计未修改任何产品代码。

复现：使用 `raw_records_window.py` 添加 `dns-rr=unused0.audit.test,65401,abcd` 至 `unused999.audit.test`（均与实际 A 查询的名字及类型无关），预热并验证 4096 个 A 缓存条目，再禁用上游应答，20 个客户端、1000 QPS。源、二进制、配置、工具与请求正确性均绑定在 plans 与 `counter-check.json` 中。

| 场景 | main CPU μs/正确响应 | fix CPU μs/正确响应 | 变化 | main/fix p95 μs |
|---|---:|---:|---:|---:|
| TCP、100 条无关 dns-rr，3 对 × 15s | 30.524 | 49.993 | +63.78% | 78.201 / 105.720 |
| TCP、1000 条，3 对 × 15s | 33.335 | 119.547 | +258.62% | 85.921 / 219.962 |
| UDP、1000 条，同量对照，3 对 × 15s | 103.354 | 101.705 | −1.60% | 201.362 / 200.042 |
| TCP、1000 条，另做 5 对 × 30s 确认 | 32.5986 | 115.9026 | **+255.54% / 3.555×** | **80.201 / 213.962** |

长窗 5 对均同方向；CPU 相对极差 main 9.55%、fix 4.33%，远低于 +255.54% 的效应。p95 增加 166.78%（2.668×），两侧相对极差 2.84% / 10.43%。PSS 中位增加 0.91%，FD 均 32，没有把 CPU 回退误报为内存泄漏。UDP 1000 条对照用于确认它的原有扫描成本；没有跨 UDP/TCP 或不同 QPS 相减估算开销。

原生 TCP 发包器每 100 条查询重连，指标包含正常连接创建/销毁，不能表述为纯 lookup 微基准。同一配对的发包器和重连行为相同。内核/连接开销不能解释 main 随记录数近乎不变、fix 随记录数上升以及 UDP 配对基本不变的组合证据。

证据：`raw-{plan,run,summary}.json`、`confirm-{plan,run,summary}.json`；Oracle 原始窗口在 `private/performance-raw-records` 与 `private/performance-raw-confirm`，逐窗哈希在 `counter-check.json`。完整重跑命令见 README；不能覆盖原窗口。

## 默认配置屏幕与已修复项

36 个默认配置窗口的中位 CPU 变化：UDP A hit +2.07%、miss +2.56%；TCP A hit +5.91%、miss +9.17%；UDP CNAME hit +0.43%、TCP CNAME hit +8.29%。TCP CNAME p95 +8.17%。这些小成本和噪声均保留，不将“没有超过事先 10% 筛选线”解释为性能等价或用户批准的容差。普通配置不能代替含合法 dns-rr 配置的回归检查。

48 MiB 普通 addn-hosts 注释文件另有实际资源改善：main 启动 VmHWM 50,476 KiB、fix 1,968 KiB、C 1,128 KiB。32 MiB RLIMIT_AS 下 main 启动和 SIGHUP 后均丢失合法 A 记录并返回 REFUSED，fix/C 均保持正确 A。这项原有问题的修复已得到新鲜三方结果支持（`hosts-memory.json`）。

## 完整性核验

`verify_counters.py` 已完成强断言，结果为 `counter-check.json`：

- 36 + 18 + 10 = 64 窗全部运行完成、退出 0、measurement_valid true；原始结果没有剔除或重跑。
- 2,497,992 条 warmup + measurement 请求逐窗满足 scheduled = sent = correct；wrong、timeout、transport_error、scheduled_skipped 均为 0。
- 三组开始前 competing-workload 检查均为空，其他审计 agent 已停止 Oracle 构建/测试；CPU 分离为 daemon 0、upstream 1、loadgen 2、controller 3。不能排除虚拟化宿主邻居噪声。
- 640 个保留的 cgroup 计数点中 nr_throttled 与 throttled_usec 全为 0。
- 每一配对的配置 SHA 完全一致，每窗执行中 ELF SHA 与计划相符。
- 每个 hit 窗口的 4096 条 A bank（CNAME 为 2048 个 owner，加一个共享 A terminal）均逐条证实；upstream_disabled / disabled 为 true、disabled_requests 为 0、steady 上游请求为 0。禁用的是应答，不是杀死上游进程。
- 配置、cache-proof、upstream.json、process-identity.json 的逐窗原始索引/哈希已保存；miss 窗口不要求 cache-proof。

首次 SSH 长连接在基础窗口进行中被网络空闲超时断开；Oracle 的 shell/controller/window 均仍运行，重定向日志连续完成 36 窗，没有重启或丢弃。不能将 SSH exit 255 记为测试窗口失败。随后两组使用 keepalive。

## 未覆盖范围

没有物理路由器性能数据，没有 saturation/max-QPS、长期泄漏或全部生产配置的性能证明；本组使用新鲜 release ELF，不把它等同于 SDK 打包 ELF 的单独性能资格。DHCP/TFTP/实际 Wi-Fi 流量的性能不在本子审计窗口中。诊断信号、配置正确性、构建/RELRO 和 configured host-record 启动资源由其他审计证据覆盖。
