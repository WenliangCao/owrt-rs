# 内部128B归因：1024／4096实际连接次数

用户2026-10-08新授权。只扩展已有diagnostic caller的连接次数；不改产品、warm、
缓存4096、固定名字集合／600s TTL、20并发上限、既有drain等待或采样点。
旧warm暂停草稿保留为ignored patch，未合入本工具。

`m6b_tcp_internal.py run --reconnect-count 1024|4096`只允许reconnect/capacity4096。
数量包含原结构warm的20条实际连接：1024是warm20＋50批20＋尾批4；4096是
warm20＋203批20＋尾批16。默认无flag仍是原warm20＋10批20的标准验收。
partial批的实际clients/G/work/views用4或16核，不伪装20。

每个connect成功且原UBus gauge确认后记录真实ordinal、当前并发、client FD和原
accept-N.gauge receipt。每批保持原active/完整drain／实际FD与原始trace；count
collector逐条重核全部1024或4096个gauge与完整drain事件，拒绝缺失／多余／乱序。
捕获同prefill后的initial（0连接、warm前）、warm、postwarm baseline和final原row／
trace index；保留最终0/1/5/15/60观察。所有stage用独立fresh输出，不覆盖红run。

count collector只确认方法、实际数量、原始wire／source／cleanup／原六controls完整，
报告全部requested／对象／根／observer／poll／ready数据与每批raw row。已知128B
不会让run因跨批余额比较提前中止；字节变化保持数据，绝不扣掉ready或容忍泄漏。
结果mode=count-attribution、method_count_complete表示归因数据完整；
internal_balance_qualified与product_cpu_pss_qualification保持false。标准10批的严格
requested、对象、根、owner、Vec余额和原negative controls完全不变。

独立cross-run分析按用户规则比较两个完整次数run：initial→final与postwarm
baseline→final同时列出；实际对象／增量随次数增长则继续泄漏修复。不得挑选较好
attempt、将count诊断充普通资源验收、或提前使用未执行数据得结论。

本提交仅本地pure边界控制；未访问Oracle、未build或执行两个count runs。
