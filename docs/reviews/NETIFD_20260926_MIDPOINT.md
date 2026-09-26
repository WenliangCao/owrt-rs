# netifd 中场检查点

按用户要求暂停；没有宣布完成，没有部署或改变生产C。暂停于H4c完整正确性批次结束后，
尚未启动H4c性能筛选、正式CI构建或最终C/R89/候选确认。

当前优先验证H4c，ELF SHA256为
`b292b0cdbf3daeeef27309ab2a9939c93c4d68a5a22ecbeab691780f7e44e69f`。
它继承B09的无线配置blob缓存，只在无变化reload时转移既有缓存；新配置仍立即编码。
164单测、clippy/release/ABI和修复隔离后的31/31、overflow、restart、两种reconnect均通过。
宿主网络/挂载/namespace前后相同，post census无项目root残留。suite日志SHA为
`af1d05151a948e4fde1e5d1a7738b29dd7121b5a865b616fb4dcc9752eca67ed`。
远端driver完成后，本地SSH waiter仍未退出；暂停时只终止了该精确本地进程，运输层exit255单独保存，
没有改写成0。远端完成标记、各门退出码/结果和post census均已独立下载验证。

H4c还没有性能结果。以下是其前版B09的AX3000T八block探索，实际无线配置/schema配隔离stub，
不涉及真实radio重配置。数字为配对log中位数变化；保留窗口08的已披露采集恢复偏差。

| B09负载 | 主体CPU较A09 | mean较A09 | 主体CPU较C | mean较C |
|---|---:|---:|---:|---:|
| wireless_status | −55.54% | −31.32% | −92.45% | −72.63% |
| wireless_status_c4 | −60.82% | −30.79% | −94.15% | −78.00% |
| unchanged reload，32接口 | +4.56% | +5.53% | −60.79% | −60.34% |

B09的reload p99较A09高11.97%，也是H4c尚需证明解决的问题。无线尾部个别窗口仍越界，
不能用CPU/mean收益抵消。该消融没有正式R89，不能给H4c填入对R89的胜出百分比。

H7b是另一独立方向：清洁Oracle四对事件负载主体CPU中位−6.85%，机制门通过；第3对主体
+1.92%、依赖+8.04%、caller+8.89%，child增加36ticks，仍未解释。它没有合入H4c。
H6/H7/H8/H9拒绝决定保留；旧Oracle宿主竞争限制和完整证据见主研究报告。

恢复后顺序：先核对该检查点和精确输入；补H4c raw66门并执行已准备的四组三侧筛选，
分别测warm status、unchanged reload和reload后的首次status；再决定H4c/H7b组合并过完整门；
补事件计时/子进程CPU工具及有限A/A；取得同commit正式CI产物后，做最终三方实机确认与资源回收诊断。
正式确认草案为26负载、20block、11指标及ratio/margin两端点；它尚未冻结或执行。

原始证据和恢复入口：ignored `private/netifd-20260926/PAUSE_CHECKPOINT.json`。
