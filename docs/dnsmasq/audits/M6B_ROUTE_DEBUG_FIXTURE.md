# Route clear debug-TCP 夹具修正

基于 main `209c5713`，只修改工具，未访问 Oracle、未改产品。旧失败在 root 已核验的 `E/M6B/full-archives/route-7009-runtime/plain/route-clears-7009-01/c/` 保留；该 debug case 的原始 config 含 enable-ubus，daemon.log 实际出现 `Cannot set UBus listeners: no connection`，metric stderr为 `Command failed: Not found`。

精确 C `dnsmasq.c:2187` 在 debug非fork路径也调用 `drop_ubus_listeners()`；`ubus.c:199–208` 释放父 context。该原版边界已由 `UBUS_CONTRACT_PHASE.md` 的 debug说明明确记录。这里不新增产品行为差异、不重建一个虚构 C UBus counter。

新 clears plan 在执行前冻结：**仅 debug-TCP case** 两侧均不启用 UBus，启用标准 `log-queries`；完整 primary logfile 在 hold前/完成后各存raw和重新解析结果。前者forward动作0，后者恰好1条 `forwarded route.resend.test to 127.0.0.2#<frozen upstream port>`；多次forward、错误host/port、伪JSON计数或日志非append都拒绝。C格式来源为 `cache.c:2397–2400,2459–2461`。其余5 clear cases和两项basic仍使用原严格UBus前/后计数，原basic PLAN与same-wire/source/single-answer要求保持。

Debug TCP 不用“等待metrics=0”猜排空：hold UDP后先取得3×20ms稳定完整FD集合；TCP本地答复后保持client打开，证明同进程owned socket的实际 `/proc/<pid>/net/tcp` 四元组/ESTABLISHED/inode以及FD集合恰好多该socket，连续3次；client SHUT_WR后必须收到真实terminal EOF，再以3×20ms实际socket/FD观察回到完全相同 held集合。最后UDP事务答复后仍须恢复原始idle完整FD集合，不能放宽上限、忽略FD或只sleep。时间/原始socket表/每次FDtarget/EOF均留证。

本地13项测试通过，新增debug负控包含错误配置/重启UBus、额外forward、错误upstream、伪counter、EOF缺失/多字节/错顺序、错误TCP四元组/state、同count换FD、残留socket和未分隔稳定采样。未执行fresh实际6case，不把工具tests当C/R资格；由root在最终freeze前排fresh两侧全clears，不阻塞无A新baseline/A，也不触碰已归档失败。
