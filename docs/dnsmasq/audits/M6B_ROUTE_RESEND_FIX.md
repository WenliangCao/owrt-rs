# 普通 route resend：传输实现与清除门

2026-10-07。独立no-A `m6b/route-resend-fix`，基点c600506b。root实际7bdb/de45镜像门已证明C poll/no-poll各2包同wire/source port、Rust各1包；两侧forward action各1且idle FD回归。原始证据由root归档。本补丁未访问Oracle，不把host tests当镜像资格；main caller由独立代理/root整合，A未合入。

## 机制与合同

`UpstreamResolver`保存最近一次成功send的ServerId、单调SocketToken、实际目标和逐字packet；只有一个可复用Vec，不增加socket owners、probe refs或pin，不从pending选择其他query。metadata不借raw FD，release后清save，避免FD重用后误发。`resend_udp_query()`沿同活socket/目标/packet复用现有 `send_udp_with_retry`，对应 `forward.c:137–143/3292–3297`；不提交frec、不调用note_sent/forwarded、不改ID/recipient/fastretry时间、不产生普通query log/dump。成功resend和终态send错误均不清原save，重复route仍可重发。

遵从root明确指令，复用既有有界send合同：EAGAIN最多1,001次send/10µs nanosleep（最后一次也wait，EINTR重置），不在这个caller新造永久owner send queue；正常路径一次send。此既有罕见重试边界保留为后续CPU/极端背压归因，不冒称无nanosleep。memory增加仅一个SavedUdp metadata/Vec及其最近成功packet容量；普通clear保留容量，drop释放，无每请求save allocation（首次或更大packet扩容除外）。

| 精确C入口 | 库实现 | 真实host门／剩余主owner门 |
| --- | --- | --- |
| successful UDP send `forward.c:548–550` | 逐个成功候选更新save，all-servers最后成功目标；失败不覆盖已成功save | exactwire/sourceport、two pending只last、all-servers只last、重复route、无forward/log/retry变化已host实过；真正route caller待fresh C/R |
| `receive_query:1628` | daemon.handle/local/forward/prepared入口clear；transport.start在run_timers后恢复new input再clear（invalid也清） | TXT local、invalid direct admission/forward、cached hit、唯一Vec复用已实过；main实际Some/None/oversize/ACL read入口由caller补丁 |
| `reply_query:1169` | 真正recv成功或非EAGAIN硬错误/EINTRclear，在认证前；批次末尾额外WouldBlock探空不清 | unmatched实际reply、SERVFAIL成功转发后的尾部探空不擦新save已实过；不能每次poll空step清 |
| `fast_retry:654` | 执行每个due计划前clear；成功send重新save；失败不恢复旧save | 真实success和port0失败、counter/transaction/socket状态已实过 |
| `server_gone:3315–3316` | actual removed ID才clear；mere routing exclusion保留token/save | 无routing group但live pending仍resend、实际server retire后不send/0socket已实过 |
| `cache_reload:1644` | daemon.reload_hosts实际入口clear | 直接reload保留pending、clear route save已实过；mainHUP门待caller整合 |
| `loop_make_probe:57` | 非空真实probe batch生成前clear；空batch不清 | 真实probe31B发包/无forward增量、旧save失效已实过 |
| ordinary child TCP / debug父packet、wildcard accept pktinfo | 库普通tcp_snapshot不清；main对应父shared入口clear | 普通snapshot保留父save已实过；debug/wildcard真实owner门由caller补丁 |
| TFTP shared scratch | 库只暴露invalidate API；main实际OACK/DATA/read-error construction及120s非final get_block对应TimedOut清，闲/最终ACK/错TID不清 | 独立caller按C精确路径补门；TFTP `void *srv_save` alias UB仅source-only，不制造危险期待 |

新增11个真实transport tests＋2个daemon tests实际host13/13通过；AArch64 Linux `--tests`类型检查通过但未实际Linux运行。初版tests的QueryLogging字段误写proto导致compile失败，改为enabled＋Default；首轮daemon local配置host-record经cache-authority给Cached，错误预期Local失败（12/13过），换TXT真正Local入口后13/13通过。失败不改产品/不放宽Local|Cached，后续记录保全收据。main仍需caller补丁与root fresh镜像/统一Linux资格，本提交不是整族通过。
