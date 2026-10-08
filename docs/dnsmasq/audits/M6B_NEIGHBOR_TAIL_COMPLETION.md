# 新启动 neighbor dump 的尾步完成与 TCP continuation

2026-10-08。主线程实际镜像服务观察：A ae1cdba6/ELF e2900727 的
`neighbor-tcp-connection-mac-snapshot` 在2秒首query超时，rows/upstream为空；相同
`--only '^tcp-connection-mac-snapshot$'` 在无A1bd9436c/ELF30141ffe亦复现。因此是共同
owner唤醒缺陷，不能归为A存储差异；初次错selector的0case运行不当资格。本文分支基精确
1bd，只准备源补丁和测试；没有访问Oracle、构建或运行测试。第1包历史基线不因此重做。

## 根因调用链

1. `step_tcp_accept → query_edns(source,false)` 首次启动内核dump，返回Pending。
   admitted TCP已持有stream、MAC3s截止，但`wait_for_files`正确地在MAC未完成时不登记
   downstream fd，避免已排队DNS字节造成忙等。
2. 本turn `step_tcp_clients` 没有先前poll的neighbor readiness，不能恢复该client。
3. 尾部 `step_neighbors → advance_neighbors → NeighborCache.step` 无条件非阻塞读dump。
   若内核已经回答，它能立即publish并把active dump清为None，而owner仍没有消费者提示。
4. 下一wait既没有active dump fd，也仍跳过待MACstream；直到MAC3s截止才恢复。
   镜像夹具2s超时、首query没到上游与此边界一致。既有
   `accepted_mac_wait_does_not_busy_poll_queued_dns_before_snapshot_ready` 手工设置
   neighbors_ready，覆盖不了首次dump在同一turn尾步完成。

## 最小修复合同

`advance_neighbors`只在active dump **Some→None**（完成或终止）时，立即在owner内
捕获待MAC TCP的Ready身份；同样覆盖仍由interface collector持有的PendingInterfaceTcp。
普通Reading连接因此在下一wait正常登记实际downstream POLLIN；不伪造revents、不读
尚未有readiness的stream。已framed的WaitingMac query若身份已捕获，则逻辑runnable，
normal与DHCP nested wait timeout为0，并使用这个身份而不是再次查询已经变化的snapshot。
调试Reading的首次MAC lookup仍延后到query，只有实际WaitingMac阶段才可被completion恢复。

这次完成也设置既有neighbors_ready消费者提示。UDP queue在尾步之后按32预算调用
step_edns_udp，余尾已由edns_udp_runnable续步；interface阻塞时仍等其collector。
TFTP在UDP之后使用completion提示，其最多8个待MAC RRQ在poll_once_with_mac中整队检查；
不创造TFTP socket readiness。若TFTP自身最后一步才启动dump，dump仍为Some，下次普通
poll会登记它；不存在已完成却无fd的这一边界。没有新的固定2ms循环或全局sticky标记。

## 新 owner测试（未执行）

`main_neighbor_tail_tests.rs` 四门都使用真实socket/内核dump；同步poll只在测试中确认
datagram已经到达，不设置owner revents或neighbors_ready：

- `tail_dump_completion_captures_accept_mac_then_registers_real_downstream`：排队真实TCP
  query，Pending→内核dump到达→尾advance完成；MAC须Ready且input/revents仍空；下一
  owner wait必须登记真实stream，并由实际socket取得POLLIN。
- `captured_buffered_mac_query_is_runnable_and_does_not_lookup_again`：已有framed query和
  已捕获MAC，无read-ready；直接runnable完成本地回答，lookup closure若被调用即失败。
- `tail_dump_completion_resumes_udp_and_interface_held_accept`：同一完成恢复UDP待队和
  interface-held TCP，稍后finish accept不能重新等待已消失dump。
- `tail_dump_completion_resumes_tftp_mac_waiter_without_socket_ready_hint`：隔离namespace
  的真实RRQ被MAC query停放；尾dump完成后无TFTP fd-ready，仍能从普通root发送真实DATA。
  所有临时文件要求fresh TMPDIR，网络仅loopback；物理路由器不触及。

主线程按统一shared-target入口复制并运行新main tests，随后无A/A同补丁的fresh EDNS
首case及完整族、TFTP和相关owner门。A的Option<DnsWork>只需将capture helper中的client
字段访问移入Some(work)，跳过None；MAC状态机、pending-interface和完成提示合同一致。
未跑的测试与fresh服务不得因代码提交算通过，也不复用旧候选的服务或CPU资格。
