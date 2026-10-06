# M6a 失败、作废和异常记录

正式方案51d1ba62先于所有Oracle性能试跑提交。M6a产品保持dc1b740d／37f85d22不变；以下是工具或合同接线预检，不算正式性能结果。正式窗口的环境/方法失败会在suite state、原attempt和最终报告中追加，真实产品错误保留在方法有效轮内、不能以丢窗隐藏。

| 步骤 / 身份 | 观察与原因 | 处置及证据 |
| --- | --- | --- |
| native工具Linux编译，setup-2fac068f | GCC `-Wall -Wextra -Werror`拒绝TCP malformed-frame分支的一行缩进歧义；没有产生被测结果。 | 1cd45718拆清控制流，仍使用相同语义；[原log](../../../private/dnsmasq-rewrite/evidence/M6a/setup-2fac068f/native-build.log)、[重跑log](../../../private/dnsmasq-rewrite/evidence/M6a/setup-2fac068f/native-build-retry.log)。 |
| 手工DHCP C pilot1 | 方法采样完整但correct0、timeout131。实际argv把DHCP发到DNS15353，daemon自然无DHCP应答；不得称C性能差。 | 41254ee7改为冻结协议的server67/client68。原[完整结果](../../../private/dnsmasq-rewrite/evidence/M6a/setup-2fac068f/dhcp-c-1-result.json)和远端raw保留；[pilot2](../../../private/dnsmasq-rewrite/evidence/M6a/setup-2fac068f/dhcp-c-2-result.json)200/200完整DORA→renew→release、0error/timeout、lease末态空。两次均excluded正式。 |
| b85 / dadd85 manifest，tcp-local C pilot | warmup1969次正确后loadgen exit2，正式measurement尚未开始。`config.h:20 TCP_MAX_QUERIES=100`、`forward.c:2457/2489`与Rust `main.rs self.queries==100`均限制每连接100次查询；原客户端把正常EOF当中断。 | 三组统一100-query复用/重连，协议附注注明原因、固定rate/时长/顺序/阈值不改。原[leaf](../../../private/dnsmasq-rewrite/evidence/M6a/freeze-b85a9628/archives/r01-tcp-local-c/attempt-1/plain/pilot/result.json)、[load](../../../private/dnsmasq-rewrite/evidence/M6a/freeze-b85a9628/archives/r01-tcp-local-c/attempt-1/plain/pilot/load.json)及全binary/full metadata archive已本地核验后prune。12个前序绿仅pilot，不借为正式135窗口。 |
| suite人工中断守卫f405 | 9PASS/1FAIL：已prune但未恢复gate时重启，再次inventory缺失run；不是Oracle性能失败，完整归档一直在。 | 6e2e6062加先验prune-intent和恢复；b85a9628首次intent前严格full inventory相等、拒绝未归档变化。53c8a71a人工12/12PASS，包括半scp原子重拷、PID归属/重用、pending gate优先、旧prune恢复、坏产品数据保留；[私有审查目录](../../../private/dnsmasq-rewrite/evidence/M6A/review/)。 |

全部工具bug在正式数据仍0/135时处理。s fresh build仍8427b9ab…／1,613,864B，只用于性能；没有修改产品或执行M6b。CPU/延迟等结论必须等至少5轮正式数据，不从这些pilot挑数。

TCP修复374e19df后的第二campaign manifest f0055eb3410c961a54818854b60a30d058e58be38994e43241e3e74a766e88f8全量短试跑仍excluded。udp-miss-r3 attempt1被exclusive门拒绝（foreign PID3799283/start102126517/cmdline hash978de9…db29）；本窗口primary start102125543且cmdline hash不同、10个resource样本children[]，现有证据不能确认来源，不改归属规则。原archive f5d1af7f…cf61已本地full SHA+metadata核验；同manifest孤立attempt2与串行attempt3均通过。原command与guard报告保留[命令证据](../../../private/dnsmasq-rewrite/evidence/M6a/freeze-tcp374e19df/udp-miss-r3-pilot1-command.json)，不将拒绝改写成已通过或产品失败。
