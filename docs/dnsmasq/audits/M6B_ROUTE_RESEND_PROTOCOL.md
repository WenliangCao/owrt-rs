# Route resend 普通 caller 冻结补门

2026-10-07。状态：工具准备、未Oracle/镜像执行、无产品改动。独立no-A分支 `m6b/route-resend-caller`，基点 `922065e4fa14f6b662f5e3aa6b580bc0115373c3`。本协议先于任何结果提交；精确C合同见 [M6B_ROUTE_RESEND_CALLER](M6B_ROUTE_RESEND_CALLER.md)。不作性能测量，不触物理router。

## 冻结的第一批

| 场景 | 两侧相同配置／负载 | 必须观察 |
| --- | --- | --- |
| `m6b-route-resend-poll` | M5精确image driver默认 `no-resolv/no-hosts/bind-interfaces/no-0x20-encode/cache-size=0`、TTL600、唯一UDP上游、1client/1query/0客户端重试；UBus真实镜像metrics | 第一query上游hold；0.2s无第二包；dummy地址触发有效kernel route；2s内收到逐字同query/同source port第二包；只对第二包回答；client正确答案1个，forward action增量1；原idle FD身份3×20ms稳定返回。 |
| `m6b-route-resend-no-poll` | 同上，只加 `no-poll` | 同上；禁止以 `no-poll` 跳过resend。 |

所有等待/预算固定在工具 `PLAN`：hold0.2s、resend2s、extra reply0.2s、稳定FD3次/20ms/最多2s。创建dummy `m6broute`，在up之前只禁该新接口IPv6以排除DAD干扰；在query前排空bootstrap netlink并发一次健康query作daemon turn barrier；后续hold期间不发health DNS、HUP或其他query。`ip addr add 198.18.252.1/24 dev m6broute` 触发connected route；raw witness必须来自kernel sender/header pid0、type24、UNICAST/LINK/MAIN|LOCAL、IPv4 /24、RTA_DST=198.18.252.0。命令成功、手工route或任意别的route消息都不能替代。控制上游在真实recv后callback记录接收序号/单调时间，必须第一包在trigger之前、第二包在trigger之后；快照写文件时间不能替代收包时间。client直接connect DNS endpoint，限制答复来源。

用M5 `m5_dns_cache.run → m2_rootfs.prepare/process_identity`，两组在同镜像rootfs overlay内执行精确C `097a9e21…cab87` 与显式SHA绑定Rust ELF。每组fresh namespace；tool receipt保存当前caller及5项依赖的SHA和字节，compare重新核验实际process/rootfs及全部raw query/reply/netlink/counter/FD，不把M5全cache族的旧manifest/旧证据当此门通过。完整实际upstream库存必须和held采样的1或2个包逐一一致，第三次迟到重发不能漏算；client flags8180、A owner/class/TTL600与empty OPT1232必须精确，并把完整normalized query/reply纳入跨C/R比较。

依赖字节在run之前冻结，结束后逐SHA确认未变；compare显式接收expected Rust SHA并绑定两侧report/rootfs/实际Rust process，核对共同image provenance与immutable base manifest；两侧复制的候选不同不能过。

缺少resend仍保存完整“1 upstream packet”证据，并仅对原packet回正确答案让pending清理；`cleanup_answer=true` 固定不能满足resend。`run` 会在保存result/validation后返回1；这是功能缺口，不能改成等待下一新query或在fixture手工补第二包。方法错误（无真实kernel route、错误答案、FD未回、extra reply等）另保留failure，不能推断产品缺口。跨C/R比较不对齐随机ID/端口；分别核对每组第一/第二包完全一致。

## 主线程执行

工具提交并冻结后，由root独占Oracle，按原 `run_isolated.sh` 执行。以下变量均指已冻结资产，Rust即待核对的无A候选；C组也传Rust以绑定共享overlay中的候选身份，不把它当被测C。

```sh
python3 "$M6B_TOOLS/m6b_route_resend.py" plan --out "$M6B_EVIDENCE/route-plan.json"
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_route_resend.py" run \
  --side c --image-root "$M6B_IMAGE" --rust "$M6B_NO_A_ELF" \
  --expected-rust-sha "$M6B_NO_A_SHA" --out "$M6B_EVIDENCE/route-c"
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_route_resend.py" run \
  --side rust --image-root "$M6B_IMAGE" --rust "$M6B_NO_A_ELF" \
  --expected-rust-sha "$M6B_NO_A_SHA" --out "$M6B_EVIDENCE/route-rust"
python3 "$M6B_TOOLS/m6b_route_resend.py" compare \
  --c "$M6B_EVIDENCE/route-c" --rust "$M6B_EVIDENCE/route-rust" \
  --expected-rust-sha "$M6B_NO_A_SHA" --out "$M6B_EVIDENCE/route-comparison.json"
```

原始失败和完整运行目录均按主账本回拷/逐SHA核验后才prune。C两项先证明普通caller合同；Rust无第二包时保留差异，产品修复另提交后fresh两侧重跑，不借修复前C成功拼候选资格。

## 第二批：普通 clear / private TCP（工具已实现，未 Oracle）

独立 tool-only 分支 `m6b/route-resend-clears` 基于主线 `c600506b`，未修改产品。`--batch basic` 仍是原来两个严格场景和原 PLAN；新增 `--batch clears` 有独立 CLEAR_PLAN，不能把“应无重发”改成 basic 的成功条件，也不能拿旧 basic 证据满足新工具冻结。

| 场景 | 第一 held UDP query 后、有效 route 前的唯一动作 | C 必须结果／完成见证 |
| --- | --- | --- |
| `m6b-route-clear-local-udp` | 另一个 UDP client 发本地 `health.cache.test`，只取精确正确答案 | upstream仍1包；本地回答 flags8580、A `.99`／TTL600／empty OPT1232；隔离namespace Udp InDatagrams增量2（守护进程query + client reply）。 |
| `m6b-route-clear-invalid-udp` | 另一个client发1字节 `00`，0重试、无回答 | upstream仍1包；Udp InDatagrams增量1，证明实际listener已recv，不能只靠发送成功或睡眠。 |
| `m6b-route-clear-unmatched-upstream` | 原controlled upstream向held query的原source端口，发完整合法response但ID异或8000（唯一pending） | upstream仍1包；Udp InDatagrams增量1、原client无reply；raw packet／原endpoint／ID变更均保存。不能发下一health DNS作为barrier。 |
| `m6b-route-clear-hup` | `addn-hosts=/m2/caller.hosts` 从1名字改2名字，然后SIGHUP | 新 `read /m2/caller.hosts - 2 names` 出现在完整既有log的后缀，证明cache/hosts重载完成；动作UDP消费0，route不重发。不是单靠signal发送成功。 |
| `m6b-route-keep-bound-tcp-private` | 保留driver原 `bind-interfaces`，普通 `-k` 新TCP连接读本地health，关闭并等slot归零 | upstream2包且逐字/source端口相同；实际cmdline、完整config核验NOWILD私有child模式；TCP本地回答精确、forward actions仍1。 |
| `m6b-route-clear-debug-tcp-query` | 同样bound config，但真实 `-d` 模式；TCP共享父路径读本地health并关闭 | upstream仍1包；同样精确回答和排空；不能以wildcard accept的clear混淆debug query清除。 |

以上 C 位置分别为 `forward.c:1628`、`:1169`、`cache.c:1644`、`dnsmasq.c:2050–2065/2102–2197`、`forward.c:2465`。local host-record在C cache_reload里是F_HOSTS|F_CONFIG（`cache.c:1655`），故健康动作回答精确要求AA=1（8580），不沿用上游answer的8180或放宽两种flags。

clear批保留basic的全部raw/query/reply/netlink、真实ELF/rootfs/依赖、forward metrics与原idle FD身份门。动作完成须严格处于first实际recv和route trigger之间；消费计数3次、每次至少15ms分隔（执行固定20ms），动作2s截止，InErrors/RcvbufErrors不得变化。HUP不插入后续health query，TCP只在私有child或debug TCP路径取health，没有UDP health污染。所有新增场景仍cache0、TTL600、唯一UDP上游、没有fastretry/TFTP/DHCP或额外上游。

预期无resend时继续观察完整2s（验证至少1.9s），然后仅对原held packet发送cleanup answer，让原client得到1个精确正确答案并检查原FD3×20ms归位。`cleanup_answer=true` 在这个clear合同中是预定收尾，不是basic资格；若错误重发，保留2包证据，clear门false。普通bound TCP反之仍严格需要2个逐字同wire/source包；欠缺、变ID、变端口或第三包都不能过。C reference先满足每项预期，再和Rust逐项比较完整规范化问题/答案/动作响应；不以两边同错作为通过。

在上节命令的 `plan/run/compare` 全部加 `--batch clears`，使用fresh `route-clears-c`／`route-clears-rust` 目录。root独占Oracle；新工具及协议提交后才能实际跑。此批尚无实际C/R或Linux资格。

## 后续边界：仍 open，最小fixture已列但未接入工具

| 边界 | 下一批最小固定fixture与判定 | 当前缺口 |
| --- | --- | --- |
| server record实际删除 | 专用resolver输入产生唯一可删除server，没有CLI fallback；held query后更新源并见证实际server代际退役。无HUP的poll-resolv路径可独立验证server_gone；no-poll对resolv不得假定删除。另列no-poll+servers-file+HUP：servers-file仍读取、server删除与pending取消，但HUP本身也清save，不能单独归因server_gone。删除后旧response不得满足client，FD归位。 | 默认driver固定CLI server不能制造实际删除，需要启动配置准备hook与删除/取消证据。 |
| wildcard accept pktinfo清 | 真正删除 `bind-interfaces` 且不用bind-dynamic；first held UDP后只accept/EOF TCP、不发送DNS query，用实际accept完成与连接结束见证再route；不得混入debug query清。 | 完整启动配置hook与accept-only witness未接。 |
| two pending只last | client A的query实际上游recv后才发不同client B；held A/B、route后库存严格A/B/B；只重发B的原wire/source端口，分别正确完成A/B，forward actions2、FD回原集合。 | 多client完成与完整库存validator未接。 |
| all-servers最后成功目标 | 两个不同固定角色controlled endpoints、all-servers；first query各收到1包，route额外只有最后成功send的角色，wire/source必须与该角色first packet一致，actions1。配置的C遍历/send次序须先由源码锁定或增加实际send顺序见证；不同selector线程的recv时间不能冒充send顺序。 | 多endpoint库存/角色与last-send顺序见证未接。 |
| 重复有效route | first query→route A收到第2同包后，再创建不同connected route B→第3同包；两个kernel raw witness严格分开，仍只1answer/action，不能在event未消费时并发添加让C合并。 | 第二route固定prefix谓词及3包库存validator未接。 |
| fast retry清/再保存 | 启用固定fast-retry后，分别锁定actual retry前清与成功send重存；到期查询本身不得清，route不推进retry。 | timer/route顺序consumer补证未接。 |
| loop probe清 | 明确成功probe生成入口覆盖共享packet，probe后route不重发先前普通UDP；无周期新timer。 | probe与普通query的独立完整库存未接。 |

TFTP共享 `void *srv_save` 非DNStransfer别名仍仅source-only；不运行危险指针期待，不宣称额外故意差异或此行通过。所有open不是停止原因，也不能由basic或上述6项替代。

## 本地验证边界

host实际7组offline tests通过（含19个坏receipt变体、完整回答变体、kernel route谓词与裁剪消息、依赖/实际process-root/完整profile集合/显式expected SHA负控），py_compile与diff-check通过。合成receipt只测试验证器拒绝条件，不冒称C/Linux执行。初版controlled question guard误将normalized list-of-lists写成tuple，5组tests有4处错误；已修精确list guard并重跑7组。该失败仅前次工具输出的派生记录，未补造原始失败文件；最终stdout/stderr、plan与工具字节在 `E/M6B/route-resend-tool-local/`，manifest SHA `8be9f01b7db4ecb6237a6e213e868d7a848507fc81819fee2b69d2b0b69b10cc`，caller tool SHA `6dcbcbb1a6913b1c6831da3bfadbaf6e1e078a26ab918fdac68e617e04e5f1f5`。独立只读审查发现的完整upstream库存、回答精度与真实收包时序缺口已在冻结前修正，未拿旧过宽工具输出充资格。当前未有实际镜像门结果。

第二批本地补注：`test_m6b_route_resend.py`现11组offline tests全部通过。原7组basic守卫保持；新增6个合成positive、5个错误resend明确false、18个坏consumer/counter/action/mode/config/HUP/absence/packet库存负控，以及完整6profile/批次身份门。`py_compile`和diff-check通过。这些只证明工具验证器，未运行实际Linux action或C/R；工具执行无Oracle权限。本地冻结收据会单独保存在 `E/M6B/route-resend-clears-tool-local/`。

第二批freeze提交 `ce28e6c152c90cb4c35819ae47fbba0a818e85d2`；完整本地收据 [route-resend-clears-tool-local/manifest.json](../../../private/dnsmasq-rewrite/evidence/M6B/route-resend-clears-tool-local/manifest.json)，SHA `51e845dae7ce4db7e2ddd892579932f064e3a42936b91f45e4bc3484e39d519d`；caller tool SHA `dafa84dc7408d3b41f148cdd6664ee63f5ffaa4ae83c3483267dfb47bfa09906`。21个文件包含全部工具/测试/协议冻结字节、basic/clears plans、11组offline tests stdout/stderr与命令/exit、py_compile/diff-check记录。未执行新actual caller，不造通过收据。
