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

## 后续边界（本批不冒称执行）

按合同表逐项补：local/cache/invalid UDP覆盖、未匹配upstream read、fast retry、server实际删除、HUP/cache_reload、loop probe；两个pending只重发最近成功包、all-servers最后成功目标、重复有效route；NOWILD/CLEVERBIND ordinary child私有query保留父save、wildcard accept的父pktinfo及debug共享query清save。它们是独立普通功能边界，不由2个基本场景替代。

TFTP的共享 `void *srv_save` 非DNStransfer别名当前仅source-only；不运行危险指针期待，不把它伪造成故意新增差异。

## 本地验证边界

host实际7组offline tests通过（含19个坏receipt变体、完整回答变体、kernel route谓词与裁剪消息、依赖/实际process-root/完整profile集合/显式expected SHA负控），py_compile与diff-check通过。合成receipt只测试验证器拒绝条件，不冒称C/Linux执行。初版controlled question guard误将normalized list-of-lists写成tuple，5组tests有4处错误；已修精确list guard并重跑7组。该失败仅前次工具输出的派生记录，未补造原始失败文件；最终stdout/stderr、plan与工具字节在 `E/M6B/route-resend-tool-local/`，manifest SHA `8be9f01b7db4ecb6237a6e213e868d7a848507fc81819fee2b69d2b0b69b10cc`，caller tool SHA `6dcbcbb1a6913b1c6831da3bfadbaf6e1e078a26ab918fdac68e617e04e5f1f5`。独立只读审查发现的完整upstream库存、回答精度与真实收包时序缺口已在冻结前修正，未拿旧过宽工具输出充资格。当前未有实际镜像门结果。
