# 方案 A 69bc：服务门恢复记录

2026-10-08。执行中，不授予资源、压力、CPU或最终验收资格；main产品仍无A。全部性能结论仅构建机，物理路由器未操作。

| 对象 | 源码 | feature-off opt3 SHA256 | 字节 | 实际Linux测试 |
| --- | --- | --- | ---: | --- |
| NoA | e8b1d6c411fba324888e3e202c0c133156afbed4 | 2326f4e104c6ea2c13bfd410335356bb34094db532272c92d8884352bb50becc | 1,953,832 | 库744 / 入口65 |
| A | 69bccf2738f2c07cbc6d8b8a950015d4cea10af3 | 21937fa33b2552801278ea6cb15f0e13cb733824e4cd236382f968a1c1c4324b | 1,962,024 | 库753 / 入口66 |

公共UBus68实际过；两库各20 ignored不算通过。两组使用唯一共享Cargo target与oracle_build.sh，完整build/controller/test日志在E/M6B/pair-udp-acl-01；source tar SHA逐字验证后才解包。A相对最新NoA增加8,192B，体积不授予CPU收益。

普通wildcard UDP新接口ACL补充门实际C/A三case过：late-device、recreated-device、late-label。两组exit0、comparison_equal=true、passed=true；精确请求、源地址、两次miss/hit及UBus增量由原工具校验。实际result SHA `2cf40eefc1eed1f5babd716e010cb53d37a8f55150b593027d7b286652bd561f`，远端pair-udp-acl-01/noa/source/private/interface-acl-02，本地E/M6B/pair-udp-acl-01/acl-02-result.json。它仅补充普通caller，不替代完整interface族。首interface-acl-01因外层未sudo而unshare EPERM，C未启动、缺result，controller FileNotFound；原目录和日志保留，非产品失败。

前代A3c666/7128d3b6的日志targeted5case实际0失败：query-stale-producers、query-stale-refresh-context、startup-fault-error-pipe、startup-fault-error-pipe-flags、startup-error-frame-interrupt。result SHA `b5a46a7766c8b3096a86819d8f63e91de1205473164f895e7b79125a37204ee1`。据此ordinary log-queries缺口复闭169/0；原closed=[]保留，仅targeted，不授latest69bc完整族资格。

最新canonical六族27steps已启动：cache12（540/516、完整C加8repeat）、EDNS3、DNSfiles1、endpoints4、interface6、logging1（329完整scenarios）。产品取a/source，工具冻结自noa/source/tools/dnsmasq，避免A分支工具滞后；spec、完整argv、checks/inventory、源码/工具每步前后SHA和实际结果保存在noa/source/private/a-service-01。现成controller只改真实对象路径/身份，不修改比较器、C变体或期望。Endpoint归档watcher通过ubuntu staging传真实本地metadata证明，sudo copy后才能prune，GNU原tar保留special metadata。

后续仍需最新A原语/隔离/layout/同源companion、5accept supplements、public11、内部10批/150s/交错/S8、压力及45CPU。旧ae1/d8 raw和资格均保留历史，不改receipt假装最新same-source；现有cpu-a-reverse-fixed-01未跑且绑定旧ELF，后续fresh common必须最新NoA同源s，45门无新增27。

3批已完targeted原始证据均在本地full-archives/a-shared-targeted-01通过全部SHA+metadata才prune远端：logging-targeted 154路径/102文件，tar SHA41c5f8f7…7afec；ACL首权限失败19路径/17文件，55f1d864…59b7a；ACL成功263路径/222文件，5358d2ae…69789。完整manifest/proof/prune收据保留，没有修改overlay权限或复制special file为普通文件。

最新六份诊断prepare均已完整SHA传到pair-udp-acl-01/a/private，source-join实际验证原始编译maps与21937产品source/build/map一致，receipt SHA `a19cf11a4f256b94508e3f3b09a1587296d009ac7d092cafa6adc8c45ec9e95a`。prepare/transfer/source-join只为源绑定，尚未build/run；执行队列见[M6B_TCP_A_CURRENT_SOURCE_GATE_RECIPE](M6B_TCP_A_CURRENT_SOURCE_GATE_RECIPE.md)。

## 11:30 UTC 续接核对与整轮重跑

未查旧聊天。只依据AGENTS、账本和报告恢复。Oracle无残留build/test/perf进程、namespace或挂载，可用63GB；最新A工作树69bc完全clean，主树仅用户docs/prompts改动保留。资源工具树的limit30未提交草稿先保全为E/M6B/resume-20261008/worktree-patches下patch（SHA e1a9edcb1891cc231cd25cd4d218aeb24df6bc44d2d4aa5d432d7e64a54ee4b7）；历史dirty树保持原样。

旧a-service-01已无进程，result.passed=false、failures=[]、仅14/27步。cache两侧各540、8次C reverse及compare、lease caller共12步实际过；compare SHA `60f021f63e9565e7dec85186b5d715ae7b7205d9d73dbf2f6b5a31dd26ac4bfb`。EDNS两侧各196过，但compare及后续族未执行。SSH Connection reset/Broken pipe原日志保留，不能认定整门通过，也不能将部分结果拼入新轮。

全量旧目录已pack、本地SHA+全部metadata验证，再prune：E/M6B/full-archives/a-69bc-service-interrupted-01，13682路径/12475普通文件，tar SHA `c1d238823479c0dbe052b01827f0146c27888f7dc281a47141897e1adcf7f3e3`，manifest SHA `15e8d5b491ae14f3528de50a82bc19f0e18340cfc259fef91133acec852dbade`。pack/verification/prune和全部plain收据齐全。

新a-service-02保留原spec/registry/27库存、产品与工具身份，整轮从头运行。每job采用既有PID代际remember/stop收尾，远端nohup保存controller.log与.exit，本地endpoint watcher02独立运行并真实核metadata后送proof。首次launch外层异步shell保留SSH stdout，root独立确认远端nohup进程后终止owned本地wrapper（仅启动通道、非runtime失败），单独启动watcher；记录在pair-udp-acl-01/launch-service-02-wrapper-termination.json。当前不授新整门资格。第4包进一步缓存/租约优化遵用户本次指令延期到M6b之后。

后续资产已独立freeze/上传但未运行：资源工具快照eb62bf67包含容量1判据及required limit30补门，393工具文件；E/M6B/resume-20261008/resource-plan保留review、完整36job队列、runner、原Git tar及GNU payload。payload SHA `e3dc9c4cc4ac9177727ff6ac7b3c21b5b58116be61a5c9be999e7731d9275d9d`，queue SHA `fb2b9f3f63bd5e50e9a1b9abec0188185360cb37aea4fe0492d7e8d3944af4d7`；远端pair-udp-acl-01/resource-tools-current完整工具SHA核验过。原运行服务的noa/source/tools未改变。

CPU45独立fresh root为cpu-a-69bc-01，完整payload SHA `756003209070831d5fbb12da362c28dcc2ea48836557572ef85c74f78a6620f8`（1571537B），已SHA核验传输/解包。E/M6B/resume-20261008/cpu-plan含最新NoA/A源码maps、实build receipts、参数化同源s/common prepare、真实15门receipt入口、45row静态preview及持久controller/watcher；不含假passed或可执行CPU plan。未构建s、未prepare common、未跑窗口。所有前置实际过后才继续。

最新A复制main测试实际日志a/private/bin-tests.log中`tcp_closed_downstream_keeps_pending_stale_work_until_refresh_completes ... ok`且66passed/0failed。此真实上游控制owner门保pending refresh视图/G、完成后先释放DNS状态且持日志G、FIFO恢复后G0；与镜像cache stale及后续S8余额互补，不宣称stale专用1Hz内部余额已实测，不扩新trace矩阵。

fresh a-service-02最新A的完整cache12步已实际全过：540 executed/540 passed、required516，missing/differences=[]；9次C原规则、四指定PTR参考变体保持，lease TCP caller与9负控通过。本族独立完整归档E/M6B/full-archives/a-69bc-cache-service-02/cache，12195路径/11134文件全SHA+metadata核验后prune，tar SHA `1754c34c1778a6a36bd9fcebcaaa652403bb5a154e3b36294dc744062f94e5f7`，manifest SHA `bf8be29881089a99302861444c8b1e78113ca3bf6252c0648373649cc9e92926`。父controller仍继续余15步，cache原始结果已保于此独立归档，不把整服务门记通过。

本轮最后已实际27/27、failures=[]、passed=true、持久controller.exit=0；EDNS196、DNSfiles107、endpoints191/188及archive/source-row、interface252/276及全部closeout、logging329均完整。余15门及父identity/commands/result/log全量保全于E/M6B/full-archives/a-69bc-service-complete-02/service-remainder：18941路径/14484文件，tar SHA `e886faad8af7651b07ad92ac30b9b490afc200165a50243e2e61059fe25459d9`，manifest SHA `accf665d2ecdb2310d8909d12be332c06284cee630d840445790476438eb69df`，全SHA+metadata过才prune；cache单独完整归档保持。Endpoint原syntax/service special元数据另由watcher02真实验证/归档后恢复plain，原tar9b97f3ca…/886beb1d…保留。

69bc现作为完整历史服务资格保全：静态审查随后确认两个共同signal普通错误边界，不因上述通过豁免。NoA cd9edcf7 / A79e29d7d新pair-signal-01已启动实际两组构建/测试，后继资格必须fresh。源码tarSHA分别d2e4653b…/337f2f34…，新诊断五prepare已生成，第6resource须等新实际产品SHA；全部raw与动态入口在E/M6B/pair-signal-01。旧69bc资源/CPU资产未build/run，不能改receipt充新资格。
