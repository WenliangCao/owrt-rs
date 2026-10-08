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
