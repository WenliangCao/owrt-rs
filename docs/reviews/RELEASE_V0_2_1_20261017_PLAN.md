# v0.2.1：K 正式发布、保留配置部署与清理

用户已明确批准合入main、正式流水线、保留配置刷机及一次正常重启，无需再次确认；
验收后推送main和不可移动的v0.2.1标签并设Latest。未授权物理断电操作，本轮不把普通
重启称为断电验收。用户未提交的docs/prompts及第三份专家报告保持原样。

## 固定输入与发布顺序

- K产品源4ce24c627615ae5ff42d3dcdbccb66d57b218b5a：181项源码/SDK输入digest
  `6505f110f02b8488c14a9261c37e13362d4227fdaffb4c2a23380e17029de4b7`。
  正式集成仅31个必要源码/测试/探针路径，不合实验分支，不含名字复用、备用OPT或插桩。
- 已接受ELF `f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08`，
  2,296,611B；profile `a26b78f1777a126799592f819cce07f1a904f92db2aa04dbf0a8e1aba4f4bfcc`，
  937,008B。原11场景/50profile单次合成训练复用，不重训，不将profile或固件提交Git。
- 永久构建输入存于非固件、非Latest的`dnsmasq-k-pgo-inputs-20261017` Release；下载后
  验哈希。正式CI使用固定Rust1.98.1及原SDK recipe，Cargo wrapper最后追加profile-use。
  缺profile、CFG/hash不符、编译覆盖参数、ELF不等于已接受K均失败，不自动放宽身份。
- 统一APK版本`0.2.1-r1`，dnsmasq中间包r4、init/ACL、布局marker和另外九组件源不改。
  DNS ELF/APK预算分别2,500,000/1,400,000B。原OpenWrt内核、驱动、CONTROL和固件元数据
  由既有native_image审计保持精确身份。
- 先推临时release分支执行正式`release-image` workflow_dispatch。main仅本地整合；
  main/v0.2.1远端推送与Latest等实际验收完成。v0.2.1指向实际CI构建提交，后续文档不移tag。
  发布和刷入使用同一批CI字节，禁止本机构建替代。最终tag推送沿原短时workflow停用/
  finally恢复及重复tag-run检查，避免自动重建替换已验收镜像。

首次CI39006620445在PGO门停止：源码/profile正确，但2858条函数missing、0 CFG/hash mismatch。
精确Cargo797e8a9bc的PackageId/SourceId逻辑及cargo metadata证实，工作区外的兄弟ubus
依赖把完整绝对路径计入crate标识；CI的package-build根与训练时不同。74425a03仅恢复
训练时包构建slot，保留当前profile/CARGO_HOME位置与正常remap，不改profile或强制metadata。
同时保留实际编译产物/小fingerprint到失败artifact。原失败不追认，下一最终CI仍必须零missing
且ELF精确等于K。正式工具检查更新为181输入，原179项测试冻结只属于v0.2.0。

## 恢复与真机验收

1. 当次新鲜配置备份、现场成员哈希、服务保留列表、8份历史MTD/Factory与完整备份在Mac
   private核验。v0.2.0官方回滚镜像13,639,968B，SHA
   `2f8083e44a548802de1738ecd8ef5231f74fda950a0a69a44f0e10e2e1d30ffd`。
   官方小米1.0.47最后救援镜像按r23既有hash补齐，保持离线。密钥/配置不进入Git。
2. 现成native_trial自动回退逻辑仅做v0.2.0目标/v0.2.1收据字面量适配，原600秒首次确认、
   300秒失健康及一次回刷熔断保留。最终rootfs上复用23守卫分支、配置恢复/12份C文件及
   正常PID1交接检查；生成新token及私有恢复包。完整v0.2.0回刷与C恢复明确区分。
3. 精确CI rootfs执行现成native_image_check/native_boot_check，核十组件、APK、init/ACL、
   DNS/DHCP及迁移恢复。ELF若精确复现K，可复用原44族/67任务及性能，不重复全套研究。
4. 当次设备身份、备份及rollback hash、空间、sysupgrade -T与客户端健康通过后，告知
   预期中断并按既有授权提交一次保留配置刷写，不加-n；断连不当成失败，不盲目重刷。
5. 新启动核十组件安装/ROM/适用进程、2集成文件与12stock恢复项，原配置一致、服务状态、
   Wi-Fi、DHCP、DNS UDP/TCP A/AAAA、WAN、IPv4/IPv6 HTTPS、LuCI与fw4。确认新boot对应
   的guard后正常重启一次，再重复同一检查。任何失败原样记录，触发既定恢复不转Latest。

## 白天60分钟采样与资源观察

稳定重启验收后固定3600秒被动采集，记录本地/UTC开始与结束；不得将夜间19查询样本冒充
白天结果。沿原LAN本机目的UDP53入口、不混杂、不改防火墙、不保存报文/名字/IP/逐包。
输出EDNS/空OPT/DO、AD/CD及未知报文、TCP段、drops、分片等完整分母。固定health名
保守排除；加密DNS和直连外部DNS不在可见范围。

双栈共现定义：同一观测源IP/地址族、规范化同名A与AAAA在从采样开始划分的同一10秒
不重叠窗中出现；2048固定槽精确比对，只在内存保存，结算清空。输出dual_groups/
all_groups及dual_group_queries/tracked_A_AAAA_queries，单独报告重复、溢出/未跟踪和
partial窗。跨窗漏配、同设备换源地址拆组限制保留；不称设备IPv6能力或K缓存命中比例。

并行用现成只读/proc方法观察生产CPU、RSS/Anon、FD、线程、PID/starttime、内存、日志
及低频客户端健康；使用实际时长和服务年龄，不能把不同真实时段占用差叫等负载性能。
最后明确24小时待看：PID/崩溃/重启、RSS与FD是否持续上升、自然续租/新设备DORA、
UDP/TCP及双栈DNS、WAN/Wi-Fi/LuCI、守卫/回滚状态。短观察不宣称已通过24小时耐久。

## 验收后清理

先提交脱敏部署/统计/空间报告，再按用户授权删除实验raw，不额外保留整套证据归档。
Oracle只删本轮研究目录、明确构建缓存、所属shm临时文件；Docker服务/数据和原厂镜像/
SDK基础设施保留。路由器删除/tmp测试/部署残留并收尾临时guard，不删除生产文件。
Mac退休完成的工作树/分支前以Git tag保存HEAD；删除其cache/raw和仓库外归档，保留main
及所有Git标签、未提交用户文件、private路由备份/最新配置/回滚与救援镜像。当前发布数据
在统计核对和报告完成后才删除。各机记录删除前后df与所选路径分配量，APFS共享/其他
活动造成的差别如实区分，不把du简单相加冒充真实释放空间。
