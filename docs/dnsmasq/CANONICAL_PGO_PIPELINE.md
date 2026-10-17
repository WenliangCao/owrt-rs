# 统一 v0.2.2 的 dnsmasq PGO 构建

**先冻结十组件整合源码，再生成一次插桩产物、训练一次、构建一次待验 use ELF。**
旧 a97 独立设备批次已退役；本文及工具不携带旧源码冻结清单，不授权独立部署。

producer / consumer 都使用 x86 CI、Rust 1.98.1、相同 SDK、普通 Cargo 输出级别及
同一绝对构建槽。Oracle 只执行冻结训练负载；最终实际 ELF 与整合镜像共同验收。
构建槽固定为 `/home/ubuntu/owrt-unified-v022-20261017/private/dnsmasq-sdk-build-slot`。

冻结 spec 必须显式提供：`source_commit`、`source_date_epoch`、完整 `source_files`
哈希映射、该映射的 `source_file_count` 和规范 JSON SHA256 `source_digest`。
映射由 `tools/dnsmasq/build_package.py::inputs` 产生，必须包含共享 platform；构建
从指定 Git commit 取档，再核对全部文件，不以工作树或旧原生测试替代最终输入。
保留 `package_release="4"`、`elf_max_bytes=2500000`、`apk_max_bytes=1400000`。

三个显式 `pgo_stage`：

- `generate`：`pgo` 只含固定 `build_slot`、`retain_link_map=true` 和
  `profile_output_dir="/tmp/dnsmasq-unified-v022-ci-pgo"`。不接受输入 profile。
  单列 `instrumentation_budget={"elf_max_bytes":6000000,"apk_max_bytes":3500000}`，
  产物仅用于训练。
- `candidate-use`：移除插桩预算与输出目录；保留 slot/map，增加
  `profile_url`、`profile_sha256`、`profile_bytes`。唯一 asset 名为
  `dnsmasq-<source前8位>-<完整profile SHA>.profdata`，仍存既有 PGO build-input
  release。`pgo.training` 绑定 generator manifest、generator ELF、training receipt
  三个 SHA256。首次 use 不预填参考 ELF；直接冻结实际输出并送最终资格验收。
- `frozen-use`：增加已接受的 `reference_elf_sha256`、`reference_elf_bytes`。
  发行重建必须等于该实际验收 ELF；前两阶段均不能绕过此门。

未冻结源码前不要创建真实 spec 或派发。冻结后的显式入口为：

```sh
gh workflow run dnsmasq-pgo-candidate.yml \
  --repo WenliangCao/owrt-control-plane-rs --ref research/core-safe-20261017 \
  -f stage=generate -f spec=manifests/<已冻结的整合generate清单>.json
```

没有 push 自动触发或旧 spec 默认值。每次输出保留原始日志、完整源码归属、APK/ELF、
host/target Cargo 指纹、build-script 输出，以及同构建 `link.map` 和 prestrip。
共享 owrt-platform 也在指纹集合中。map wrapper 仅在实际 static PIE 链接追加地图
输出，不改变 Cargo/rustc 的代码生成参数。任何未知或正常构建可见的编译/Cargo/
linker warning、profile missing/mismatch 均失败；最终预算仍为 2.5/1.4 MB。

Oracle 的 `tools/dnsmasq/pgo_training_only.py` 请求另需 `source_spec={path,sha256}`，
绑定本轮完整 generate 冻结清单。`reference_plan` 只固定原 workload、seed、工具、
SDK 与 C helper，绝不提供新产品 source 身份。请求还绑定实际 CI manifest/ELF 与
新 ELF 的 excluded smoke 收据；输入 hashes 验证后才执行原 collect。CI 调用收据
显式记录 `cargo_verbosity=normal`，两阶段都核验。最终输出继续标记 unqualified。

历史诊断 `39045487550` 的 `-vv` 暴露两条 rustix 未启用 hint 提示而失败；普通模式
`39046178426` 为 0 编译警告，同一插桩 ELF SHA 与 7 项 Cargo 身份记录完全相同。
两份原始结果均保留。`-vv` 也将 registry dependency 的 `--cap-lints allow` 改为
`warn`，所以不声称全部 rustc argv 相同，也不声称第三方 verbose 诊断为空。
统一链只声称实际执行的普通发行构建 0 编译警告；不加白名单、nightly 或 vendor 修改。

## 最小证据复用边界

`a97edbc1` 与整合树 `bbcaec4f` 比较，dnsmasq 的 `src`、`platform/src` 共 162 个
文件及两份 Cargo.toml 逐 blob 相同；变化是 DNS 锁、owrt-ubus 的 connect/readiness/
sys/lib、共享 platform 与打包输入闭包。最终冻结后重查这份差异，不能把当前比较当
作最终源码冻结。

| 已有证据 | 可复用范围 | 新整合候选必须绑定的内容 |
| --- | --- | --- |
| native 988 项 | 未变 DNS 函数体的算法与边界证据；保留原源码身份 | 共享依赖/feature 闭包变化后的编译与相关集成测试，不能把旧 988 报成新运行 |
| 8 组源码 corpus | 未变 config/cache/lease 函数体及固定 C oracle；既有 lease 布局差异继续保留 | 最终冻结若修改相应函数体或 oracle/fixture，则只重跑受影响组 |
| 原训练场景、种子、负载工具与 C helper | 经原哈希验证后复用，不重新设计 workload | 新 CI instrumented ELF 的 excluded smoke、11 场景/50 profile；旧 profile 不复用 |
| 旧 ELF 的 44/67、no-proc、FD、shipping、startup | 历史行为及原失败/纠正记录 | 共享依赖影响实际 ELF；最终新 ELF 的这些行为重新绑定，尤其 UBus/readiness/fork |
| 旧 K 对照与设备负载工具 | 固定基线身份、原 workload、噪声与分析方法 | 整合候选的统一现场批次；旧 a97 独立 40/148 自动排程已撤回 |

keepcaps 精确选项注入、UBus 346 项清单以及已验证的 startup snapshot 修正随工具
迁入整合树，不通过重现已经定位的 fixture 错误来增加新候选工作量。所有旧原始记录
保留；复用算法证据与新二进制资格分别标明。
