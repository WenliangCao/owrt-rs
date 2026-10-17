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

历史诊断 `39045487550` 的 `-vv` 暴露两条 rustix 未启用 hint 提示而失败；普通模式
`39046178426` 为 0 编译警告，同一插桩 ELF SHA 与 7 项 Cargo 身份记录完全相同。
两份原始结果均保留。`-vv` 也将 registry dependency 的 `--cap-lints allow` 改为
`warn`，所以不声称全部 rustc argv 相同，也不声称第三方 verbose 诊断为空。
统一链只声称实际执行的普通发行构建 0 编译警告；不加白名单、nightly 或 vendor 修改。
