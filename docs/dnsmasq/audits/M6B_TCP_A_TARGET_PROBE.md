# A target layout / allocation probe：统一构建入口

2026-10-08。工具准备，未生成、构建或执行。原 `m6b_tcp_a_layout.py` direct cargo/LLVM/native入口只用于本机模型，**不用于Oracle**。新 `--prepare-probe` 导出精确commit的ignored component copy，加入cfg(test)单个ignored lib-test与System meter；不改产品/交付allocator，不把其ELF叫产品。

Oracle经静态allowlisted `oracle_build.sh ... probe-tests`：仅release lib-test、opt3、feature-off、`--no-run`，共享 `/home/ubuntu/dnsmasq-cargo-target` 和原复制锁。清理同package release缓存、构建、从Cargo JSON识别并锁内复制唯一 `lib-dnsmasq_rs`，独立kind=probe-tests receipt；不能进入CPU gate的kind=release product binding。没有脚本自行创建Oracle target-dir。

采样scope使用const POD TLS Cell；开始/结束仅probe测试线程，其他libtest harness线程的分配保持inactive。allocator原样System alloc/zeroed/realloc/dealloc，无header/日志/registry，TLS不可用时不计，成功realloc才计delta。`allocations`是成功allocation/realloc请求数，不是新对象或libc malloc计数。snapshot/hit/detach/增长操作经过black_box并被order/ptr/余额或JSON结果使用，不借旧native数字当实际target；仍须方法controls核对TLS边界及fail-realloc。

生成收据保存Git component archive/PAX commit、完整原component输入与生成输入SHA、patch和tool SHA。probe构建在锁内记录编译前后source_files相等；不能以构建后的路径代替编译时字节。`--run-probe`只执行exact ignored单test，保存argv/退出码、执行前后ELF与stdout/stderr/prep/build SHA；collector核验archive原输入、tool/patch、实际编译输入、完整运行receipt、embedded source/probe identity、copied ELF和log。actual arch=aarch64/env=musl；libtest的同一行`test ... `前缀允许，但多个marker/失败/其他target/非整数size/缺scope拒绝。旧direct cargo方式须显式`--local-native`且拒绝/home/ubuntu Oracle路径。结果只提供target sizeof/请求分配scope，不能替代产品PSS/CPU/functional或10批余额。

以下命令只准备，**正式27窗口结束后由root执行**；out与report必须fresh。

```sh
python3 "$M6B_A_TOOLS/m6b_tcp_a_layout.py" --prepare-probe \
  --repository "$M6B_REPO" --source "$M6B_A_COMMIT" --out "$M6B_PROBE_PREP"

# 源迁移到Oracle后，保留prep receipt；组件逐SHA不得变化。
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' sh "$M6B_TOOLS/oracle_build.sh" \
  "$M6B_PROBE_SOURCE" "$M6B_PROBE_BUILD" probe-tests
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_A_TOOLS/m6b_tcp_a_layout.py" --run-probe \
  --receipt "$M6B_PROBE_PREP/probe-receipt.json" --probe-source-root "$M6B_PROBE_SOURCE" \
  --build-json "$M6B_PROBE_BUILD/build.json" --test-elf "$M6B_PROBE_BUILD/lib-dnsmasq_rs" \
  --test-log "$M6B_PROBE_LOG" --test-stderr "$M6B_PROBE_STDERR" --run-receipt "$M6B_PROBE_RUN_RECEIPT"
python3 "$M6B_A_TOOLS/m6b_tcp_a_layout.py" --collect-probe \
  --receipt "$M6B_PROBE_PREP/probe-receipt.json" --probe-source-root "$M6B_PROBE_SOURCE" \
  --build-json "$M6B_PROBE_BUILD/build.json" --test-elf "$M6B_PROBE_BUILD/lib-dnsmasq_rs" \
  --test-log "$M6B_PROBE_LOG" --test-stderr "$M6B_PROBE_STDERR" --run-receipt "$M6B_PROBE_RUN_RECEIPT" --report "$M6B_PROBE_REPORT"
```

保全source/patch/prep/build/test ELF/stdout/stderr/report全部SHA，collector不得覆盖前次失败。报告分别列SlotIndices/NameIndex/bucket payload的target尺寸、高位shard分布、Singleton/Many2/3/64/1024、共享首次写与unique后续写的容量/请求数。ContentBlock仍两对象，尾块模型和额外指针成本另列，不以此probe指称CPU收益。当前方法controls、生成Rust/CLI、actual target均未验证，所有相关fresh门仍open。
