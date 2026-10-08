# 原21-case reverse门的只读 ordering sidecar

2026-10-08。只提交 prepare/run/collector工具，未生成diagnostic源码、编译、执行测试或访问Oracle。产品、原C/Rust comparator、21-case corpus和旧strict4/12差异不改。M5完整cache服务独立推进。

本门仅复用原`multiple-ptr-export-order`的12行输入；C仍21case×native/SDK×3（126个原有预算），Rust仍同21case。没有扩D/C/M/E/I/S1/S2七profile或257-name池。本collector可证明实际诊断布局上的插入点／lookup／LRU关系，不冒称七profile collision/pressure门、完整原primitive或产品CPU/PSS通过。

## 方法与身份

`m6b_reverse_order_sidecar.py prepare`由完整product commit/PAX component archive导出ignored copy：

- Rust只在真实`reverse_bucket`原return处保留原computed bucket并记录name/bucket/原64B mixer。算法表达式不改、不再复制一个hash；snapshot读取真实reverse_chain和LRU，通过同一个真实函数取得name bucket，标diagnostic=true。原计算路径标false。
- 原reverse cfg(test) adapter只增加owner/command上下文及A/T前后snapshot，原标准stdout仍完全相同。没有产品字段／API、root引用、COW状态或持久顺序字段改变。
- C private driver/include由hash-pinned `cache.c`和原driver派生。真正hash_bucket return处记录原name、actual bucket、真实typestr64B；T/A读取真实hash chains/LRU。额外static/CNAME只作元数据，不读不适用union。O_APPEND短单write JSONL，失败退出118为方法错误。
- private C builder复用现有fresh C source/ABI/argv/receipt逻辑；只换diagnostic driver及每invocation的sidecar环境变量，把整个生成C目录纳入before/after输入。不是将未改C源码的qualified声明套在hook后的程序上：这些是diagnostic-only派生产物。

source-receipt锁product archive/base inputs、generated compile inputs、Rust/C templates、private driver/include/header/patch和builder/corpus SHA。root经统一`oracle_build.sh ... probe-tests`（release opt3/feature-off/共享target/锁内copy）取得唯一copied lib ELF；已有rust_lib_probe重验source-before、全部输入、ELF64 little AArch64及前后SHA。C与相依fresh-transfer收据也完整验证。

诊断代码会改变自身ELF布局，因此自己的typestr pointer bytes可能与旧e290 probe或产品ELF不同；只能归因这一实际diagnostic ELF的bucket/chain关系。旧e290 strict4/12仍原样保存，不能用新link后偶然匹配覆盖它。所有raw、失败、sidecar、ELF/build/source/archive/receipt一起归档。

## root执行入口（未运行）

```sh
python3 "$M6B_TOOLS/m6b_reverse_order_sidecar.py" prepare \
  --repository "$M6B_REPO" --source-commit "$M6B_A_COMMIT" \
  --reference-source "$M6B_C_SOURCE" --out "$M6B_ORDER_PREP"

ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' \
  sh "$M6B_TOOLS/oracle_build.sh" "$M6B_ORDER_SOURCE" "$M6B_ORDER_BUILD" probe-tests

# 保留完整prep source/receipt/product-components.tar/C目录。C private脚本
# 导入的是同一冻结TOOLS中的transfer/helper，不能在目录内放别版dependencies。
sudo -n sh "$M6B_TOOLS/run_isolated.sh" env PYTHONPATH="$M6B_TOOLS" \
  python3 "$M6B_ORDER_PREP/c/cache_reverse_transfer_oracle.py" \
  --reference-build "$M6B_C_NATIVE" --source-identity "$M6B_C_SOURCE_IDENTITY" \
  --sdk "$M6B_SDK" --target-reference "$M6B_C_TARGET" \
  --transfer-baseline "$M6B_FRESH_TRANSFER" \
  --fresh-transfer-receipt "$M6B_FRESH_TRANSFER/fresh-c-receipt.json" --out "$M6B_ORDER_C"

sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_reverse_order_sidecar.py" run-rust \
  --source-receipt "$M6B_ORDER_PREP/source-receipt.json" \
  --rust-source-root "$M6B_ORDER_SOURCE" --rust-test-binary "$M6B_ORDER_BUILD/lib-dnsmasq_rs" \
  --rust-build-receipt "$M6B_ORDER_BUILD/build.json" \
  --c-baseline "$M6B_ORDER_C" --fresh-c-receipt "$M6B_ORDER_C/fresh-c-receipt.json" --out "$M6B_ORDER_R"

python3 "$M6B_TOOLS/m6b_reverse_order_sidecar.py" collect \
  --source-receipt "$M6B_ORDER_PREP/source-receipt.json" \
  --rust-source-root "$M6B_ORDER_SOURCE" --rust-test-binary "$M6B_ORDER_BUILD/lib-dnsmasq_rs" \
  --rust-build-receipt "$M6B_ORDER_BUILD/build.json" \
  --c-baseline "$M6B_ORDER_C" --fresh-c-receipt "$M6B_ORDER_C/fresh-c-receipt.json" \
  --rust-run "$M6B_ORDER_R" --out "$M6B_ORDER_RESULT"
```

collector逐一处理六个C运行和Rust实际trace，不选择有利permutation：

1. 每个进程／fork继承的64B mix和name bucket自身一致；不要求C/R bucket相同。
2. CH prelookup原输入序／P2 prelookup导出导入双反序精确；实际name bucket与snapshot、原T行一致。
3. 复用既有`cache_reverse_order_oracle.model_chains`，按本invocation真实bucket检查leading equal-name插入点和完整chain，不sorting。
4. 实际A输出严格等于reverse(actual hash walk)，随后LRU严格等于该输出；lookup不改chain、随后T保持LRU、计数3/0。
5. changed LRU、changed bucket、missing snapshot三个负控必须拒绝；整个21-case Rust inventory和所有raw SHA完整。

结果`ordered_relation_gate_passed`仅表示这套有序关系及方法controls；`full_original_primitive_passed=false`与`product_cpu_pss_qualification=false`固定保留。结果同时列全部六份12行strict C/R逐行差异，不改旧comparator、不把它们清零。若关系失败，必须作为具体插入点／遍历／LRU／方法缺口处理，不能用“布局”名称掩盖。
