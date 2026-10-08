# A 内部余额：精确执行入口与分阶段资格

2026-10-08。只准备工具与 ignored source copy，未访问 Oracle、未构建或运行测试。
产品仍冻结 `d8ddb22b3dcd3cce2eae44b0941f5c4095800b3c`，feature-off opt3
SHA `924bdfc240f1ef811c8eacb4035a7476f8581166469144b6e4a22a01449a2c71`、
1,957,928 B。A 未合 main。本文入口不能代替服务、产品 PSS 或 CPU 门。

## 准备收据与第一个方法失败

本地 `private/dnsmasq-rewrite/evidence/M6B/a-d8-resource-prepare-01` 保留首次生成失败：
旧 guard 扫描整个仓库 components，误把 httpd/ubusd/rpcd examples 的 global allocator
当成 dnsmasq 产品 allocator，实际拒绝生成。修正只检查现有 `compilation_files`
定义的 dnsmasq/ubus 产品输入，不放松真正产品 allocator 的拒绝。

修正后的 `a-d8-resource-prepare-02` 已实际生成，status 仍
`prepared-not-built-not-validated`；三个模板包含本次六个方法 controls。
精确根锚仍 content constructor1、NameIndex constructor2、content detach2、index detach2，
与 d8 的 Empty/One/Many `Arc<Vec<usize>>` 相容。Many Arc 不当 content/index root。
任何后继模板变化都需新 fresh prepare，旧生成 copy 不覆盖。

```sh
M6B_REPO=/Users/USER/Developer/owrt-control-plane-rs
M6B_A_COMMIT=d8ddb22b3dcd3cce2eae44b0941f5c4095800b3c
M6B_A_SHA=924bdfc240f1ef811c8eacb4035a7476f8581166469144b6e4a22a01449a2c71
python3 "$M6B_REPO/tools/dnsmasq/m6b_resource_companion.py" prepare \
  --repository "$M6B_REPO" --source-commit "$M6B_A_COMMIT" \
  --product-sha256 "$M6B_A_SHA" \
  --out "$M6B_REPO/private/dnsmasq-rewrite/evidence/M6B/a-d8-resource-prepare-03"
```

完整 prepare 输出用 Python `tarfile.GNU_FORMAT` 传输，不使用带 Finder `._` 的 BSD tar。
生成源码不修改产品树。传入 Oracle 的建议固定布局如下；`M6B_IMAGE` 使用 root 已校验
SHA097镜像的既有绝对路径，不能临时换另一份 image。

```sh
M6B_A_ROOT=/home/ubuntu/dnsmasq-m6b-20261007/a-fresh-d8ddb22b
M6B_TOOLS="$M6B_A_ROOT/tools-freeze/tools/dnsmasq"
M6B_PREP="$M6B_A_ROOT/resource-prep-03"
M6B_DIAG_SOURCE="$M6B_PREP/source"
M6B_DIAG_BUILD="$M6B_A_ROOT/private/resource-diag-build-03"
M6B_CONTROL_BUILD="$M6B_A_ROOT/private/resource-control-build-03"
M6B_CONTROL_RUN="$M6B_A_ROOT/private/resource-controls-03"
M6B_PRODUCT_BUILD="$M6B_A_ROOT/private/opt3"
M6B_LAYOUT_REPORT="$M6B_A_ROOT/private/layout-probe-01/layout-report.json"
```

先把本文对应工具提交的完整 freeze 导出并更新 `M6B_TOOLS`；022e5f22 旧 tools-freeze
没有新 internal runner/controls，不能只复制一个入口漏依赖。各命令写到远端脚本文件，
root 用 `ssh -n oracle sh FILE` 调用，每个命令 `</dev/null`，不继续 stdin SSH 脚本。
在没有正式窗口且 root 串行调度期间执行：

```sh
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_LINK_MAP=1 \
  sh "$M6B_TOOLS/oracle_build.sh" "$M6B_DIAG_SOURCE" "$M6B_DIAG_BUILD" release </dev/null
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_LINK_MAP=1 \
  sh "$M6B_TOOLS/oracle_build.sh" "$M6B_DIAG_SOURCE" "$M6B_CONTROL_BUILD" probe-tests </dev/null
python3 "$M6B_TOOLS/m6b_resource_companion.py" bind \
  --receipt "$M6B_PREP/receipt.json" --diagnostic-source-root "$M6B_DIAG_SOURCE" \
  --build-json "$M6B_DIAG_BUILD/build.json" --diagnostic-elf "$M6B_DIAG_BUILD/dnsmasq-rs" \
  --product-build-json "$M6B_PRODUCT_BUILD/build.json" \
  --product-elf "$M6B_PRODUCT_BUILD/dnsmasq-rs" \
  --out "$M6B_PREP/bound-receipt.json" </dev/null
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_internal.py" controls \
  --bound-receipt "$M6B_PREP/bound-receipt.json" \
  --build-json "$M6B_CONTROL_BUILD/build.json" --layout-report "$M6B_LAYOUT_REPORT" \
  --out "$M6B_CONTROL_RUN" </dev/null
```

唯一共享 target `/home/ubuntu/dnsmasq-cargo-target`、统一 build/copy lock、release opt3、
feature-off 和 source-before/after 沿用 oracle_build。controls 在 copied release lib 上逐项
执行 exact 六个 test；每次新 TMPDIR；逐个保存 argv、退出、ELF 前后 SHA、stdout/stderr。
System 正常/zeroed/realloc/free、真实超大 realloc 失败保留旧块、已知未释放64B对象、
observer reserve/grow/drop、真实根 detach/缺 constructor/缺 detach、同地址 stamp 都有实际
断言。缺 hook 负控必须真的使 registry missing 变正；不能把编译失败记成负控成功。
诊断 Slot/Entry/Record/ContentBlock/Cache/SlotIndices/NameIndex 尺寸逐一对原 d8 实测 layout。

## 第一阶段：固定父缓存的10批重连

新增 `m6b_tcp_internal.py run/collect`，每次只运行一个 capacity；推荐先跑4096，让 root
及时拿到最关键门。随后0/1/150独立 fresh namespace。每批20连接，各保持独立 view；
完整预填 parent，随后使用同一固定名字集合与同一600s单A回答。父 DO 强制替换32个既有
名字、每 child 强制同名提取一次再命中另一既有名字，真实 upstream events 必须增加。
有一个不计资格的同样 structural warm batch，先稳定 clients/fd-array/HashMap 容量。
每个 measured batch 必须实际记录20 clients/G/work/views、旧parent pinned和child private
根，再全部排空并取得相隔至少0.9s的两条稳定内部样本。后10批完整保存，没有挑最好批次。

```sh
M6B_INTERNAL_OUT="$M6B_A_ROOT/private/internal-4096-03"
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_internal.py" run \
  --image-root "$M6B_IMAGE" --rust "$M6B_DIAG_BUILD/dnsmasq-rs" \
  --bound-receipt "$M6B_PREP/bound-receipt.json" --capacity 4096 \
  --out "$M6B_INTERNAL_OUT" </dev/null
python3 "$M6B_TOOLS/m6b_tcp_internal.py" collect --run "$M6B_INTERNAL_OUT" \
  --controls "$M6B_CONTROL_RUN/controls.json" \
  --out "$M6B_A_ROOT/private/internal-4096-03-result.json" </dev/null
```

trace 固定 `/m2/internal.jsonl`，create_new；生成器不增加产品队列或 Arc owner。最后完整
trace 留在 output `rootfs-overlay/upper/m2/internal.jsonl`，另存 `diagnostic.jsonl` 相互逐字节
校验。namespace 退出后的 `rootfs` 空目录不当证据。trace/marker/result/controls/build/ELF/
工具字节均绑定；每个实际 query/reply、UBus call、FD 稳定样本和最终0/1/5/15/60s PSS/
Anonymous保存并复核。计时诊断增加1FD与1Hztimer，PSS/CPU不作为产品表现。

collector 对所有十批要求 parent root/registry容量、对象余额、各 buffer容量与 warm baseline
相等，client/view/TCP/UDP/pin/private全部归零，`live-requested - observer-registry` 初末严格
相等；缺钩/失败分配/负余额即方法失败。最终 drain epoch 必须有完整0/1/5/15/60真实时间。
同时从完整成功 raw 故意注入残留client/view/transaction/pin、已知1B/1object增量、registry
增长、缺hook、缺批、缩短60s采样，十个 collector 负控必须拒绝。更改 raw 与对应 marker
一同进行，避免只证明“报告不相等”而没有证明余额门。

此阶段通过只关闭**相应capacity的固定名字10批门**。公共 `m6b_tcp_pressure` 的旧
reconnect4096每批新增264名字、10批尚未填满4096，不能拿它的增长当泄漏或当余额通过。
公共11 profile 仍另跑 feature-off product C/A wire+FD/PSS门，内部 companion不替代它。

## 第二阶段：已写入口，明确未运行

同一个诊断 source/ELF/controls，无需重建；新增仅 runner/collector。每个独立 fresh output：

```sh
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_internal.py" run \
  --image-root "$M6B_IMAGE" --rust "$M6B_DIAG_BUILD/dnsmasq-rs" \
  --bound-receipt "$M6B_PREP/bound-receipt.json" --profile half --capacity 4096 \
  --out "$M6B_A_ROOT/private/internal-half-4096-03" </dev/null
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_internal.py" run \
  --image-root "$M6B_IMAGE" --rust "$M6B_DIAG_BUILD/dnsmasq-rs" \
  --bound-receipt "$M6B_PREP/bound-receipt.json" --capacity 16384 \
  --out "$M6B_A_ROOT/private/internal-16384-03" </dev/null
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_internal.py" run \
  --image-root "$M6B_IMAGE" --rust "$M6B_DIAG_BUILD/dnsmasq-rs" \
  --bound-receipt "$M6B_PREP/bound-receipt.json" --profile multi-rr --capacity 4096 \
  --out "$M6B_A_ROOT/private/internal-multi-rr-4096-03" </dev/null
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_internal.py" run \
  --image-root "$M6B_IMAGE" --rust "$M6B_DIAG_BUILD/dnsmasq-rs" \
  --bound-receipt "$M6B_PREP/bound-receipt.json" --profile pin150 --capacity 150 \
  --out "$M6B_A_ROOT/private/internal-pin150-150-03" </dev/null
```

每个 output 仍用第一阶段 `collect --run ... --controls ... --out FRESH_JSON`。
half4096 只预填2048条；大缓存16384完整预填；multi-RR4096预填2048名字×双A，
固定 seed `0x6b4096` shuffle，各20 child真实查询相同RRset两次，raw必须保持双A并轮转
RR顺序；仍完整warm+10批、严格初末余额。pin150先同样warm20连接，然后只持有1 view，
连续140s每秒强制替换一个既有parent名字，在140s再查旧snapshot，150s原始deadline关闭
（145–160s witness）；old parent roots实际pin至少130s、释放后全部归零并严格余额。
诊断1Hztimer可推动该伴随构建，因此**不证明feature-off product timer正确**，普通公共
idle-pin150的C/A配对仍必须独立通过。

## 其它并行阶段（明确未运行）

| 设计压力 | 现有覆盖 | 后继必须补齐 |
| --- | --- | --- |
| 空/小/4096、20client、10批 | 本文第一阶段工具已写，未运行 | 全部实际通过且保全 |
| 半满和大缓存 | 第二阶段已写入口 | 实际run/collect未做 |
| 单条150s snapshot+父持续替换 | 第二阶段pin150已写；公共 idle-pin150有wire/FD | 两种ELF的实际资格独立，未运行 |
| 随机多RR轮转 | 第二阶段multi-rr已写 | 真实raw RR顺序和内部余额尚未运行 |
| 错峰accept+同名冲突 | 独立m6b_tcp_interleaved代理准备 | 固定不同代际accept、父子同名RDATA冲突及即时导回证据 |
| reload/lease更新+导入交错 | 独立m6b_tcp_interleaved代理准备 | 保留accepted旧代际/parent新代际，hold child upstream后reload或lease发布再导入，内部余额 |
| EOF/deadline/stale/log-only/TERM | 公共11/M5及独立interleaved补充 | 同companion交叉G/work、待事务、pin释放与诊断写失败；不从FD推对象 |

以上剩余压力与方法异常控制属于独立后续工具单元，由 root 串行实际验证；未做不能写
“设计5.6通过”。全部 raw/receipt/source/ELF/patch 按 SHA+metadata回拷验证后才 prune。
