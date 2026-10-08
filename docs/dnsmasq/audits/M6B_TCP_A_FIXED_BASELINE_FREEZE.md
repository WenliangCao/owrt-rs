# 逆向导入修复后的方案 A CPU 门：新 common 准备计划

状态：本地只读准备，未访问Oracle、未构建、未跑测试或窗口。A源码绑定的原语、隔离、服务、资源/生命周期及压力仍由root串行补齐；本计划不授予CPU启动资格。现有45窗工具、数值预算及[M6b协议](../M6B_PROTOCOL.md)不改。

## 对照基线和窗口范围

既存逆向导入缺陷已分别修进无A和A；旧70097c66的27窗保留为历史，不再新增27窗。新的45窗用同一修复后的无A/A和新执行的镜像C：

| 组 | 产品源码 | feature-off opt3 ELF SHA256 | 字节 |
| --- | --- | --- | ---: |
| C | 精确镜像C | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` | 使用原镜像对象 |
| R3_new | `1bd9436c1f87b17f9be1c127247f9c08336dc09c` | `30141ffe4d75a7a2692999fdad15c9f9f279223d77255cdbe96ea9fde3e8cdae` | 1,949,736 |
| A | `ae1cdba6bd03cf4e28b566c31f610a31020824de` | `e29007279f74165ffd08afc1d590fe6974db4be0624aa0bfe69aecdc5e827695` | 1,962,024 |

无A/A的build receipt分别绑定 `/home/ubuntu/dnsmasq-m6b-20261007/pair-reverse-fixed-02/{noa,a}/source`。不能为准备common把ELF随意移到新source_root后改写receipt；复用现有source、receipt和ELF即可。A对无A的产品体积增量12,288B（0.63%），不先假定CPU收益。

TCP三个profile为local、cache、miss，全部C/R3_new/A各5轮，共45窗口；每个窗口含fresh pilot、完整正式steady/saturation和采样。轮次顺序沿用C→R3_new→A、R3_new→A→C、A→C→R3_new、C→A→R3_new、A→R3_new→C。各轮内依次local/cache/miss，profile内三组交错，不用历史27窗替代新C/R3_new五轮。

## 为什么必须重新prepare common

`m6a_suite.py prepare`明确要求r3为opt3、rs为opt-s，两者build.source等于同一product_freeze.source_root、产品逐文件hash相同；build flags除link-map路径外一致。`suite.verify`又核验所有组ELF、两份build和工具树。`m6b_tcp_cpu_gate.freeze`要求R3_new源码和ELF等于common基线，再独立绑定A。因此旧70097 common不能仅手改r3/source_commit后复用；也不能把旧70097的s留在新common的rs槽、给A伪装rs或用opt3别名充s。

沿用现有工具的最小规范做法：**构建一次无A1bd9436c同源feature-off opt-s，只供common未测槽**，在新的root重新调用prepare；45窗schedule没有Rs，适配器不会执行它。本次没有“新s性能结论”，该中间s构建不替代最终含A同源opt3/s的135窗。这样无需修改通用工具或增加测量范围。最终135窗仍只在所有修复合入后的最终候选执行一次。

旧common的原生C源码 `m6a_loadgen.c`/`m6a_upstream.c` 与当前源码SHA相同；m6a_suite/window/analyze和CPU gate/run七项主要工具亦相同。但旧tools完整map还冻结了其他全部工具，不能通过只保留这七项绕过其他变化。新prepare会用同一flags重新编译两原生helper并记录编译器、ELF SHA、kernel、四核affinity；正式窗口不进行helper构建。

## 先准备资产，不提前填前置通过

root可在串行构建阶段准备下面资产。所有输出用fresh文件/目录，不覆写旧common/state，source-bound原语和companion准备完成也不等实际通过。

1. 两份产品source freeze，包含实际完整40位commit、现有build.source对应root、全部产品输入SHA以及各自opt3 ELF SHA。输入必须从各自精确Git快照得到；源码未变但新增测试文件也不能从70097复制文件列表。本地Git树当前无A两个组件157文件、A158文件，实际freeze还应包含存在的根`.cargo`及Cargo/toolchain输入，不能把这个文件数当固定合同。
2. 新无A同源s：通过统一`oracle_build.sh`，共享 `/home/ubuntu/dnsmasq-cargo-target`，`ORACLE_BUILD_OPT_LEVEL=s`、`ORACLE_BUILD_FEATURES=''`、其余flags保持；实际构建后记录SHA/size/receipt。它只补合法common rs槽，不执行窗口。
3. 将当前工具和协议冻结到fresh common root，建议 `/home/ubuntu/dnsmasq-m6b-20261007/cpu-a-reverse-fixed-01`。工具快照应含gate/run、suite/window/analyze、PID清理和archive watcher，逐文件SHA；后续不能在common目录改文档/工具。原产品源码树仍留在pair目录，不能把diag原语/companion源放进产品source_files。
4. 由root核对前置实际证据后，生成same-A source/ELF资格汇总。必需键恰为 `primitive`、`view-isolation`、`service`、`resource-lifecycle`、`pressure`、`small-cache-150`、`empty-cache`、S1–S8共15项；每项来自实际报告/receipt并附evidence path/SHA。内部余额10批、150s pin/churn和0/1/5/15/60资源证据通过后归入对应资源/压力汇总；诊断ELF用自己的SHA，报告须另外绑定产品A SHA，不冒充产品ELF。

缺任一实际门，就保持准备状态，不生成假的`passed=true`，不调用CPU plan/run。旧d8的门不能充ae1源码资格；新修复共同镜像8配对通过也不能替代A全部S1–S8与资源门。

## Source freeze生成与现场验证

source freeze不是性能结果。建议由本地精确Git导出得到expected输入SHA，再上传private；Oracle原目录逐文件一致才允许prepare/plan使用。下面为生成计划示意，尚未执行；`ROOT`参数必须取现有build receipt的source值，不能取common root。

```python
import hashlib, json, subprocess
from pathlib import Path

def write_source_freeze(commit, source_root, elf_sha256, without_a, output):
    entries = subprocess.check_output([
        "git", "ls-tree", "-r", "--name-only", commit,
        "components/dnsmasq", "components/ubus", ".cargo",
        "Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
    ], text=True).splitlines()
    source_files = {}
    for name in entries:
        payload = subprocess.check_output(["git", "show", commit + ":" + name])
        source_files[name] = hashlib.sha256(payload).hexdigest()
    freeze = {"source_commit": commit, "source_root": source_root,
              "source_files": source_files, "elf_sha256": elf_sha256,
              "without_tcp_scheme_a": without_a}
    with Path(output).open("x") as stream:
        json.dump(freeze, stream, indent=2, sort_keys=True)
        stream.write("\n")
```

source快照中的上述编译输入必须是普通文件，遇symlink/submodule先按精确Git对象核查，不能把symlink目标/子模块OID当源文件内容。`suite.prepare`现场核对无A所有freeze.source_files；`gate.rust_binding`现场分别核对两组source_files、ELF、receipt、feature/opt-level，并允许源码remap/私有map路径差异。源冻结文件本身随后以实际SHA引用。

无A同源s构建计划（root串行执行，正式窗口开始前完成）：

```sh
CPU45_PAIR=/home/ubuntu/dnsmasq-m6b-20261007/pair-reverse-fixed-02
ORACLE_BUILD_OPT_LEVEL=s ORACLE_BUILD_FEATURES='' ORACLE_BUILD_LINK_MAP=1 \
  sh "$CPU45_PAIR/noa/source/tools/dnsmasq/oracle_build.sh" \
  "$CPU45_PAIR/noa/source" "$CPU45_PAIR/noa/private/opts-cpu-common-01" release \
  </dev/null
```

新common prepare计划：

```sh
CPU45_ROOT=/home/ubuntu/dnsmasq-m6b-20261007/cpu-a-reverse-fixed-01
CPU45_PAIR=/home/ubuntu/dnsmasq-m6b-20261007/pair-reverse-fixed-02
python3 "$CPU45_ROOT/tools/dnsmasq/m6a_suite.py" prepare --m6b \
  --root "$CPU45_ROOT" \
  --source-commit 1bd9436c1f87b17f9be1c127247f9c08336dc09c \
  --r3 "$CPU45_PAIR/noa/private/opt3/dnsmasq-rs" \
  --r3-build "$CPU45_PAIR/noa/private/opt3/build.json" \
  --rs "$CPU45_PAIR/noa/private/opts-cpu-common-01/dnsmasq-rs" \
  --rs-build "$CPU45_PAIR/noa/private/opts-cpu-common-01/build.json" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --product-freeze "$CPU45_ROOT/private/noa-source-freeze.json"
```

prepare默认产生全9profile common及135-window空state，这是共同工具的配置载体；**不要运行m6a_suite run**。45窗适配器会先原字节保留empty common state为`common-state-before-cpu.json`并记录SHA，再转换为45窗state；有任何旧windows/events的状态会拒绝，不能清空伪装fresh。

## 输入绑定和冻结执行门

在全部实际前置门过后，用真实文件SHA产生 `CPU45_ROOT/private/inputs.json`，其schema沿用[CPU门接口](M6B_TCP_A_CPU_GATE.md#输入与输出接口)。common_manifest引用新manifest；R3_new引用新无Asource freeze、现有noa opt3 receipt及SHA30141ffe…；A引用新A source freeze、现有a opt3 receipt及SHAe2900727…；prerequisites引用same-A资格汇总。不预填s的SHA或prerequisites真值。

只冻结计划的命令：

```sh
python3 "$CPU45_ROOT/tools/dnsmasq/m6b_tcp_cpu_gate.py" plan \
  --inputs "$CPU45_ROOT/private/inputs.json" \
  --output-root "$CPU45_ROOT/private" \
  --output "$CPU45_ROOT/private/plan.json"
```

root核验plan完整45行、三组各15行、五轮真实顺序、每行SHA/source、全部fresh pilot/formal argv后才启动适配器；计划JSON不可覆盖。正式窗口daemon/C子进程CPU0、upstream CPU1、native generator CPU2、controller CPU3，互不重叠；两原生helper不使用QEMU。root持唯一共享构建锁，Oracle禁其他build/test/fuzz/perf/strace，代理只本地读码/报告。archive watcher逐窗口完整本地SHA/metadata核验后才prune并开启下一窗，全部失败/取消尝试保留。

## 不变的判定合同

完整说明沿用[CPU门预算](M6B_TCP_A_CPU_GATE.md#事前预算与结果解释)。每个TCP profile分别对steady/saturation五轮中位数要求A CPU/正确请求≤1.05×新R3_new且严格低于本次C；QPS≥0.95×R3_new，p95≤1.05×R3_new；A错误/FD漏为零。CPU以daemon cgroup usage_usec/正确完成请求，C子进程只计一次。W、4/5方向、收益/回退幅度、generator-limited分类均不改。

每窗正式60秒idle CPU、30秒预热、120秒负载（前90秒steady/末30秒saturation）、完整正确回答和wire抽查；Rust排空以client/view/pending归零或已证实完整空闲FD形状稳定，0/1/5/60秒采样。资源前置仍另有15秒样本与10批内部余额，CPU门不代替它们。

旧70097单轮CPU仅历史归因，预算比较使用这45窗中新执行的正确性修复后C/R3_new；不因共同修复改变5%门槛，不用M6a旧20µs作门，不拼某组最快尝试。A硬门失败保全证据并交用户决定，未过前不合main。通过后才能合A、冻结最终候选并跑最终135及统一功能/资源/APK验收。所有性能结论仅Oracle构建机，物理路由器未触碰。
