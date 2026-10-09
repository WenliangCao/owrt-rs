# M6b A CPU45 与最终冻结交接（2026-10-09）

A 的产品改动已合入 main `f2a59167`，采用候选 `7d3dc4d9c270d76ce73ad0cd1b805a6737af6da1` 的精确八个产品路径。暂存及提交后均逐 SHA 核对实际 165 项编译输入；整个组件与候选相同，共同 signal/route 十个函数正文保持原字节。原始资格继续绑定候选与实际 ELF，最终 main 的 source/build/ELF 冻结留下一新会话。

CPU45 完整执行 C/NoA/A 各三场景五轮，45 个正式窗口均使用第 1 次 attempt，全部 pilot、raw、PAX 归档与 SHA/metadata 本地证明保留。控制器与 watcher 均退出 0；收尾观察无本轮 CPU 进程。三组 warmup/measurement 的 wrong、timeout、transport_error 全为 0，FD/子进程与原方法检查通过。

## 合入判定与吞吐边界

用户明确以 CPU 预算作为合入门：`u_A <= 1.05*u_R3_new` 且 `u_A < u_C`。六个场景/阶段全部通过，既有 QPS/p95 数值检查也全部通过。NoA 为同源 `cd9edcf7727faa199f225587ea76eb283c52b15f`，fresh common 与原 8ae8b834 工具、时长、种子、顺序、亲和性和阈值保持一致。

原冻结分析器因生成器单核占用达到 90% 将两个饱和吞吐项标为 restricted，原结果仍是 `qualification=unproven`、`passed=false`，没有改写。用户接受受限吞吐作为 A 的下限：下限已高于实测 NoA 与 C，吞吐未退步成立；真实上限未测。local 有四个 A 饱和窗口受限，cache 有五个。不得从第五轮 local 的未受限结果中挑选较好 attempt，也不把受限测量写成吞吐提升倍数。

单位为每次正确回复的 CPU 微秒；每格是五轮中位数。

| 场景 | 阶段 | C | NoA / R3_new | A | A/NoA | 两条 CPU 门 |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| tcp-local | steady | 28.607856 | 25.915557 | 23.793537 | 0.918118 | 通过 |
| tcp-local | saturation | 26.649709 | 13.642285 | 11.718476 | 0.858982 | 通过 |
| tcp-cache | steady | 34.019234 | 31.709652 | 19.961889 | 0.629521 | 通过 |
| tcp-cache | saturation | 31.662140 | 20.420704 | 8.279532 | 0.405448 | 通过 |
| tcp-miss | steady | 229.165775 | 117.486832 | 97.541426 | 0.830233 | 通过 |
| tcp-miss | saturation | 218.213324 | 109.781146 | 82.493255 | 0.751434 | 通过 |

QPS 同样取五轮中位数；受限值只表示下限。

| 场景 | 阶段 | C QPS | NoA QPS | A QPS |
| --- | --- | ---: | ---: | ---: |
| tcp-local | steady | 9996.26 | 9997.32 | 9997.11 |
| tcp-local | saturation | 37419.77 | 73216.67 | ≥85207.87（生成器受限，真实上限未测） |
| tcp-cache | steady | 9995.49 | 9973.39 | 9997.48 |
| tcp-cache | saturation | 31494.03 | 48901.40 | ≥120566.37（生成器受限，真实上限未测） |
| tcp-miss | steady | 4357.72 | 8292.46 | 9968.42 |
| tcp-miss | saturation | 4577.87 | 9091.60 | 12087.87 |

两个原样确认窗口由用户取消：仅在本地准备了私有草稿与空闲检查，没有上传、prepare 或执行窗口。原 45 窗口的 plan/state/选择与分析保持不变。接受判定单独保存在 `E/M6B/cpu-a-7d3-01/adoption-decision-01.json`，不冒充原工具绿色资格。

## 内存与延期第 4 包

TCP 未命中内存仍为 C 的约 3 倍：交接尺度约 **18.6 MB 对 5.7 MB**，约 3.3 倍。本轮 steady 树 PSS 峰值的五轮中位数为 A 18,580 KiB、C 5,617 KiB、NoA 33,592 KiB；精确口径和逐轮数值保留于 raw/分析。该残余内存成本列入**延期第 4 包**，本轮没有继续调整产品或内存门。

租约导入只修 owner 当前 local 记录与 importer 的边界，沿用 C 的同址丢弃/异址事务失败规则；reload 与 hosts 两条发布链也经过同边界审查及生产 caller 单测。15 个精准 Linux 测试、feature-off 租约 C 差分、受影响服务/原语和 fresh 资源 26–36 均已实际通过，未出现新产品错答。资源资格由六项交错、四项 S8、一项 pressure 通过段覆盖；失败整控制器、旧十批红、旧 A79e 错答和原 strict reverse 四行差异均保持原判定。详细实际资产见 [checkpoint](M6B_A_79E_CHECKPOINT.md)。

## 冻结身份与证据入口

`E = private/dnsmasq-rewrite/evidence`。本地 CPU 根 `E/M6B/cpu-a-7d3-01`；Oracle 根 `/home/ubuntu/dnsmasq-m6b-20261009/cpu-a-7d3-01`。

| 对象 | SHA256 / 身份 |
| --- | --- |
| A feature-off opt3，1,962,024 B | `7707909285e3d4bbd30bdbc69e14ac1366b0729ba6ece88ee19f1037902e3f3c` |
| NoA feature-off opt3，1,957,928 B | `c0886bb0cfcc03f0f5afb678a9bfbaaaea25aefc065cc0e3ceb8de52363de85e` |
| 镜像 C ELF | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| CPU45 plan | `071f9b425ed05a23db0f349c72d6a25fe59e146e1ebbc92ab4dd8be2e0d01acc` |
| fresh common manifest | `3099d469944ed8f37aa1b5129565d19db7b1e7902b09a6d6fe902116720f874e` |
| published 十五门收据 | `ce2f66902493ae936739952b12d0f83d76c1242f0dc3c179a2114f0ae99dc045` |
| 最终 state | `98c24813056a8114de7c2b2128274f8565a3156810b1e9d7194482093f94ba3a` |
| 原 CPU45 离线分析 | `af86f5f449c1169966b2e14219a2958d78585696f0f004d91c630cce32330a37` |
| 提交后 165 输入/十正文核对 | `2c2d9624d09a14485011bf0dea517ecb1f85186c28ca2a06db18af43ec26d86f` |
| 45 归档总索引（总 tar 1,698,394,773 B） | `25216c7fcf38eb00f670fe2e64df640317e70255b77dea83cfadd7a9343a44f7` |
| 用户接受判定 | `0482125d31e3091d9e7d082ed4e6bfe09abf4bff8263ebe74efb38251632df12` |
| Oracle 收尾观察 | `ea7991938c625ef0163274cd0beb648dc20790d9a87345ae539f3b0b1d29c031` |

完整窗口在 `archived-private/archives/<job>/attempt-1/{archive.tar.gz,manifest.json,local-verification.json,prune.json,plain}`。归档总索引与用户接受判定均有以下独立收尾收据。`final-controller-01` 保全 log/PID/exit，`final-native-01` 两个实际 native ELF 已与 common manifest/Oracle 收尾 SHA 逐一核对。远端按原工具清理大 raw，保留 JSON/log gate 文件；本地全部 raw 与元数据证明完整保留。

十五门派生收据保留旧实际运行身份、源等值证明与新受影响门的实际结果，未给旧证据换 ELF/源码标签。新产品全 private 和独立 pressure 的完整归档入口及 SHA 继续使用 checkpoint 所列两份完整资产。

## 下一新会话

从账本当前状态/工作规则、本 checkpoint 最末停点及报告末节恢复。以最终 main 新身份重新冻结 source/全编译输入、feature-off opt3 和同源 s 的实际 build/ELF/link map；完成最终 source-bound review 与既定统一验收。现有候选收据保留原身份。

正式 135 的配方入口为 `docs/dnsmasq/audits/M6B_FINAL_ACCEPTANCE_RECIPE.md` 的「正式135与guard的准备顺序」，工具为 `m6a_suite.py prepare --m6b`、`m6a_suite.py run` 与 `m6a_archive_watch.py`。使用最终 main 两个实际 ELF、独立 product-freeze 和 fresh root，完整九场景 × C/最终 opt3/同源 s × 五轮，不用本轮 45 替代。basis/caps、全族/M2、资源/压力、APK/lifecycle 等按既定最终配方收尾；最终冻结和 135 本轮未执行。

十五棵已交付树已由 archive tag 保全后退役；活跃 A/route 树、dirty counters 和用户 prompts 保留。物理路由器与用户服务未操作。本轮在交接提交后停止。
