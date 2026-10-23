# 业务 unsafe 边界返工（2026-10-23）

状态：返工、独立安全复核、oracle完整门禁与必要差分已完成。基线为 `d6719f66`，
产品及工具修复提交至 `2d88241c`；构建身份以验证记录中的文件SHA为准。

2026-10-22 审查将七个业务入口的 `forbid(unsafe_code)` 降为 `deny`，并通过
局部 `expect` 传播 unsafe 契约。虽然补充了前提条件，这仍违反了项目自v0.2.2
保留的业务边界；之前的审查账本不能证明这一做法正确。本次恢复 dnsmasq
lib/bin、fw4、procd、reload-config、rpcd、ubusd 七个入口的 `forbid`，这些
组件的 `src/` 不再包含 unsafe block/function/impl/extern，也没有局部豁免。

## 安全边界

- 信号处理函数、原子状态和self-pipe由platform持有。reload-config、rpcd、
  ubusd只调用固定操作，不能注册任意函数或传入任意唤醒FD。管道两端保留到
  进程退出/exec，避免在途handler写到已被复用的FD。
- `ProcessOwner`不能跨线程传递。获取时核验一次；每次敏感调用仍先屏蔽信号，
  通过Linux `unshare(CLONE_VM)`验证当前地址空间、信号状态未被其他线程共享。
  它在独占状态下不改变namespace或FD表，在共享状态下拒绝。
  [Linux 6.12实现](https://github.com/torvalds/linux/blob/v6.12/kernel/fork.c)
  的`check_unshare_flags`是此判断的依据；没有把`/proc`计数或历史凭证当永久证明。
- 环境变量参数先转换成具体字节串，平台临界区内只执行固定setenv/unsetenv。
  fork还需要独立的资源和处理函数契约：DNS使用不可伪造的typed worker凭证，
  procd使用固定的进程操作对象。只有`platform/`启动适配器能通过unsafe构造
  登记已审过的函数和纯数据输入；业务代码无法临时指定新的fork处理函数。
- procd的Command在平台中完成配置和spawn，带有post-fork hook的Command不能
  逃回业务调用方。子进程在exec前恢复父线程原信号mask；父线程退出临界区时
  也恢复。内核拒绝检查时返回错误，不降级到未经证明的操作。
- DNS worker关闭继承FD前忘记旧panic hook，安装固定终止策略；禁止从正在panic
  的线程重入fork。继续运行的后台daemon保留原hook。原始进程帧和未拥有的资源
  不会从worker返回或析构。atfork、共享映射和固定函数调用链仍是平台启动
  适配器明确承担的审查契约，不冒称线程检查能证明所有fork条件。
- WDTFD只在procd平台入口、任何业务FD创建前接收；后续业务获得OwnedFd。
  保留原描述符，不复制以免影响watchdog最后一次关闭。固定Rust 1.98.1启动
  [实现](https://github.com/rust-lang/rust/blob/1.98.1/library/std/src/sys/pal/unix/mod.rs)
  在这一入口之前只整理标准流、信号、栈和参数，没有持有额外的Rust FD所有者；
  升级运行时必须重新核对这个前提。

不改成额外exec worker，不复制协议算法，不取消现有fork/COW流程。
procd业务代码仍在原`src/main.rs`，作为`forbid`库由很小的平台bin调用；DNS
保留原`forbid`库，bin平台入口包含另一个明确`forbid`的daemon模块。没有通过
放宽库根再嵌套业务模块的方式绕过crate级禁止。

## 明确的边界与兼容性

正常preinit传递的WDTFD（>=3）语义不变。0/1/2现在返回EBADF并清理环境变量，
不会接管或关闭标准流；这是无效handover输入的安全收紧。F_GETFD只能证明
描述符有效，不能证明它没有Rust所有者，所以不能为复刻异常C行为关闭标准流。

新增内核检查无`/proc`依赖，可在降权后执行；外部seccomp若禁止unshare则会
明确拒绝敏感操作。必须核对目标镜像的实际ujail/策略输入；主机测试不能证明
任意外部沙箱策略。未修改物理路由器或发行基线。

已核对精确25.12.6镜像的dnsmasq init与procd shell，以及匹配revision的
instance/ujail实现：默认dnsmasq jail没有注入seccomp策略。实际无`/proc`、
UID453及原有能力限制下，helper和运行期hostname worker两项边界验证通过。
此结果不扩大为对任意自定义seccomp策略的兼容保证。

## 回归门禁

新增负控制验证：凭证创建后再启动线程时拒绝环境修改/worker启动、线程退出
后重新验证成功；未登记worker拒绝；父子信号mask恢复；worker不调用/析构旧
panic hook；满信号管道仍不阻塞且保留errno；WDTFD低值不会关闭标准流。

长期门禁在编译前检查业务根必须包含无条件`forbid(unsafe_code)`，拒绝降成
`deny`或只在test启用。编译器继续禁止子模块豁免；DNS嵌套bin的ignored测试
按实际完整名称运行，procd显式lib路径仍包含doctest门禁。

最终验证命令、输入SHA、结果和逐文件增量审查见本次JSON记录。全部Rust
构建、测试与Clippy只在oracle通过`mbx`执行。先前失败日志保留，不把旧产物
测试或零测试输出计作新实现通过。

| 验证 | 最终结果 |
| --- | --- |
| 主crate门禁 | 14个crate默认/适用all-features、all-targets、doctest、普通examples和Clippy `-Dwarnings`通过；15个crate及fuzz格式通过。 |
| feature/fuzz/工具 | DNS两个单feature与5个fuzz目标编译通过；完整benchmark门禁和Python工具harness通过；新增11项门禁测试及27项打包测试通过。 |
| rpcd/ubusd/reload-config | 真实main信号烟测10项通过；rpcd官方镜像68项及15项故障恢复通过；ubusd37行一致、44项检查通过。 |
| procd/fw4 | procd官方镜像bundle两侧16项检查通过；fw4官方31项通过；process fixtures含动态线程拒绝、exec mask与watchdog最后关闭。 |
| DNS实际进程 | 全部18项namespace测试、25项独立process fixtures；官方镜像配置157案例、lease-init6场景、后台daemon4场景、无proc/降权2场景通过。 |
| DNS独立C primitive | 四个driver共1881观测，1877匹配C；4项既有lease差异保留，全部269条lease输出与原Rust基线一致。 |
| 打包入口 | inputs→230文件快照→213文件最小包树→锁定主程序编译通过；平台入口、注册器和测试适配器缺失会被拒绝，旧PGO pins未更新且仍拒绝新源码。 |

[最终门禁](PLATFORM_BOUNDARY_VALIDATION_20261023.json)绑定115份日志；
[49文件增量审查](PLATFORM_BOUNDARY_REVIEW_20261023.json)区分新文件全文阅读和
既有全文基线加完整补丁复核，不重复声称未改文件又被全文阅读。
细节分别见[进程凭证](RUST_PROCESS_OWNER_BOUNDARY_20261023.json)、
[固定信号](PLATFORM_SIGNAL_BOUNDARY_20261023.json)、
[procd/fw4](PROCD_FW4_PLATFORM_BOUNDARY_20261023.json)、
[DNS](RUST_DNS_PLATFORM_BOUNDARY_20261023.json)、
[包装入口](PLATFORM_PACKAGE_ENTRY_20261023.json)及
[单feature组合](PLATFORM_DNS_FEATURES_20261023.json)。

最终Rust文件与锁文件在统一门禁前后逐字节一致。之后仅给Makefile的harness
列表加入打包测试并重跑工具门禁。文件同步目录最初缺少Git历史，使依赖
`git show`的合成发布测试失败；补齐实际仓库bundle后通过，没有放宽断言。
这是测试环境失败，原日志与首次不完整修复均保留。
