# FIX4：构建、启动与 hosts 独立复核

本轮审计冻结提交 `f93b6b269acb16f495b292ae7a1409c372db8b45`，main `be531cee49e366bb5044443d473944dbea45b87e`。相关代码静态复核与本轮 fresh 普通单测、最终 SDK 实际启动/hosts 对照未发现新增合并阻断。这里只给出本工作域结论；性能总体判定交由本轮三方数据，不能将以前 main-only 的退步结论直接带入。

## 身份、构建和运行时保护

- `local-input-identity.json` 将当前 Git、工作区的 178 项产品/配方/打包输入逐项绑定；没有差异。输入摘要 `aeab077f18f7ffbeed216372d9a27da8d6c291628e62bcc17017c46daf7f05a1`。
- `verify_and_test.py` 在 Oracle 重新计算 `/home/ubuntu/dnsmasq-fix4-repair-20261013/source-final` 的这 178 项 SHA；它们与当前 HEAD、两个最终 SDK manifest 的 `source_files` 和 `source_digest` 完全相同。SDK acquire/verify 的 ELF、APK、pre-strip ELF 和各 16 个 payload 文件全部现场重哈希匹配。两个 SDK 的 ELF/APK 逐字相同。本轮是核验保留的真正源码构建收据，不是又做两次 SDK build。
- 最终 SDK ELF：`55ea363f626f3e14279f280b1dba708a1d751877ab22a3503d312985c9efd6ca`，2,054,939 B；APK：`5853a61ed87ee94b75520f19fa356976d903068f5af7b54060e6aa85e4d4cedd`，1,117,789 B。保留的源码构建明确 `build_mode=compile-and-package`、`frozen_elf=false`、`source_build_passed=true`，原始预算仍按 `size-target` 失败，未把编译成功冒充完整替换验收通过。
- 从匹配当前 HEAD 的 `source-final` **fresh 编译并执行普通 test-profile 程序**：777 lib + 77 bin = **854 pass、0 fail、23 ignored 未运行**，每个 ELF 都在独立 network/mount/PID namespace 和 tmpfs `/tmp` 中串行执行。编译日志、执行 argv、程序 SHA、test summary 在 `result.json`。它与 SDK release ELF 身份分开，没有把 test-profile 当成发布程序的运行证据。
- 本地 Python 3.14 运行包工具 20 个测试全部通过，含 Make `BuildPackage eval` compiler lookup、固定 startup objects 改写、异常 linker 参数、PIE/linkage/RELRO gate、recipe 恢复和包依赖/lifecycle metadata。见 `package-tests.json`。这些是工具测试，不是实际 OpenWrt procd/APK 部署。
- 对**最终 SDK ELF** 与**精确镜像 C**各 fresh 启动 3 次，实际 `/proc/PID/exe` SHA 正确；双方 UDP/TCP A 响应相同、正常退出。SDK 的全部 11 页 GNU_RELRO 为 `r--p`；3 次 ASLR 基址不同；无 WX 映射、stack 无 execute 位。精确 C ELF SHA `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。完整结果见 `relro.json`。

独立源码检查：`packaging/openwrt/owrt-dnsmasq/Makefile:85` 用 backtick 保留 compiler 查找直到 shell 执行；wrapper `static-pie-linker.py:9–35` 验证实际 compiler、固定 aarch64 musl self-contained startup 对象集合和替换存在性，拒绝重复 static、已有 PIE/shared 标志和 response file，继而换用 rcrt1/crtbeginS/crtendS。`startup_relro.rs:52–103` 在重定位与 constructors 完成后查 ELF 自身 RELRO，验证页大小/地址溢出/末页边界，mprotect 失败导致 `main.rs:203–205` 明确退出 5。当前固定工具链和 4 KiB 页环境没有发现构建或启动错误；不能由此声称未来工具链/其他页大小也获支持。

## hosts 修复与失败边界

`hosts.json` 是本轮重新运行 `tools/dnsmasq/audit_fix_20261011_hosts.py` 的最终 SDK/精确 C 对照，8/8 通过，另语法检查控制一致。覆盖普通/debug 模式、100,000 字节 token 和 comment、VT/FF/CR/NUL、多个非法名称/地址的日志优先级与行号、addn-hosts 目录、启动 DHCP 权威名称、SIGHUP 后新名称发布，以及保留名字的 UDP/TCP 回答。不是只检查存活或 RCODE。

源码依据：`hosts.rs:296–318` 的 8 KiB 输入 buffer 和 `hosts.rs:328–329` 的 502 B token 代替整文件读入/整行暂存；token 截断、NUL 前缀和 EOF/read-error 完成逻辑符合匹配 `cache.c:1390–1544` 的 gettok/read_hostsfile。普通 hosts 的错误和完成通知经 `main.rs:6785–6806` 流式发给 logger。hostsdir 仍保留待发布记录及逐坏行计数，不能据此宣称所有大文件路径都固定内存，但这不是本分支新引入的数据结构。

`main.rs:3184–3197` 在同步 reload 内释放旧 local/daemon hosts，再构建、同步发布新索引；该同步调用期间不会进入 DNS 收包。最终新 hosts 触发 lease-name rebuild，动态租约单独保留。普通 hosts 现在在降权之后的 EVENT_INIT 打开，符合 C：原来 main 可读而 C 不可读的 root-only hosts 权限情形是 C 对齐，不能列成此次功能回归。

启动 DHCP/helper 的 gate 覆盖 `files_initializing` 与初始 hostsdir bulk (`main.rs:3337–3353`)，普通 hosts 完成后还会执行 `hosts_changed` (`main.rs:3569–3584`)。相关普通单测通过，包括 `main_hostsdir_init_tests.rs`；本工作域未重复完整 DHCP/恢复 helper 族，详见同轮 DHCP 审计。

configured hosts 仍在 `main.rs:884` 先构建，EVENT_INIT `main.rs:3571` 再经 `read_hosts_with_notices` 构建一次；这是本分支相对 main 新增的冗余工作，清除旧索引只解决同时驻留峰值，不消除第二次构建。**本页不据源码或旧 main-only 数据认定性能回退**，应使用本轮 performance 目录的 C/main/final SDK 三方启动数据判断影响。

## 已有范围问题和限制

原 ELF 1,000,000 B / APK 700,000 B 预算在 main 就失败，当前仍失败；是完整替换资格的既有障碍，不作为此次合并新增阻断。最终 SDK 准确大小如上；本工作域不重新定义预算。

本轮未 fresh 重编 SDK、未验证跨构建路径/跨宿主可重复性、未运行 23 个 ignored 测试、未做 allocator fault/内存耗尽、mprotect fault 注入、其他页大小、长期 soak、Cortex-A53 性能、真实 APK solver/procd/ujail/UCI 服务生命周期或物理路由器。旧 SDK 日志中的 host wrappers 和 source-build 收据仅按所声明输入范围复核，不能等价于 canonical x86_64 SDK 全链重建。

## 复现

新建 Oracle private 输出目录；不覆盖已有证据。`verify_and_test.py` 的 `R` 应改到该目录，并把同目录 `local-input-identity.json` 放到它读取的位置，再运行驱动。它会验证身份、fresh 编译 test-profile，并串行执行 lib/bin 普通测试。

最终 SDK 运行探针：

```sh
S=/home/ubuntu/dnsmasq-fix4-repair-20261013/source-final
E=/home/ubuntu/dnsmasq-fix4-repair-20261013/private/sdk-verify-final/payload/usr/sbin/dnsmasq
I=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
# OUT 须是新的审计私有目录
sudo -n sh "$S/tools/dnsmasq/run_isolated.sh" python3 \
  "$S/docs/dnsmasq/audits/20261011/independent/build_protections_probe.py" \
  "$S" "$E" "$OUT/relro" --image-root "$I" --require-relro
sudo -n sh "$S/tools/dnsmasq/run_isolated.sh" python3 \
  "$S/tools/dnsmasq/audit_fix_20261011_hosts.py" \
  --image-root "$I" --rust "$E" --out "$OUT/hosts"
```

原始日志、映射与 rootfs overlay 留在 `/home/ubuntu/dnsmasq-audit-fix4-20261014-build/private/`，Git 只保留工具和派生结果。
