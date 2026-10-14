# FIX7：fresh 构建、身份和普通测试

冻结产品 HEAD 为 `02659da6f35fb60ccc916a28b8abf761bf51913c`；增量基线为 `137c2882381109daf3e011f77401cd79524a0221`；main 为 `be531cee49e366bb5044443d473944dbea45b87e`。本域没有发现新增构建、普通测试或启动保护阻断。F3 和其他 DNS 语义必须以同轮精确镜像 C 报文对照裁定，单测通过不能替代该对照。

## 冻结与身份

本次从 Git HEAD 生成完整 `git archive`，在新 Oracle `/home/ubuntu/dnsmasq-audit-fix7-20261014/source` 解包；本地尚未提交的提示文档没有进入归档。预检确认该 `source` 和 `private` 均不存在，再创建新目录，未覆盖旧证据。

`build_package.inputs()` 枚举的 178 项产品、依赖及配方输入，与 HEAD Git blob、本地工作区和 Oracle 冻结源码逐项一致，摘要为 **`6057e515c4baea04396d1a7529ff24dc4066d2576a26009ec2d1b25d82f5bf4f`**。保留 main 172 项、before 178 项分别匹配各自 Git；before 使用 FIX6 source，其产品输入逐项匹配本轮 `137c2882` 基线。收尾再次检查所有输入、实际 ELF、日志和工具身份，共核验 Oracle 583 个文件，并另外核验 148 个 C 参考源码文件。原有提示文档 SHA 全部保留。[冻结工具](prepare.py)、[当前输入](local-input-identity.json)、[保留输入](retained-input-identity.json)、[归档](archive.json)、[收尾重新核验](identity-after.json)

| 角色 | Oracle 实际 ELF SHA-256 | 字节 |
| --- | --- | ---: |
| 精确镜像 C，2.93-r1 / nodhcpv6 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` | 269,305 |
| 保留 main | `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863` | 1,970,216 |
| F3 修复前，FIX6 / `137c2882` 产品输入 | `a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66` | 2,056,672 |
| FIX7 fresh release | `e475163a4cd95d4146767d8a6f9d1c26097d80ef7b9bc88b4349b2da5ec233e9` | 2,056,672 |

匹配 OpenWrt patches 的 C 源码为 `/home/ubuntu/dnsmasq-rewrite-20260929/reference/dnsmasq-2.93`：148 文件全部匹配身份清单，recipe revision 为 `f0a60eee2fe051741c643ea6118718aae1ef17fb`，`src/rfc1035.c` SHA 为 `231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222`，身份清单 SHA 为 `62cec0e9dda0265cb9c4f6af27f7d23067aed967afab3c74e37370149a8326e9`。实际语义基准仍为精确镜像 ELF，没有用宿主重编 C 替代。[实际身份和测试收据](result.json)

## 本次新构建与验证

- Release 使用冻结源码自己的 `oracle_build.sh`，共享 `flock`、包级 clean、Cargo fresh build、锁内复制；Rust 1.98.1，AArch64 musl，opt3，feature-off，SDK linker，static PIE。实际产物为 `/home/ubuntu/dnsmasq-audit-fix7-20261014/private/release/dnsmasq-rs`。[构建 manifest](release-build.json)
- Test profile 同样 fresh 构建；两个 ELF 各自放入独立 network/mount/PID namespace，挂载私有 tmpfs `/tmp` 并使用独立 `TMPDIR`，串行运行。**780 lib + 77 bin = 857 pass，0 fail，23 ignored 未运行**。新增加的 owner 越界单测包含在本次 780 个 lib pass 中。实际 argv、测试 ELF SHA、日志 SHA 和测试总结均保留。[执行工具](verify_and_test.py)、[测试收据](result.json)
- 本地 **20 个包工具测试全部通过**；这验证现有冻结身份、recipe、static PIE wrapper 和 metadata 门限，不代表本次生成了 APK。[包工具测试](package-tests.json)
- 当前 release 和精确 C 各新启动 3 次，`/proc/PID/exe` SHA 均匹配。6 次 UDP/TCP 合成查询回答完全相同、进程退出 0。当前 11 页 RELRO 全只读，3 个 ASLR 基址不同，无 WX 映射，stack 为 `rw-p`。[运行保护收据](relro.json)

各驱动、构建脚本、隔离脚本、归档、实际 argv、编译日志、测试日志和保护探针原始产物均有 SHA，收尾读取 Oracle 实际文件重新验证；原始日志、ELF 和 rootfs overlay 留在 private。[调用与原始证据身份](invocations.json)、[收集工具](finalize.py)、[可重跑身份检查](verify_identity.py)

## 边界

本次完成的是 fresh SDK-linker Cargo release/test-profile 构建，**没有 fresh 完整 SDK prepare/strip/APK 打包**；没有声称生成包含 F3 修复的 APK。没有运行 23 个 ignored、长期 fuzz/soak、OOM/allocator/mprotect fault 或其他页大小验证；不同构建配置 ELF 大小不能单独证明体积回归。本域没有修改产品代码或 C 参考树，没有接触路由器，没有部署、合并或推送。
