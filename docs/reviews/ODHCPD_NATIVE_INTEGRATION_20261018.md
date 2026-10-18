# odhcpd 下一版本原生集成准备

**当前保留为候选，不刷机、不发布、不合并主线。** 用户要求新组件完成一次独立
审计并处理结论后再继续；离线资格允许完成，不能据此绕过该暂停边界。

真实客户端短时 trial 连续 124.99 秒通过并恢复 C 后，默认配方已提升为
**v0.2.4**（package `0.2.4-r1`，`native-eleven`），作为用户所说“下一版本”的
patch 后继。正式 CI `39111043955` 从 `4acf1c80` 构建；其最终镜像资格结果另记，
不把组件试运行当作完整固件已经刷写或发布。

[默认配方](../../packaging/image/native-25.12.5.json) 从 v0.2.3 复制，
仅改变版本并添加 `/usr/sbin/odhcpd`。其余十个 ELF、dnsmasq 212 文件冻结构建
输入和既有 PGO 使用配方均未改变；不训练 odhcpd PGO。

| 对象 | SHA-256 |
|---|---|
| 资格测试的 SDK odhcpd-rs | `79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55` |
| 精确 stock odhcpd | `53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82` |

APK 原 owner 是 `odhcpd-ipv6only`。集成只替换 ELF，保留原 `/etc/init.d/odhcpd`、
`/usr/sbin/odhcpd-update`、`/etc/uci-defaults/15_odhcpd` 和启动链接。原 ELF 保存到
`/usr/libexec/owrt-stock/usr/sbin/odhcpd`。integration files 仍仅为已验收的
dnsmasq init/ACL 两项，总恢复集合为 11+2=13。

`native_image.native_layout()` 只接受固定十组件或加 odhcpd 的固定十一组件，
同时验证每个名字、标准路径、binary 名和 stock owner，不按数量宽泛放行。
manifest 分别使用 `native-ten`、`native-eleven`；原十组件历史继续可审计。
`owrt-recover-c` 要求旧十二路径完整存在；十三行时还必须包含 odhcpd，拒绝
把 odhcpd 混入缺一条旧路径的十二行集合、重复项和未知项。先验证整组再替换。

正式 workflow 和 `make ci-image` 已启用 core odhcpd 构建；手动阶段命令为：

```sh
OWRT_CORE_INCLUDE_ODHCPD=1 sh tools/ci_build_core.sh WORKDIR
sh tools/ci_integrate_image.sh WORKDIR
```

APK 原包重装夹具使用默认 spec，或显式传入
`native_apk_fixtures.py --spec packaging/image/native-25.12.5.json`，
增加精确 odhcpd 原包 payload；所有重装/恢复检查随 manifest 严格接受 10/11。

Oracle `/home/ubuntu/odhcpd-native-eleven-20261018` 运行 `test_native_image.py`，
17 项测试通过；恢复 shell 额外在临时合成路径实际执行六种集合，验证两种合法
集合恢复成功、四种缺失/替代/重复/未知集合在替换前失败。shell 语法检查通过。
首次测试副本缺 `.git` 导致唯一冻结源码清洁度检查无法执行；补上独立 Git 索引
后重跑通过，未放宽源码哈希或跳过该检查。没有构建 Rust 或最终 APK/镜像。

full-image 准备、handoff、boot 和 client-health 工具现已支持严格的 10/11
边界；提升默认时移除了临时 spec，保留构造的历史十组件恢复测试。默认配方提升
后的 image/core/deploy/backup 共 46 项工具测试通过，未新增性能样本。
