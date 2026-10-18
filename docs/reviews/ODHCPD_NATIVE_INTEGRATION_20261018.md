# odhcpd 下一版本原生集成准备

新增可显式选择的 `native-eleven` 配方，默认发布配方仍为 v0.2.3。
下一 patch 暂定 **v0.2.4**（package `0.2.4-r1`），是对“下一版本”的合理后继推定；
只有短时 trial 通过后由主线程提升默认配方。这份改动未生成镜像、发布、刷机或
修改现网，也不替代 trial、恢复门和客户端健康验收。

[候选配方](../../packaging/image/native-25.12.5-odhcpd.json) 从当前 v0.2.3 复制，
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

显式选择仍需已有 core opt-in，后续构建模板为：

```sh
OWRT_CORE_INCLUDE_ODHCPD=1 sh tools/ci_build_core.sh WORKDIR
OWRT_NATIVE_SPEC="$PWD/packaging/image/native-25.12.5-odhcpd.json" \
  sh tools/ci_integrate_image.sh WORKDIR
```

这只是启用说明，本任务没有执行这些命令。APK 原包重装夹具使用
`native_apk_fixtures.py --spec packaging/image/native-25.12.5-odhcpd.json`，
增加精确 odhcpd 原包 payload；所有重装/恢复检查随 manifest 严格接受 10/11。

Oracle `/home/ubuntu/odhcpd-native-eleven-20261018` 运行 `test_native_image.py`，
17 项测试通过；恢复 shell 额外在临时合成路径实际执行六种集合，验证两种合法
集合恢复成功、四种缺失/替代/重复/未知集合在替换前失败。shell 语法检查通过。
首次测试副本缺 `.git` 导致唯一冻结源码清洁度检查无法执行；补上独立 Git 索引
后重跑通过，未放宽源码哈希或跳过该检查。没有构建 Rust 或最终 APK/镜像。

主线程另行更新 full-image 准备、handoff、boot 和 client-health 工具的 10/11
边界；此变更不触碰部署 driver。trial 通过提升默认配方时，需同步调整
`test_next_recipe_is_explicit_and_preserves_the_accepted_ten` 的预发布断言，并可
移除临时 spec，避免维护两份相同默认配置。
