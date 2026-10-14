# b337 SDK 源码构建：保留的中间产物

2026-10-14。源码 `b337c8509e549398116a0a9c7929f38b7fe32148`，tag
`audit/dnsmasq-merge-b337c850-20261014`。**该源在构建期间因 F10 的源文件行边界
反例被后继冻结替代，不是最终候选，也没有转签任何 runtime 资格。**

在新的 `/dev/shm/full-merge-sdk-b337c850-20261014/` 中，659 个 Git archive 文件
逐项核对。真实匹配 SDK 的 prepare、Cargo 源码编译、正常 RSTRIP/sstrip 与 APK
包装均退出 0；没有 `OWRT_DNSMASQ_FROZEN_ELF`、没有复用旧 dnsmasq target。
SDK recipe 恢复，SDK 工具和源码前后相同。输入 digest：
`e380eca59fe2a67bf7918d0f368e220ae17e26c94760846d16dad26ac5129362`。

| 中间产物 | 字节 | SHA-256 |
| --- | ---: | --- |
| SDK `.pkgdir` 中 strip 前安装 ELF | 2,122,208 | `5e14950c7ae6776e95d231a6e572b3b20a678d69006e6b4a0b16405580ec9fa3` |
| APK 提取的 strip 后 ELF | 2,120,475 | `5a1dc3053f889c3657ef73d2d92c5c9b70162636e2c7ea4c97a8cd8e12750846` |
| dnsmasq-2.93-r4.apk | 1,151,608 | `e1396ffe181cd665c8546e8d1f49b902217416a9f1872c8ed1f3ab58bbb29c43` |

初始测量驱动在构建成功后试读 Cargo target 中的 strip 前 ELF；SDK 的
`CONFIG_AUTOREMOVE` 已正常删除它，因此原 `manifest.json` 记录 FileNotFoundError。
这个失败没有覆盖，也没有说成编译失败。随后只读核验 SDK `package-pack.mk`
明确保留的 `.pkgdir` 安装副本，并追加 `interim-audit.json`：该副本先复制到 ipkg，
才执行 RSTRIP，能直接提供真实 strip 输入。没有为了修正测量而重新编译。

原工具的 ELF≤1,000,000 B/APK≤700,000 B 数字门仍失败，完整大小和原因保留；
不在这里做最终预算接受决定。包内 init 与 ACL 均逐字匹配该冻结源码，文件所有权、
APK 元数据、ELF AArch64/static PIE/RELRO 等静态审核通过。未运行该包的生命周期、
DNS/DHCP、资源或总线验收。

[派生记录](sdk-interim-b337.json)。全部 source、源码/SDK 输入清单、真实命令与日志、
原失败 manifest、追加审核、APK 及两个 ELF 已回拷到持久主仓库
`private/final-sdk-b337c850-20261014/interim-evidence.tar.gz`，SHA-256
`0c45affb93b6b372cb412f0274fa5d3a435fcac40706e65b286dab03a6852145`，本机复算一致。
后继 b587 构建使用新源与输出目录，不能沿用本页二进制身份或资格。
