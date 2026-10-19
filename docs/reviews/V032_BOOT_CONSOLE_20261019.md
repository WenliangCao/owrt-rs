# v0.3.2：追加串口日志级别

四轮独立离线构建均得到相同 FIT：
`903af7754872eb673062d041ce6e1f5358c2795cb46bb856874d34a83cc299d4`。
DTB 只增加 `switch@1f status=disabled` 和 `/chosen bootargs-append` 两项，
内核压缩负载逐字节不变。尚未部署，启动时间、串口空档、DSA/WAN 时间及
两次启动的 dmesg 完整性均待真机实测，不报告离线推算的启动收益。

## 精确内核行为

参考为 OpenWrt 25.12.5 `f5dae5ece4` 对应的 Linux 6.12.94 patched build tree，
位于 Oracle `/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/h1-3a/build/openwrt/`。

- `target/linux/generic/hack-6.12/920-device_tree_cmdline.patch` 和实际
  `drivers/of/fdt.c:1050` 使用 `strlcat(cmdline, p, ...)`，**不添加分隔空格**。
  因此属性值为 **`" loglevel=4"`**，包含一个前导空格。直接使用 `"loglevel=4"`
  会把它拼在已有末尾参数上，不能实现要求。未增加 bootargs-override，未修改
  U-Boot、原 bootargs、firmware/mtd/uart_en 或任何其他启动参数。
- `kernel/params.c:161` 的 `parse_args` 从左到右遍历参数；
  `init/main.c:786` 的 `do_early_param` 对每个匹配项调用处理函数，
  `init/main.c:246` 的 `loglevel` 每次有效解析都赋值 `console_loglevel`。
  所以 `loglevel=8 ... loglevel=4` 的后一个有效值生效，没有“首次出现后忽略”逻辑。
- 匹配 `.config` 的 `CONFIG_CMDLINE=""`，没有强制内核命令行替换；
  `CONFIG_CMDLINE_OVERRIDE=y` 只有存在对应 DT 属性时才起作用，本候选未设置该属性。
- console_loglevel 控制控制台输出，未更改内核 ring、日志生产或用户态过滤。

核对文件的 SHA256：

| 文件 | SHA256 |
|---|---|
| init/main.c | `4ba36f0a3ca9eab90ce632504cba6c2cd90f16fd2432f56a3e6620c696435338` |
| kernel/params.c | `e71d65adcd85a3b01e0aadfe697cb23aa91c5689f2b359d574f1e95ebb46e7d4` |
| drivers/of/fdt.c | `205fb923751146831cbcdb40a1a07058a4ae136375430fb485e728c6068b1f5b` |
| .config | `3a9cc7e085b362cb27c7414d3b4c77e13e8635c36c1a9467bf54c56508a983ba` |

## 离线红绿与身份门

`tools/check_ax3000t_fit.py` 提取并运行真实 CI Python 构建块，固定原 FIT/DTB/ITS
身份，每轮使用独立副本、不同输入 mtime 和外部 SOURCE_DATE_EPOCH。
原 DTB 四轮 `fdtget /chosen bootargs-append` 均返回 FDT_ERR_NOTFOUND；
修后四轮都精确返回带前导空格的属性值，switch disabled 也通过。
四轮输出 DTB 均为
`5ebbe0671eabe9b16f08573a6bc26192d7552e7447aadbc4c8a090c5b2ee1f3f`。

CI 对反编译 DTS 的严格差异检查从一条扩展为且仅为指定节点的两条插入；
最终镜像校验器从 pinned 原 DTB 重新执行这两条修改，再按完整字节比较。
每轮均拒绝去掉空格的元数据与替换 FIT 身份的反例，原 ImageBuilder 输入未改变。
原始结果和计划在 Oracle `/home/ubuntu/v032-loglevel-20261019/fit-4x/`。
该检查不能代替最终 release-image 两轮字节复现和精确镜像整套离线资格。

用户态 conloglevel 与 log_size 的一次性保配置迁移另行验证；最终设备验收须
在新镜像资格完成、用户明确同意后进行，回滚目标仍是 v0.3.1 `099db992…`。
