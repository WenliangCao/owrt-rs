# 决策 0010：把 firewall4 生成器移植为 Rust `fw4`

> 日期：2026-09-02
> 状态：已定
> 阶段：阶段 4

## 背景

firewall4 是约 3400 行 ucode 加 800 行模板的一次性程序，把 UCI/ubus 输入渲染成 nftables 文本。
I0 判定它"只差一个差分测试"即可升级为 Rust 目标；上游自带 68 个用例是现成 oracle。

## 决策

1. **逐函数移植**，不重新设计：`components/fw4` 保持 fw4.uc 的解析顺序、警告文本与模板输出，目标是
   字节相同。JSON 解析、blobmsg 转换放进 `components/ubus`（从 httpd 迁入）供复用。
2. **输入读取**：UCI 文件用自写解析器直接读 `/etc/config/firewall` 与 helpers 文件（匿名段命名
   `@type[n]` 与 ucode cursor 一致）；ubus 用 `components/ubus` 调用；`nft -j` 通过子进程。
3. **切换**：package `owrt-fw4` 提供 `/usr/sbin/fw4-rs`；`enable` 先比较 `fw4-rs print` 与 `/sbin/fw4 print`
   的字节差分，为空才 bind mount 到 `/sbin/fw4`（形式同 R05）；`disable` 卸载。`boot-enable` 用 S18
   之前的 init 脚本重新挂载（`firewall` 是 S19）。差分不为空时拒绝启用。
4. **验证**：上游 68 用例 + 设备配置差分 + `nft -c`；设备窗口内 `fw4 reload` 前后 `nft list ruleset`
   哈希一致。
5. **零第三方 crate**。

## 后果

- 上线那一刻内核里的规则不变，因此这是四个替换里爆炸半径最小的一次上线。
- 移植量最大（预计 2500–3000 行 Rust）；以用例通过数量作为进度指标。
