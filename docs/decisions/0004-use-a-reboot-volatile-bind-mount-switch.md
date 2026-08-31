# 决策 0004：V1 使用重启即失的 bind mount 显式切换 R05

> 日期：2026-08-31
> 状态：已定
> 阶段：V1

## 背景

C1-01 要求原 `/sbin/reload_config` 保持可见、切换后共享同一基线格式，并能立即回退。
V1 又要求 package 默认无控制权，不能因安装而改写 boot、rpcd 或人工调用路径。持久替换文件、
修改多个调用方或引入新的配置 owner 都会扩大当前职责和恢复面。

## 决策

package 安装两个独立文件：

- `/usr/sbin/reload_config_rs`；
- `/usr/sbin/owrt-reload-config-switch`。

安装本身不替换 `/sbin/reload_config`。管理员显式执行 `enable` 时，开关先核对原文件的精确
SHA-256，再把候选 binary bind mount 到原路径；`disable` 卸载该 mount 并再次核对原文件。
这样 boot、rpcd 和人工调用者都继续调用同一路径，无需逐个修改。

mount 不写入配置，也不跨重启。package 的 live `post-install`、`post-upgrade` 和
`pre-deinstall` 都强制回到 disabled；离线 rootfs 安装因 `IPKG_INSTROOT` 非空不执行运行态动作。
缺少候选或原实现身份不符时，`enable` 拒绝操作。

## 被验证纠正的假设

最初只在 `prerm` 中回退。精确 rootfs 的 apk 3.0.5 实测表明：upgrade 不执行旧包的
`pre-deinstall`，已启用的 mount 会继续指向旧 inode。V1 gate 因此失败。最终把 disabled
后置条件同时放入 `post-install`/`post-upgrade`，升级与降级结束后都恢复原实现；`prerm`
继续覆盖卸载。

## 后果

- 默认安装、升级、降级、卸载和重启后的生效路径都是原实现；
- 激活是显式、局部、可立即回退且不持久的；
- package 只适用于已核对的 OpenWrt 25.12.5 stock 镜像原文件身份；
- bind mount 行为已在 mount namespace 中验证，尚未在实体路由器或目标 kernel 上执行；
- H1 若获单独授权，仍必须先做 disabled install 和只读核对，不能直接启用。
