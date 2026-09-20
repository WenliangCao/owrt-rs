# R97：方法签名与 ACL 的 C 字符串边界修复

2026-09-20。继续研究方法存储时发现实际兼容性缺陷，先修复再做性能比较。
没有证据可以把当前 ubusd 差距归为 Rust/C 的不可逾越语言差异。

精确 ubus revision `24864e7840b3a02a9ef76284a373f6b2f00b8a9b`：
`ubusd_obj.c` 保存方法数据并引用 `blobmsg_name`；`ubusd_acl.c` 对方法和 ACL 方法授权使用 `strcmp`。
匹配 libubox 的 `blobmsg_check_name` 只验证声明长度处的 NUL，允许更早的 NUL。
`blobmsg_add_blob` 则调用 `blobmsg_add_field`，用 strlen 重建外层名字并清零名字填充，方法数据原样复制。
线上资料入口：[blobmsg 校验](https://lxr.openwrt.org/source/libubox/blobmsg.c)、
[方法保存](https://lxr.openwrt.org/source/ubus/ubusd_obj.c)；最终以本镜像对应的本地源码和实机差分为准。

原 Rust 的问题：方法名复制了整个声明长度，ACL 方法授权也比较完整 JSON 字符串；
lookup 直接复制原外层字段。因此嵌入 NUL 的方法可能错误隐藏，名字尾部或非零填充也可能原样返回。

本次修复：

- 校验仍按原声明长度进行，接受/拒绝边界不变；ACL 使用第一个 NUL 前的名字。
- 名字授权和通配符也遵循 C 字符串结束位置。
- 注册时一次性生成 C 会返回的外层字段：标准名字长度、零填充、原方法数据。
  保留完整方法数据，不把规范化后的短名字长度误作原始数据偏移。

路由器上同时运行精确 C、改动前 Rust、修复后 Rust，全部在独立命名空间。
七个对象检查覆盖：wire 名字嵌入 NUL、拒绝对照、ACL JSON 名字嵌入 NUL、通配符嵌入 NUL、
有效 C 名字为空、非零名字填充、普通控制。root 与 nobody 共 14 条观测；方法数据包含 policy 字段。
C 和修复后的记录完全一致；旧 Rust 的错误隐藏和非规范外层字段均复现。
被拒绝的方法在三侧均保持拒绝，不把名字后面的合法后缀当作授权依据。

构建机和路由器各通过 29 条单测，clippy 门通过。生产 C、配置、boot、宿主挂载、健康与清理均通过，
未部署候选。[身份与完整差分](r97-method-fix.json)。原始记录在 `private/r97/method-fix/`。
这是方法名字与方法授权边界的修复，不声称已经审完所有 JSON 字符串边界。
