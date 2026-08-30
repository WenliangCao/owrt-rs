# AX3000T stock / OpenWrt 25.12.5：来源缺口

> 日期：2026-08-30
> I0.1 阻塞缺口：无

固件文件、用户部署确认、官方签名清单、`profiles.json`、buildinfo、manifest/BOM 和镜像内
metadata 已相互对齐。I0.1 没有阻止源码映射或静态部署验证的来源缺口。

以下内容不属于 I0.1 来源缺口，但仍属于后续证据门：

- 未采集物理设备当前激活槽和 U-Boot environment；
- 未采集实际 UCI 配置、ubus objects、服务实例和动态时序；
- 未验证用户是否曾在官方固件安装后增加、删除或升级 package；
- 未取得首次迁移使用的 initramfs/factory 文件；该文件不影响当前 sysupgrade 镜像身份，
  但影响从小米原厂布局首次迁移的完整历史重建。

这些问题将在 I0.6 形成最小运行态问题单；在用户另行授权以前，不读取物理设备。
