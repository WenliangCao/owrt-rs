# 公开前隐私检查

2026-10-20。仓库已按用户选择更名为 `WenliangCao/owrt-rs`，About 为：

> Incrementally rewriting and optimizing OpenWrt components in Rust for Xiaomi AX3000T (AN8855).

**首次检查时仓库保持 PRIVATE。未发现已确认的真实私钥、令牌或密码，
初次检查发现当前文件及远程可达 Git 历史含有个人标识；下述发现记录清理前状态。
用户随后授权完整脱敏，并通过独立新仓库公开；原仓库继续私有。
清理与迁移结果见 [历史迁移说明](../history/PRIVACY_MIGRATION_20261020.md)。**
这份报告不复述邮箱、MAC、SSID、服务器地址或个人目录的实际值。

## 检查范围

扫描基线为 `52550b4670e76d5044277f10be7cbb7c87a12e3a`：4362个已跟踪文件，
684个本地可达ref、7230个提交、195个注解标签、13667个唯一文件对象，包含已删除
文件、提交消息及标签消息。410个GitHub远程ref的对象全部在本地，可达性单独核对，
没有把本地保留的旧历史误报为当前GitHub公开面。

使用官方预编译Gitleaks 8.30.1并校验其发布摘要；历史补丁与全部原始对象分别扫描，
报告全量遮盖匹配值，再逐项检查候选。补充检查私钥块、密码字段、凭据URL、
文件名、IP/IPv6、邮箱和与离线备份对应的设备标识。2张PNG和3份PDF图表完成
文字/元数据及视觉复核。没有构建Rust或访问物理路由器。

GitHub托管内容另行检查：10个Release的113个附件（180652347 B）、324份Actions
运行日志、133个构建artifact，以及唯一关闭PR和评论/review端点。附件下载身份
核验后检查文本、归档及可提取内容；Release的9个固件与35个独立APK、10个归档
内APK解包，Actions额外87个APK与10个固件也在Oracle离线解包检查。
没有执行下载的程序或修改发布附件。

## 已确认的个人信息

| 类型 | 当前文件或历史位置 | 范围 |
|---|---|---|
| 个人邮箱 | Git author/committer元数据；示例提交 `2f14e05f4ce5` | 14个远程可达提交，主线及版本标签祖先均包含；另125个只在本地保留历史 |
| 实际设备MAC | `components/netifd/src/config.rs:635`、`:643`；`components/netifd/src/device.rs:755` | 字符串及数字数组共3处；11个远程可达历史blob版本 |
| 实际Wi-Fi名称 | `reports/ax3000t-stock-openwrt-25.12.5/R74_P33_DEVICE_WINDOW.md:46` | 当前文件及1个远程可达历史blob |
| 本机个人目录路径 | 多份历史工具和报告 | 当前44文件/201行，暴露用户名和工作目录；敏感程度低于凭据 |

`components/netifd/src/device.rs:845` 还有一个与实际MAC有5个字节相同的候选地址，
尚未独立确认属于实际设备；后续清理时宜一并使用明确的合成测试地址。

`private/` 虽被.gitignore忽略，仍有7个已跟踪的基准测试脚本/补丁；未发现其中有
秘密，但目录名和.gitignore都不是访问控制。未跟踪的实际备份、镜像和设备原始日志
仍留在忽略目录，没有因此次检查上传。

## 未发现项与边界

- 当前SSH别名oracle使用的公网IP，在全部13667个历史文件对象中精确匹配为0；
  其他公网IPv4/IPv6候选经上下文核对未确认个人服务器地址。
- 离线配置中的实际Wi-Fi密码在当前文件和全部历史对象中精确匹配为0。
- Git凭据扫描608个补丁候选、410个对象候选均为文件摘要、公开指纹或明确的
  隔离测试值；密码哈希为已有rpcd测试夹具，没有发现真实SSH私钥或访问令牌。
- Release与Actions的已检查内容未匹配已知个人服务器地址、MAC、SSID、密码或
  私人邮箱。固件中的原版公钥、加密库PEM分隔符和测试输入不当作用户私钥。

这是已说明范围内的静态检查结果，不是对任意未知、加密或混淆秘密的绝对保证。
扫描后新增内容仍需检查。原始证据仅留在权限受限的私有审计目录；脱敏报告位于
ignored `private/privacy-audit-20261020/`。

## 公开前需要处理

GitHub的public/private权限作用于整个仓库，不能给公开仓库内的某个目录单独设
私有读取权限。官方说明还明确指出：从private变为public后，Actions历史和日志也
会对所有人可见。参考[仓库可见性](https://docs.github.com/en/repositories/creating-and-managing-repositories/about-repositories)
与[更改可见性](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility)。

需要保密的资料应独立存放于私有仓库或不进入Git。上述MAC/SSID应替换为合成值，
个人路径可改为相对路径或占位符；但只修改当前文件无法清除旧提交、标签和作者邮箱。
可选择清理整个公开历史，或从脱敏后的快照建立公开仓库并保留原私有归档。

上述为首次检查时的建议。后续历史清理已获用户授权；原始证据已离线私有备份，
发布产物保持原始身份。最终处理范围和GitHub残留引用边界以历史迁移说明为准。
