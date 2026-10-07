# M6b APK r3：接受过 M5 r2 的升级与回滚范围

2026-10-07。独立tool-only提交 `fa2d57cf`，基于主线 `0a9d1550`；未修改产品、Makefile或当前70097c66冻结，没有Oracle/SDK/APK执行。只执行最小本地工具负控，不阻挡27窗口或方案A。最终原 ELF 身份和 APK体积预算失败保留；此改动只使升级版本与验收范围明确。

## 接受过的 M5 原资产（已实际本地读/hash）

以 [M5_REPORT](../M5_REPORT.md) 的构建证据为准，不重建旧包：

| 资产 | 精确身份 |
| --- | --- |
| M5 APK | `dnsmasq-2.93-r2.apk`，1,065,071 B，SHA `bfed44eaf49703745a2c08a8ee1fbc5325b44f833d07baee2224a0084a6ee8aa` |
| M5 ELF | 1,929,256 B，SHA `37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b` |
| M5源码 | `dc1b740d7973838e2ae7f098d0726b0484e55074`，已有durable `archive/dnsmasq/m5-m6a/20261007/m5-final-registry-recovery` 等tag包含该commit；旧refs原样保留 |
| 原构建manifest | `E/M5/final-20261006/dc1b740d7973/archive-package-final/plain/build/manifest.json`，SHA `c16780b08c672b280b15412bcf06ec639bcc31cc359629119bb0836fb71d335b`，artifact_identity_verified/recipe_restored均true |
| 原APK本机位置 | 同一manifest目录下 `dnsmasq-2.93-r2.apk`；实际文件SHA/bytes等于manifest，不修改/替换/重新生成 |
| 镜像stock C | 固定`2.93-r1`，ELF SHA `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`；原image/stock APK/备份原样保留 |

stock/M5 ELF/APK继续只保存在ignored/private或原镜像资产中，不进Git；source稳定refs和完整SHA记录保留。root将该**原APK字节**复制到最终private资产目录并再次核验，而不是用新builder重建所谓M5包。

## 最小接口与字段传播

recipe本来已有 `V1_PACKAGE_RELEASE`、默认2，不需要修改Makefile。旧Python硬绑r2，需要以下小扩展：

- `build_package.py --package-release {2,3}` 默认2；传给现有Make变量，filename与metadata按同一release核验。frozen package必须 `freeze.package_release`匹配；旧M5缺此字段等价2，不能据旧freeze误造r3。不重新codegen/strip已验收ELF。
- `m4_package_lifecycle.py --package-release {2,3}` 默认2；r3必须同时传 `--previous-apk/--previous-apk-sha256/--previous-elf-sha256/--previous-source-commit`。四项完整且必须等于上述接受过M5身份；实际APK SHA和extract后的payload ELF再次核验，metadata必须r2，ancillary和post-upgrade脚本仍与stock一致。
- `m5_final_validation.py` 的M5模式保持r2和原stock范围；M6b冻结为r3，并要求 `previous_package`完整dict：path、package_id、APK SHA、ELF SHA、source commit。prepare将原M5 APK加入冻结assets；commands/`package-freeze.json`/builder/leaf checks/summary全部传播相同release与旧身份。
- M6b生命周期completion要求candidate r3、previous_upgrade.passed=true、原M5三SHA，以及严格6个追加阶段顺序、完整**14阶段inventory**。summary记录release、expected_package_id、旧身份、previous_upgrade结果及完整stage名。只CLI有r3而静态validator仍r2的情况不能过。

## 真实事务合同（尚未执行）

原stock链8个stage保留，M5默认r2行为不变；M6b用r3跑同一链，仍验证r3→stock直接downgrade和移除后stock rollback、fresh install、reinstall、uninstall、配置/UID/GID/ujail/DNS/ownership和variant互斥。然后在已经回到stock的同一隔离rootfs追加：

| 追加阶段 | 实际事务与断言 |
| --- | --- |
| stock-to-m5-baseline | `apk add previous.apk`，实际installed version=r2、执行原37f85 ELF，modified配置保持 |
| m5-to-candidate-upgrade | `apk add candidate.apk`，**r2→r3真实版本变化**、执行最终ELF；不带force-reinstall |
| direct-m5-downgrade | `apk add previous.apk`，r3→r2真实直接downgrade、执行原M5 ELF |
| m5-to-candidate-for-removal | 再次r2→r3；保持同配置/用户/文件合同 |
| candidate-remove-for-m5-rollback | `apk del dnsmasq`；包/ELF/运行进程/init links确实删除，modified配置保持 |
| m5-rollback-after-removal | `apk add previous.apk`；r2实际恢复、原ELF/jailed service/配置健康 |

版本变化/直接downgrade后仍显式执行stock init restart并记录operator activation；不把它冒称post-upgrade自动重启。所有capture读取真实APK数据库、文件状态和实际process ELF/DNS；辅助旧APK的路径不用于service身份，只有安装路径可满足门。失败时previous_upgrade保持false，原失败及cleanup保留，不挑路径或跳过rollback。

## root最终freeze的确切输入与命令

不要原地改70097c66、M5旧manifest或正在跑的性能freeze。最终产品/工具齐备后，复制原M5 APK到例如 `/home/ubuntu/M6B-FINAL/private/accepted-m5/dnsmasq-2.93-r2.apk`，核对固定SHA，并在最终inputs中添加：

```json
{
  "validation_mode": "m6b",
  "package_release": "3",
  "previous_package": {
    "path": "/home/ubuntu/M6B-FINAL/private/accepted-m5/dnsmasq-2.93-r2.apk",
    "package_id": "2.93-r2",
    "apk_sha256": "bfed44eaf49703745a2c08a8ee1fbc5325b44f833d07baee2224a0084a6ee8aa",
    "elf_sha256": "37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b",
    "source_commit": "dc1b740d7973838e2ae7f098d0726b0484e55074"
  }
}
```

其余最终inputs、同一feature-off opt3 ELF、link map、44族/M2/perfguard/资源/压力与5个solver依赖均按[最终同ELF配方](M6B_FINAL_ACCEPTANCE_RECIPE.md)。prepare会验证旧APK并锁SHA；前置功能全部通过后：

```sh
sudo -n python3 "$M6B_TOOLS/m5_final_validation.py" run --manifest "$M6B_MANIFEST" --phase package --attempt 1
sudo -n python3 "$M6B_TOOLS/m5_final_validation.py" run --manifest "$M6B_MANIFEST" --phase lifecycle --attempt 1
python3 "$M6B_TOOLS/m5_final_validation.py" summary --manifest "$M6B_MANIFEST"
```

控制器实际builder命令增加 `--package-release 3`，`package-freeze.json`中release=3；APK为 `dnsmasq-2.93-r3.apk`。leaf实际命令增加下列参数（其余stock APK、两个variants、五deps和最终source/SHA照原控制器）：

```sh
--package-release 3 \
--previous-apk /home/ubuntu/M6B-FINAL/private/accepted-m5/dnsmasq-2.93-r2.apk \
--previous-apk-sha256 bfed44eaf49703745a2c08a8ee1fbc5325b44f833d07baee2224a0084a6ee8aa \
--previous-elf-sha256 37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b \
--previous-source-commit dc1b740d7973838e2ae7f098d0726b0484e55074
```

size-target仍保留原始failure；只有artifact identity、r3 metadata和SDK recipe恢复正确的size-only失败可继续生命周期。新APK体积实际构建后记录，M6b增量接受仍由用户在最终报告后决定。未做任何物理router安装/回滚。

## 本地验证与失败保全

工具提交 `fa2d57cf4358aa601d5d47279ba39d1a2aaaea1d`。14个最小本地测试通过：r2旧默认/metadata/freeze兼容，r3误用r2/缺release拒绝；M5 APK/ELF/source不完整或不同拒绝；controller argv/14stage/顺序与artifact版本绑定；虚拟事务无force且失败的版本变化不能让previous_upgrade过；summary不把未跑其他门冒称整体通过。py_compile/diff-check通过。FakeCase和合成metadata只测试工具，**不是SDK、真实APK或升级通过**。

第一版合成controller fixture漏runtime_root，出现KeyError/exit1；同未修改草案立即重跑完整stdout/stderr并保存，补fixture后通过。首次工具输出未单独落盘，保存的重复日志不称首次日志；这是工具fixture问题，不是实际APK失败。中央证据 `E/M6B/apk-r3-tool-local/manifest.json` SHA `e37ad40cb9f6eac73624a00d25fc514b659bcd566eb8265b3d1ab8b68a609e82`，包含失败/重跑、工具字节/patch、接受过M5原manifest及实际hash身份。所有Oracle构建／14stage执行仍待最终freeze。
