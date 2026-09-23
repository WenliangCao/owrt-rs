# R141 PGO use 构建结果

冻结的八类训练 profile 已用于一次 use 构建；控制精确重现 generic R136。两个产物使用相同 30 文件源码和 canonical 路径，未修改运行时或重新训练。

| 产物 | SHA-256 | 字节 |
| --- | --- | ---: |
| R136 control | `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330` | 514771 |
| profile-use | `70e7174c648ef676800a5f03d557ba7a0e1f07de2450c5d0d6ed334d3aa862eb` | 621267 |

最终候选增加 106,496 字节（20.69%），必须保留为体积代价，不能沿用插桩 ELF 的大小或声称 PGO 无代价。

输入固定为 `/home/ubuntu/r141/training-01/merged.profdata`，SHA `566a73250308a19e97715b40ff2b2f4043f07ed836b89b205d50d810ef07c4f8`。训练结果 `passed:true`，绑定八类首次成功、各 daemon 正常退出、smoke 排除和单次合并；训练计划 SHA `1c7611cc90a925300c540352eb7c08b2349bb8239775ad901beaec9a25dce9ed`，结果 SHA `81059d6cc19d3845f39654f1075f4cb904822ca5d92f881354339ee6678b05dc`。

Cargo fingerprint 核对 use 的有效 rustflags 恰好为控制 flags 加：

```
-Cprofile-use=/home/ubuntu/r141/training-01/merged.profdata
-Cllvm-args=-pgo-warn-missing-function
```

保持 generic CPU，没有 generate flag，不重建 std。源码根、原 SDK recipe、编译器和其他链接参数沿用 [冻结计划](R141_PGO_PLAN.md)。构建前后 profile SHA 与源码身份均一致。

完整阅读两侧日志：没有 missing-function、hash mismatch 或 invalid-profile 诊断；没有诊断不代表所有运行路径均已训练。两侧各有九条同样的 SDK `runas.so` LD_PRELOAD 无法加载且 ignored 消息，Cargo 各汇总为一项 linker warning；原日志全部保留，控制 ELF 仍逐字匹配。

Oracle 输出 `/home/ubuntu/r141/build-use-01/` 已下载到 ignored `private/r141/build-use-01/`，ELF、大小和日志逐项核对。构建结果 `passed:true`；冻结计划 SHA `aa660621e724f491b3df1b131a30bba9def467c2325cb24af2c064b666dfa4ca`，结果 SHA `51ce393b05caa6d7a21f29ef527e8501ed57908de78d8e5f75da25f3693e71c0`，use 日志 SHA `560b7af1046e8e3509d44fc4b741f0802d09ebca6d6cbf258d7e8a3e23204dfc`。

本报告仅确认构建和身份。候选已交给独立正确性与筛选阶段；尚无此 ELF 的性能或部署结论，不改变 R136 的旧尾延迟负项，生产保持 C。
