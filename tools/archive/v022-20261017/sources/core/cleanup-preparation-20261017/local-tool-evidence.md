# 本地工具保留盘点

25 个远端控制器全部找到保留或重建依据；独有工具缺口为 0。只读检查，没有删除、测试、Oracle/router 操作或新大归档。

- 本地筛选 173 份工具，其中 65 份与当前 Git blob 完全一致；其余私有包装脚本、路径适配版本保留在原目录。
- `continue-r92.py` 已有精确本地副本 `core/private/r92-continuation/continue.py`，SHA `4913a166e9472067ee2ba4f26af95e25939a5ca445518b9560735e2f11be51ee`；完整 38 条命令也已保存，无须重新归档或提交。
- 旧 r75 overlay `effc87d0…` 在 Git `23398378`；fdinfo 版本 `765c6b78…` 在 `72ea30de`。PGO training-only、R93 accept 和 event-stress builders 均有当前 Git 精确版本。
- 训练完整包、两次 image CI 原始 ZIP、native-runtime 工具包以及旧 safe retention 包均存在；路径和复用哈希见 JSON，不重复读取大文件校验。
- DNS/CORE/PGO 报告均已提交且可从当前 HEAD 到达；本地原始失败及修正证据未动。

这只是工具保留盘点。远端 raw、唯一归档、运行进程及可删目录由父代理另行核实；不把本清单当作整目录删除许可。尤其不据此声称远端 `native-final-598b19a7-raw.tar.gz` 已有本地副本。
