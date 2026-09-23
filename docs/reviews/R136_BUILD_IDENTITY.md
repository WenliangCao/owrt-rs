# R136 构建身份诊断

**已从 source02／主线 `195e45f` 逐字重建出实测的 `ce3d1aa…de2330`。** 问题是构建源码的绝对路径变化，不是运行时代码漂移；已测 ELF 和旧 target 均未覆盖。

| 构建 | 源码 | 固定源码根尾部 | 全新 target | release SHA-256 |
|---|---|---|---|---|
| 已测产物 | source01 | `r136-combined-01` | 原构建 | `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330` |
| 触发诊断的重建 | source02 | `r136-combined-verify-02` | 是 | `52114e36dd5aa4f3edc692021de27d3c2dbcaaf15a0537a8b8dbe2a140f76d54` |
| 原路径控制重建 | source01 | `r136-combined-01` | 是 | `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330` |
| 当前源码确认重建 | source02／195e45f | `r136-combined-01` | 是 | `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330` |

source01／02 的 30 个输入文件集合相同，仅两个示例文件内容变化；运行时、Cargo.toml、Cargo.lock 均相同。改路径后 `owrt_ubus` 的 Cargo 路径 fingerprint 和依赖构建身份改变。两产物 `.text` 都是 405576 字节，但有 2876 个字节位置不同，另有 unwind／重定位数据差异；不是仅时间戳或剥离元数据。恢复原路径后，两次全新 target 均重建相同 ELF。原源码根在替换示例前已完整归档。

`--remap-path-prefix` 不能在本 recipe 中充当“任意绝对路径均得到相同产物”的保证。Rust 文档分别说明了[输出路径映射](https://doc.rust-lang.org/rustc/command-line-arguments.html#--remap-path-prefix-remap-source-paths-in-output)和[参与符号名哈希的 metadata](https://doc.rust-lang.org/rustc/codegen-options/index.html#metadata)；这里的因果判断来自上述实际重建。未继续追踪所有编译器／链接器内部排序细节。

复现直接复用 [现有构建脚本](../../tools/r135/build_variant.sh)，不改冻结筛选程序。源码取 `195e45f` 的 components（30 个相关文件哈希见下方 JSON），在 Oracle 的相同 SDK／工具链环境中运行：

```sh
cd /home/ubuntu
bash /path/to/repo/tools/r135/build_variant.sh \
  /path/to/195e45f/components \
  /home/ubuntu/r136/rebuild-new \
  /tmp/owrt-build/r135/r136-combined-01
sha256sum /home/ubuntu/r136/rebuild-new/ubusd-rs
```

脚本要求输出目录和固定源码根尚不存在；需要保留现场时，在独立构建 mount namespace 中映射该绝对根，避免覆盖已有证据。路径必须保持为 `/tmp/owrt-build/r135/r136-combined-01`；输出和 target 可用新目录。脚本固定 Rust `1.98.1-aarch64-unknown-linux-gnu`、aarch64 musl target、OpenWrt 25.12.5 GCC 14.3.0／bfd、release `opt-level=3`／LTO／单 codegen unit／panic abort／strip，再执行 SDK `sstrip -z`；路径映射和所有链接参数保持脚本原值。

**本轮候选各用不同 work_root，因此单项筛选同时包含源码修改和路径引发的代码布局变化。不能把微小收益精确归因某一个结构修改。** 这不推翻相同实测 ELF 的路由器对比。后续批量构建应在各自独立 mount namespace 中映射相同绝对源码根；本轮不重开筛选、不替换已测 ELF。

[派生身份结果与输入／日志哈希](r136-build-identity-results.json)；原始诊断在 `private/r136/identity-diagnostic-01/`。
