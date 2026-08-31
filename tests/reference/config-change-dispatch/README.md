# 参考测试：配置变更检测与分发（C1-01）

合同见 [docs/contracts/config-change-dispatch.md](../../../docs/contracts/config-change-dispatch.md)。

## 这些用例证明什么

用例在**规范化内容 token** 的层面建模，不使用真实 md5，因此无需 uci 二进制即可运行。
它们验证**算法**：

- 扫描集合与 `/var/run/uci/` 优先级；
- 含点文件名产出空条目的规则；
- 新增 / 修改 / 删除三者的不对称；
- 切换实现时必须零事件（回退安全）。

## 这些用例不证明什么

**不证明规范化本身。** 「替换实现产出的规范化输出与 `uci show` 逐字节一致」
是合同 C-06 的要求，只能由 V1 在真实设备上做差分验证。本目录的 token 模型刻意
不触碰这一层，避免用一个假设去验证另一个假设。

## 运行

```sh
python3 tools/c1_reference_check.py --cases tests/reference/config-change-dispatch/cases
```

参考模型即 `tools/c1_reference_check.py` 中的 `reload_config()`，是 R1 实现必须
在这些用例上对齐的 oracle。

## 证据等级

每个用例标注 `evidence`：

| 等级 | 用例数 | 含义 |
|---|---:|---|
| RUN | 2 | 本设备只读观察已证实 |
| DEP | 5 | 由 `/sbin/reload_config` 全文直接得出 |
| SRC | 4 | 由固定 revision 源码推导，**尚未在设备上观察** |

四个 SRC-only 用例不得被当作已验证行为：

- `c04-deleted-config-emits-once` —— 依据 busybox 1.37.0 对缺失文件返回 FAILED；
- `c07-dotted-rename-to-valid-becomes-live` —— C-03 的逆向推论；
- `c08-var-run-uci-takes-precedence` —— 本设备 `/var/run/uci` 不存在，分支未被走到。
- `c11-dotted-name-can-resolve-section` —— `package.section` 成功解析时会输出该 section；
  这是防止把本设备 7 个空条目错误泛化为“所有含点文件均为空”的源码反例。

它们各自需要的验证方式记在合同 §8。
