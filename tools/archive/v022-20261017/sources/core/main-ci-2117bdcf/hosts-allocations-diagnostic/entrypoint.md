# x86 精确源码诊断入口（仅准备，未执行）

源固定 `2117bdcfe715e20c9c9fbee21e8b426466aad8bb`，Rust 1.98.1 / LLVM 22.1.8。
本 Mac 为 arm64 且禁止 Rust 构建；Oracle 为 AArch64。可用真实 x86 执行环境是原
`ci` workflow 的 GitHub `ubuntu-latest` runner。不是重试失败 CI，也不以诊断替代原失败。

在一次独立 x86 诊断 job 中从固定 Git 对象取档，使用全新私有 target 与 TMPDIR：

```sh
set -eu
test "$(uname -m)" = x86_64
freeze=2117bdcfe715e20c9c9fbee21e8b426466aad8bb
mkdir source diagnostic
git archive "$freeze" | tar -x -C source
cargo +1.98.1 -V
rustc +1.98.1 -Vv
export RUSTFLAGS=-Dwarnings CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$PWD/diagnostic/target"
export TMPDIR="$PWD/diagnostic/tmp"
mkdir "$TMPDIR"
cargo +1.98.1 test --locked --manifest-path source/components/dnsmasq/Cargo.toml   --test hosts_allocations --no-run
sudo -n env "PATH=$PATH" "CARGO_HOME=$HOME/.cargo" "RUSTUP_HOME=$HOME/.rustup"   RUSTUP_TOOLCHAIN=1.98.1 RUSTFLAGS=-Dwarnings CARGO_INCREMENTAL=0   "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" "TMPDIR=$TMPDIR"   sh source/tools/dnsmasq/run_isolated.sh cargo test --locked --offline   --manifest-path "$PWD/source/components/dnsmasq/Cargo.toml"   --test hosts_allocations -- --test-threads=1 --nocapture
```

这是原 17 项 allocation-test binary 的完整顺序；若 root 选择只定位单例，在 `--test
hosts_allocations` 后加原名 `retained_dhcp_bulk_links_match_finite_and_infinite_c_lease_controls`
并在测试参数中加 `--exact`。单例结果不能代替原完整顺序的失败，也不能被当作通过重跑。
原 assertions 保持，任何诊断记录应避免在注入窗口内额外分配；具体观测字段由根因研究决定。

`comparison.json` 保存 Oracle 该项原执行的成功行、源码与日志 SHA。原本的主机 CI
失败日志保持在相邻 `ci/` 下。没有创建/推送新 workflow，没有调用 dispatch。
