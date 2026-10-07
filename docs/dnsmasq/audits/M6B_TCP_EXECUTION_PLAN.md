# Scheme A TCP 门禁执行方案（待运行）

日期：2026-10-07。此文件只冻结命令、身份和归档布局；不启动构建、Oracle 或压力窗口。被测源码必须是独立分支 `m6b/tcp-scheme-a` 的提交 `9cef54fe`（包含 `ca63c365`、`90ce2c22`、`454ab2e9`）。UDP-only 候选及其窗口不作为 TCP A 证据。

## 1. 源码归档与身份

在本 worktree 执行，生成一次性 source archive；不要使用主线工作树或旧 source tar：

```sh
BRANCH_SHA=$(git rev-parse HEAD)
git diff --quiet "$BRANCH_SHA" --
ARCHIVE=/tmp/m6b-tcp-a-${BRANCH_SHA}.tar.gz
git archive --format=tar --prefix=source/ "$BRANCH_SHA" | gzip -n > "$ARCHIVE"
sha256sum "$ARCHIVE" > "${ARCHIVE}.sha256"
```

Oracle 由主线程在 UDP-only pilot 完成后执行，使用新目录（示例目录名，不得复用 UDP candidate）：

```sh
ROOT=/home/ubuntu/dnsmasq-m6b-tcp-a-20261007
SOURCE=$ROOT/source
EVIDENCE=$ROOT/private/evidence/M6B/tcp-a-20261007
C_BUILD=$ROOT/private/c-reference-097a9e21
C_BIN=$C_BUILD/dnsmasq/dnsmasq
scp -O "$ARCHIVE" oracle:/home/ubuntu/m6b-tcp-a-source.tar.gz
ssh oracle "mkdir -p '$ROOT' && tar -xzf /home/ubuntu/m6b-tcp-a-source.tar.gz -C '$ROOT'"
```

解包后必须记录 archive SHA、`git rev-parse`（若存在）、所有 source file SHA，并确认 C reference 的 ELF SHA 为 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。`C_BUILD` 必须含匹配的 `dnsmasq/dnsmasq`、identity 和 source recipe；不能用镜像外任意 C 构建替代。

## 2. AArch64 opt3/s 构建（仅命令，不在本阶段启动）

构建必须串行持有共享 Cargo target/build lock，且输出目录全新；每个 `build.json` 和 ELF SHA 归档到 `$EVIDENCE/builds/`：

```sh
mkdir -p "$ROOT/private/build-opt3" "$ROOT/private/build-opts"
ORACLE_BUILD_LINK_MAP=1 sh "$SOURCE/tools/dnsmasq/oracle_build.sh" \
  "$SOURCE" "$ROOT/private/build-opt3" release
ORACLE_BUILD_OPT_LEVEL=s ORACLE_BUILD_LINK_MAP=1 \
  sh "$SOURCE/tools/dnsmasq/oracle_build.sh" \
  "$SOURCE" "$ROOT/private/build-opts" release
sha256sum "$ROOT/private/build-opt3/dnsmasq-rs" \
  "$ROOT/private/build-opts/dnsmasq-rs"
cp "$ROOT/private/build-opt3/build.json" "$EVIDENCE/builds/build-opt3.json"
cp "$ROOT/private/build-opts/build.json" "$EVIDENCE/builds/build-opts.json"
```

在任何门之前确认 opt3/s 的 source identity、toolchain、RUSTFLAGS、target triple 和 artifact SHA；s 仅为性能对照，不能用作功能资格或 APK 身份。

## 3. Primitive 与 S1–S8

`run_isolated.sh` 只用于需要 Linux loopback-only namespace 的脚本；每个输出目录必须新建且位于 `$SOURCE/private/`，同一组保存 `commands.json`、stdout/stderr、result/summary、tool/source/ELF SHA 和 cleanup。

```sh
mkdir -p "$SOURCE/private/evidence/M6B/tcp-a-20261007/primitive"
python3 "$SOURCE/tools/dnsmasq/dns_cache_diff.py" \
  --rustc /home/ubuntu/.rustup/toolchains/1.98.1-aarch64-unknown-linux-musl/bin/rustc \
  --rust-source-root "$SOURCE" \
  --output "$SOURCE/private/evidence/M6B/tcp-a-20261007/primitive/cache"
```

S1–S8 的本地原语门必须先读 `$SOURCE/docs/dnsmasq/audits/M6B_TCP_PLAN.md`，复核 `Cache::{snapshot,new,clear,start_insert,insert*,negative,CNAME,commit,capture,import,lookup,remove,free,LRU}`、`PublicationCache` 和 `main.rs` TCP accept/client/drop 接线。故意共享 LRU、漏 detach shard、错用 child EntryId、CNAME 乱序和失败回滚负控必须各自失败；负控结果与正例放在 `primitive/negative-controls/`，不能只保留成功输出。

## 4. Service contract gates（C-first，再 Rust）

以下命令均在 Linux Oracle 上以 `sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh"` 前缀执行，`RUST=$ROOT/private/build-opt3/dnsmasq-rs`；每条命令输出独立目录，不覆盖失败结果：

```sh
TOOLS=$SOURCE/tools/dnsmasq
OUT=$SOURCE/private/evidence/M6B/tcp-a-20261007/service
RUST=$ROOT/private/build-opt3/dnsmasq-rs

sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/dns_tcp_cache_diff.py" \
  --reference-build "$C_BUILD" --rust "$RUST" --out "$OUT/tcp-cache"
sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/dns_tcp_reload_diff.py" \
  --reference "$C_BIN" --rust "$RUST" --output "$OUT/reload"
sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/dns_tcp_writeback_diff.py" \
  --reference-build "$C_BUILD" --rust "$RUST" --out "$OUT/writeback"
sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/tcp_stale_oracle.py" \
  --reference-build "$C_BUILD" --rust "$RUST" --out "$OUT/stale"
sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/dns_do_cache_diff.py" \
  --reference-build "$C_BUILD" --c-binary "$C_BIN" --rust "$RUST" --out "$OUT/do-edns"
sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/dns_tcp_daemon_diff.py" \
  --reference "$C_BIN" --rust "$RUST" --output "$OUT/daemon"
sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/dns_tcp_capacity_diff.py" \
  --reference-build "$C_BUILD" --rust "$RUST" --out "$OUT/capacity"
sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/dns_tcp_accept_failure_diff.py" \
  --reference-build "$C_BUILD" --rust "$RUST" --out "$OUT/accept-failure"
```

Ingress is two-phase: run C with `--binary "$C_BIN"` to make `c/result.json`, then run Rust with `--binary "$RUST" --reference "$OUT/ingress-c/result.json"`; both invocations use the isolated wrapper and separate output directories.

```sh
sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/dns_tcp_ingress_diff.py" \
  --binary "$C_BIN" --out "$OUT/ingress-c"
sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/dns_tcp_ingress_diff.py" \
  --binary "$RUST" --reference "$OUT/ingress-c/result.json" --out "$OUT/ingress-rust"
```

Each service gate is a hard semantic gate: C/R rows, wire bytes, TTL/clock, upstream count, counters, exit status and cleanup must match according to that tool's documented normalization. A failed gate remains in place with its first failure; do not rerun into the same directory or replace it with a later passing window.

## 5. Resource, lifecycle and pressure gates

For controlled resource/lifecycle checks, use the same exact image root and Scheme A ELF. The existing TCP scripts above record FD/thread/child and active metric state. Add the 0/1/5/15/60-second drain samples and live requested bytes to each output. Then run the required disk/FD pressure pair, keeping each side's raw result:

```sh
IMAGE_ROOT=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
PRESS=$SOURCE/private/evidence/M6B/tcp-a-20261007/pressure
sudo -n python3 "$TOOLS/m3_soak.py" pressure \
  --image-root "$IMAGE_ROOT" --rust-binary "$RUST" \
  --out "$PRESS" --duration-seconds 300 --timeout-seconds 720
```

The pressure output must show both ENOSPC and EMFILE C/R results, correct replies/lease state, listener survival, no FD/thread/child leak and cleanup. A five-minute resource run (if not already included in the formal M6b suite) uses `m3_soak.py run --duration-seconds 300` once per implementation with separate output directories; it is a resource check, not a replacement for the 9×3×5 performance window.

For TCP-specific new pressure, preserve profiles for 20 and configured-limit connections, empty/half/full/4096 cache, random multi-RR, 100-query reconnect, 150-second idle snapshot plus parent churn, conflict and interleaved reload/lease import. Record profile JSON and process snapshots under `$EVIDENCE/pressure/tcp-*`; all must satisfy the drain barrier before after-drain samples are labeled.

## 6. CPU hard gate and final archive

For each C/R3/A formal TCP window compute `u=(daemon cgroup CPU usec + TCP child CPU usec)/correct replies`. A passes only if median `u_A <= 1.05 × median u_R3`, median `u_A < median u_C`, throughput/p95 do not regress over 5%, S1–S8 add no differences, and errors/FD leaks are zero. Keep all five raw rounds and the round-range `W`; never select a best window. Archive full command/identity/ELF/source SHA, raw latency/wire/CPU/PSS/FD/thread/child, failure and cleanup JSON, then verify SHA/metadata before pruning remote data.

No command in this document has been started during the UDP-only 27-window reservation. The first remote action after the reservation is released is source identity verification, then the two builds, then primitive/service/resource gates in the order above.
