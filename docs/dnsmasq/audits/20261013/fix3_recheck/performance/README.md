# Same-type raw record recheck: reproducibility

See `NOTES.md` for the confirmed remaining N4 finding, retained-statistic cross-check and limits. This directory does not change product source.

Actual Oracle root: `/home/ubuntu/dnsmasq-fix3-recheck-20261013`. All originals remain under `private/performance-same-type` and `private/performance-same-type-smoke`. The main/final release SHAs and complete source inputs are frozen in `same-type-plan.json`. `statistics-check.json` independently recomputes the **prior** six-pair type-absent results; it is not a new execution of those 32 windows.

Native tools are reused without recompiling, with SHA256:

- `m6a_loadgen`: `959fcdbf1fb2cd9ac682ed51ef35ba1811f4f744d743c09fa71a8f598460c8f1`
- `m6a_upstream`: `ee5259b721a7f0f45acd769b791b5c004620f14c0af2fc067f8548bd7878da35`
- exact-image C: `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`

## Safe repeat of one directed window

Use a **fresh** `--output`; never remove or replace original audit output directories. The following reuses the retained source, tools and exact binary identity. Change only `--rust` and its matching `--expected-rust-sha` to run main; all other parameters remain identical. For the UDP control change `--scenario tcp` to `--scenario hit`.

```sh
R=/home/ubuntu/dnsmasq-fix3-recheck-20261013
IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
NATIVE=/home/ubuntu/dnsmasq-final135-889fe4f5/private/native
sudo -n sh "$R/source/tools/dnsmasq/run_isolated.sh" \
  python3 "$R/performance/same_type_window.py" "$R/source" 1000 \
  --implementation rs --rust "$R/private/release/dnsmasq-rs" \
  --expected-rust-sha 25b7291d0074b8c7a854aa9f63f7b5edb12bc1315e60dd26f8f6eed36d362fd8 \
  --image-root "$IMAGE" --loadgen "$NATIVE/m6a_loadgen" --upstream "$NATIVE/m6a_upstream" \
  --preflight --scenario tcp --tcp-profile hit --round 1 --rate 1000 \
  --cache-names 4096 --clients 20 --warmup 3 --duration 15 --saturation-seconds 0 \
  --cpu-daemon 0 --cpu-upstream 1 --cpu-load 2 --cpu-control 3 \
  --drain-sample-seconds 0,1 --drain-timeout-seconds 65 --seed 1297297665 \
  --output "$R/private/same-type-RECHECK-NEW"
```

Main path: `/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs`; main SHA256: `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`. Each direct window proves a configured raw A through UDP/TCP, then checks all 4096 dynamic A cached names before disabling upstream answers. This is a complete fixture, not a claim that one window replaces the three-pair evidence.

## Repeat the full frozen process

`same_type_smoke.py`, `same_type_pairs.py` and `verify_same_type.py` retain the exact paths of this audit. To repeat the full process, first copy the scripts into a **new isolated root**, update ROOT in the pair and verifier drivers, and prepare the same source commit and fresh release/build receipt with the adjacent build workflow. The main artifact, image and native tools must remain as frozen. The prerequisite fresh build receipt must truthfully be passed and match `SOURCE_COMMIT`. Do not just rerun these drivers against existing original directories.

The original invocation sequence was:

```sh
sudo -n sh "$R/source/tools/dnsmasq/run_isolated.sh" python3 "$R/performance/same_type_smoke.py"
python3 "$R/performance/same_type_pairs.py" prepare
# All builds and other task workloads must finish before this command.
sudo -n python3 "$R/performance/same_type_pairs.py" run
python3 "$R/performance/verify_same_type.py"
```

The controller rejects existing attempts, holds the shared build lock, verifies frozen hashes and checks for competing task workloads before every window. No product changes, packet tracing, retries, outlier deletion or clock-window selection are used. TCP reconnects every 100 requests; CPU includes that normal connection work. Performance is measured on Oracle, not a physical router or as a saturation capacity test.
