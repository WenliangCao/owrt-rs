# Shared hosts owner: inotify resource boundary (2026-10-14)

This is an additional runtime boundary for `1d535cb9bd1499a3c4bae0fc6e76e285a933b5bf`.
The independently reproduced shared-owner regression is failed full HUP;
the incremental ownership change is not claimed as a separately reproduced
old bug. All runs used private Oracle namespaces and synthetic hosts/DHCP,
without changing a physical router, main, or the stock image.

## Exact inputs

- Fixed ELF: `/dev/shm/full-integrated-fix-20261014/private/release-owner-fix/dnsmasq-rs`,
  SHA-256 `d57280b85ddb1d7ad5a861254b739d928a9834bd45147e9c9bbba6163ea3484e`.
- Prior combined ELF: `/dev/shm/full-integrated-fix-20261014/private/release/dnsmasq-rs`,
  SHA-256 `e2b075617d39cafa7d9443abfabbd18f9d2602dc0b535eed6393ac62ee9bbf77`,
  source `397cecb67f3ff71ad352de80220834a6a5e78103`.
- Exact C: OpenWrt 25.12.5 rootfs
  `/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`,
  daemon SHA-256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
- Driver snapshot: `/dev/shm/full-integrated-fix-20261014/private/tools/full_r2_hosts_recovery_v2.py`,
  SHA-256 `a0fd9f5a57188e6459d7e1707e78df59034ac1d647eced953216440581037ade`.
  The previous driver path was not overwritten.

`--hostsdir` starts with `/m2/hostsdir/hosts` and uses close-write events for
both pressured updates and recovery. It never sends HUP. It cannot be combined
with the separate HUP/cache-expiry scenario. Each run starts with 2000 hosts,
establishes and queries one held TCP connection, then measures that process's
VmSize before applying its own RLIMIT_AS headroom. Both pressured generations
replace the same path. Configured `ready.test` and the synthetic DHCP lease
remain independent of the changing file.

## Results

Each row is one fixed Rust process with two pressured updates; its exact C
counterpart uses the same workload and relative resource budget.

| Replacement rows | Headroom KiB | Rust ENOMEM total | Source EOF in each update | ENOMEM after each EOF | UDP/new TCP view under pressure |
| --- | --- | --- | --- | --- | --- |
| 2000 | 256 | 2 | yes | 1 | complete old samples |
| 2000 | 512 | 2 | yes | 1 | complete old samples |
| 2000 | 1024 | 2 | yes | 1 | complete old samples |
| 6000 | 256 | 215 | no | 0 | complete old samples |
| 6000 | 512 | 262 | no | 0 | complete old samples |
| 6000 | 1024 | 2 | yes | 1 | complete old samples |

All six Rust cases stayed alive and exited normally. Each pressure stage,
release-without-update stage, and later close-write recovery passed configured
DNS, lease DNS, UDP/TCP and DHCP ACK checks. Held TCP kept its accepted old
generation throughout; new TCP saw the parent's old generation until the
successful recovery update. The old file's first/last and each new file's
first/middle/last samples show no partial publication. These samples are not
an exhaustive proof over every name.

The four EOF cases prove that failure occurred after the entire source was
staged, rather than testing only early staging failure. ENOMEM is counted
before client probes, so probe allocations are excluded. Syscall evidence
alone does not identify whether that failed allocation belonged to the
working-copy or publication-copy step.

Exact C fully adopted each new generation in five cases. At 6000 rows/+256 KiB,
C reported 2644 ENOMEMs, exposed partial hosts samples and failed fresh TCP
probes under pressure; configured UDP DNS and DHCP stayed healthy. After
removing the limit, UDP/TCP/DHCP were healthy and the subsequent close-write
recovery succeeded. The driver's general C `passed` flag excludes pressure
TCP health; its separate `pressure_tcp_healthy=false` is retained and is not
reported here as a full TCP pass.

The prior combined Rust ELF was also run at 2000 replacement rows and all
three headrooms. Those three cases passed with two ENOMEMs each and kept the
old generation. This does not establish a new incremental regression before
`1d535cb9`; the reproduced reason for that fix remains the held-TCP full-HUP
failure documented separately.

An unrestricted 2000-to-6000-row positive control passed for both C and fixed
Rust with zero ENOMEM: UDP/new TCP adopted each complete new sampled generation,
held TCP retained the old generation, and DNS/DHCP/recovery stayed healthy.

Raw results, packets, identities, stderr and syscall traces are under:

- `/dev/shm/full-integrated-fix-20261014/private/r2-inotify-2000-ownerfix/`
- `/dev/shm/full-integrated-fix-20261014/private/r2-inotify-6000-ownerfix/`
- `/dev/shm/full-integrated-fix-20261014/private/r2-inotify-2000-before-ownerfix/`
- `/dev/shm/full-integrated-fix-20261014/private/r2-inotify-6000-control/`

The driver and these raw results (excluding reproducible staged rootfs copies)
are also backed up in this worktree's ignored
`private/inotify-ownerfix-20261014/evidence.tar.gz`, SHA-256
`62f5cb862278459084fafa8470fe3a4980a7530b548bd4e7380465a0996ffa6c`.
The later unrestricted control is in the adjacent `control-evidence.tar.gz`,
SHA-256 `cc6d9e8455525553fc50597802142af4793cbc7535b1a4759e538a057e5d7b75`.

## Reproduction

On the Oracle build host, use a fresh output path. This tests both exact C and
the identified fixed ELF; change `--new-rows 2000` to `6000` for the other row set.

```sh
BASE=/dev/shm/full-integrated-fix-20261014/private
TOOLS="$BASE/source-owner-fix/tools/dnsmasq"
OUT="$BASE/acceptance-inotify-2000"
sudo -n env PYTHONPATH="$TOOLS" sh "$TOOLS/run_isolated.sh" \
  python3 "$BASE/tools/full_r2_hosts_recovery_v2.py" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --rust "$BASE/release-owner-fix/dnsmasq-rs" \
  --rust-sha256 d57280b85ddb1d7ad5a861254b739d928a9834bd45147e9c9bbba6163ea3484e \
  --source-commit 1d535cb9bd1499a3c4bae0fc6e76e285a933b5bf \
  --output "$OUT" --services shared --initial-rows 2000 --new-rows 2000 \
  --headroom-kib 256,512,1024 --repeats 1 --held-tcp --hostsdir
```

For the prior Rust control, replace ELF/path/hash/source with the prior combined
identity above, add `--sides rust`, and use a different output directory.
