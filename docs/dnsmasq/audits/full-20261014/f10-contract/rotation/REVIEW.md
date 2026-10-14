# F10 candidate: warmed and rolling TCP memory/order

Product: `b99eae7e54c1d3922368513714da2eaef09cef58`; Oracle ELF
`/dev/shm/full-f10-product-20261014/private/release-b99e/dnsmasq-rs`,
SHA-256 `edf0f62ca08946cd35aa5b48255575546baaec53d3273723fb25550eb14e5fac`,
2,130,400 bytes. The exact-image C SHA is
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.

All three fresh runs use 30,000 names / 60,000 hosts records, parent warmup,
20 held TCP clients, one 64 MiB cgroup for the daemon and all C children,
and swap disabled. Rolling cases then perform 2,000 accept-before-drop cycles.
Only isolated Oracle namespaces were used. No product changes or router work.

| Case | C peak bytes | Rust peak bytes | Rust parent-warm → 20-client PSS KiB | Rust rolling start/end PSS KiB |
| --- | ---: | ---: | --- | --- |
| Warm repeated addresses | 16,510,976 | 28,577,792 | 27,372 → 28,852 | — |
| Original repeated-address rolling | 16,842,752 | 28,487,680 | 27,448 → 28,928 | 27,652 / 27,652 |
| Unique-address rolling | 16,547,840 | 36,511,744 | 35,328 → 36,804 | 35,528 / 35,528 |

Each side completes 20/20 connections, subsequent UDP and all rolling queries,
with no OOM/kill, empty cgroup at cleanup and successful cgroup removal. The
20-client Rust PSS increments are 1,480, 1,480 and 1,476 KiB. Constant rolling
PSS and those increments support the bounded snapshot behavior for these cases;
they are not an allocation proof, a universal memory bound or throughput results.

The **original repeated-address driver is unchanged**, SHA
`30f7e009761ac96991269823651b17d05aeadcf8d6a798defb6a9318d00aaa8b`.
It previously exposed 188/6,020 fixed/C differences. This fresh candidate run
matches exact C on **all 6,020 raw observations**. Both old failing controls
remain intact: old Rust had 191 differences and old/fixed Rust output was
identical. The fresh result does not rewrite those controls.

Warm and unique use the committed delivery driver SHA
`66f29e7cf865072124b6773d56f3f63cf064cd629ab7e673f769aa924be4a758`.
Warm matches all 20 raw replies. Unique matches the entire 6,020-row relative
sequence, but **three raw replies differ**: `rolling-parent-500`,
`rolling-new-500`, `rolling-old-500`. They are preserved as failures of raw
byte equality. The new C output exactly equals the retained
`final-cgroup64-60k-rolling-unique` C output; the new Rust output equals all three
retained Rust controls. Comparing the other retained C starts produces exactly
those same three differences. Thus these specific order differences have a
direct C/C control; no broad ordering exemption or normalized all-pass claim is
made. This does not establish unrelated PTR ordering or truncation behavior.

Derived metrics and input hashes: [summary.json](summary.json), independently
recomputed by [collect.py](collect.py). [identity-after.json](identity-after.json)
rehashes actual Oracle files and checks only the three output prefixes: no task
processes or host mounts remain. Eighteen copied files in this worktree's ignored
`private/f10-rotation-b99e/oracle` match Oracle hashes; its backup manifest covers
the two evidence archives. Generated stage rootfs directories are excluded.

Oracle output names under `/dev/shm/full-f10-product-20261014/private/`:
`rotation-b99e-warm`, `rotation-b99e-repeated-original`, `rotation-b99e-unique`.
Each holds raw replies, measurements, per-side stderr and an unchanged driver.

Replay on Oracle with a fresh output directory:

```sh
tools=/home/ubuntu/full-audit-20261014/private/source/tools/dnsmasq
rotation=/dev/shm/full-rotation-check-20261014
product=/dev/shm/full-f10-product-20261014/private
sudo -n sh "$tools/run_isolated.sh" env PYTHONPATH="$tools" \
  python3 "$rotation/private/fixed-cgroup64-60k-rolling/driver.py" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --rust "$product/release-b99e/dnsmasq-rs" \
  --output "$product/replay-repeated" --names 30000 --warmup --budget-mib 64 --rolling 2000
```

Warm uses `hosts_rotation_memory-delivery.py` under `$rotation` and omits
`--rolling 2000`. Unique uses that delivery driver with `--rolling 2000
--unique-addresses`. Each must use a new output path. This scope excludes HUP,
inotify, low-memory replacement, DHCP and PTR ordering gates owned by the other
final-candidate checks.
