# Frozen target package checkpoint: 574f5ed

The inert target package built and passed the scoped checks below. This is an
intermediate artifact, not a completed rewrite or production acceptance.
Resource acceptance remains open: the Rust ELF is **720,686 bytes larger
(+267.6%)** than the exact image's C ELF. Keeping the package inert does not
exempt that regression from the optimization target.

The product input is committed snapshot
`574f5ed88d8d3c9453f0ac9c25a891933b5a128b`, with declared epoch `1790806621`.
The initial 77-file input digest was
`629ac5abdeaa1345005b857dcb30775678ec139b13969eaa1acc1c70a2b0d4d0`.
The first SDK invocation completed, but revealed that the SDK scans hidden
recipe backups beneath `package/`. Tool-only fix `95f7347` moves that recovery
copy to the SDK root. The rebuilt snapshot changes exactly one build input,
`build_package.py`; all 76 other input hashes, including every product source,
are unchanged. Its input digest is
`fcda4758a24571c561779a1b6cf3229606cdfa82b1a0174ebff0ce3d7752fa64`.

The SDK archive is the pinned OpenWrt 25.12.5 mediatek/filogic GCC 14.3.0 musl
SDK (`ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25`).
Explicit prepare copied the frozen inputs and every copied file hash matched.
The SDK's original package recipe was restored after both runs.

| Artifact | Final result |
| --- | --- |
| APK | `owrt-dnsmasq-0.1.0-r1.apk`, 520,797 bytes |
| APK SHA256 | `2c1ae3a6cb04bf9ed190422c7ec5d57b42eefe7c99377143c8a07702073f75a5` |
| Rust ELF | AArch64 static EXEC, 989,991 bytes |
| Rust ELF SHA256 | `e88fc9131b8321fef7d913fd052ec7ce06af5eebddb38f41621b3d1478f8090e` |
| Installed executable | `/usr/libexec/dnsmasq-rs`, root:root, mode 0755 |
| Other regular payload | APK ownership list, root:root, mode 0644; lists only that executable |
| Package activation | Inert; no stock binary/init/UCI replacement |

The final run retains 181 warning lines, including SDK Kconfig/dependency
discovery warnings and host `runas.so`/`libfakeroot.so` preload warnings. Tool
and linker exits, source checks, package extraction, ownership/mode metadata and
ELF identity were verified despite those warnings. The obsolete backup-recipe
discovery warning is absent from the second run. Full warning text remains in
private logs; this is not a warning-free build claim.

The two output directories produced different APK and ELF hashes, although both
ELFs are 989,991 bytes and the product source hashes match. The first output is
retained as a superseded attempt. Bit-for-bit reproducibility across task build
paths/tooling is not established; no additional build loop was run to disguise
that result.

The exact target C reference was obtained read-only from the existing canonical
image extraction. All five files also match the independent stock extraction
and the already-recorded ROM hash observation; no router was contacted. The
canonical image SHA256 is
`144c1283da1fb3ead5e4ee7b8b55f66b7d9e872f785892f87cadf9fca6ed0720`.

| Target C file | Bytes |
| --- | ---: |
| `usr/sbin/dnsmasq` | 269,305 |
| `lib/libc.so` (also the musl loader) | 590,852 |
| `lib/libubus.so.20251202` | 28,834 |
| `lib/libubox.so.20260213` | 65,633 |
| `lib/libgcc_s.so.1` | 131,088 |

The C ELF SHA256 is
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
It is AArch64 PIE with those four dynamic dependencies. Its feature string
matches dnsmasq 2.93 nodhcpv6. The private runner explicitly invokes the copied
musl loader with the copied library directory; dependency resolution and all
library hashes are recorded. The shared libraries total 816,407 bytes, but are
needed by other platform components and cannot be counted as exclusive space
saved by Rust. The comparison above reports ELF bodies separately; it does not
charge the entire shared-library closure solely to C.

The SDK Rust artifact was executed on the AArch64 build host in isolated
loopback-only namespaces. Initial checks used the audited native glibc C oracle
and are labeled cross-ABI evidence. The following critical gates were then run
against the exact target C ELF and its image libraries:

| Gate | Final result |
| --- | --- |
| UDP no-route REFUSED | 558 compared requests; zero mismatches |
| TCP daemon | 15 scenarios / 116 replies; zero mismatches |
| DNS reload/cache/hosts lifecycle | 23 checks; zero mismatches |
| TCP hosts snapshots across SIGHUP | 8 compared queries and 2 shutdowns matched |
| DHCP daemon smoke, Rust target ELF only | 5 checks passed; no full C service-equivalence claim |

The UDP tool initially rejected the target runner because its default identity
pin intentionally accepts only the native C ELF. Test-tool change `06cae43`
adds an optional strict target identity check: all five pinned image-file hashes
and the exact loader command must match. The same UDP corpus then passed; its
first rejected invocation is retained, not counted as a protocol pass.

The frozen Rust host test binaries also ran in private Linux namespaces: the
library reported 278 passed / 13 ignored, and main reported 6 passed. Twelve
ignored tests were explicitly run next: four exact-C configuration tests and
eight Linux socket/interface tests, all passing. The four configuration tests
were additionally run with the target musl C parser/getopt reference and passed.
The one remaining cache-oracle driver was not run here without its dedicated
corpus/comparator; no pass is claimed for it by this checkpoint.

Evidence is indexed under ignored
`private/dnsmasq-rewrite/package-574f5ed-stage/`: `attempt-01/`, `attempt-02/`,
`native-tests/`, `target-c-reference/`, the original `target-574f5ed-*`
cross-ABI runs, and `target-pair-574f5ed-*` target-artifact runs. The C wrapper
hash in paired reports identifies the invocation script; the reference identity
manifest separately identifies its actual ELF and libraries. Both APKs, ELFs,
all substantive logs/configuration/packets and final hashes were recovered and
checked locally. Intermediate SDK build trees remain in the task-owned remote
private directories. The two source freezes and the failed initial tooling-copy
attempt are retained separately.

These checks establish only the listed offline behavior. Static Rust and dynamic
C do not have identical dependency linkage. No emulator/router kernel, physical
router, production lifecycle or target-router performance acceptance is claimed.
Missing functionality and the ELF-size regression remain delivery blockers;
this checkpoint provides no throughput, CPU or memory optimization conclusion.
