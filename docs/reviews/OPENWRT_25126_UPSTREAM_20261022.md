# OpenWrt 25.12.6 upstream compatibility review

Recorded: 2026-10-22. Scope: official release evidence and source comparison against
the project's pinned 25.12.5 baseline; no physical-router access or Rust build.

The necessary application changes are concentrated in **rpcd filesystem/session
security and uhttpd parsing/security**. Most replacement components have identical
upstream source. The retained kernel, Wi-Fi, TLS libraries, CGI helper and LuCI
must come from the new release when qualifying a 25.12.6 image; changing a version
string or reusing the 25.12.5 binary hashes would not establish that qualification.

## Official evidence and immutable identities

- [Release announcement](https://lists.openwrt.org/pipermail/openwrt-announce/2026-October/000090.html):
  released **2026-10-18**, sixth service release.
- [Release notes](https://openwrt.org/releases/25.12/notes-25.12.6) and
  [complete changelog](https://openwrt.org/releases/25.12/changelog-25.12.6).
  The wiki's `?do=export_raw` endpoint provides the source text when the normal
  HTML returns an Anubis challenge.
- [Buildroot comparison](https://github.com/openwrt/openwrt/compare/v25.12.5...v25.12.6),
  checked using both complete Git trees, including package files and patches.
  A GitHub compare API response can truncate the file list at 300 files; it was
  not used as proof that a component was unchanged.
- [Filogic version](https://downloads.openwrt.org/releases/25.12.6/targets/mediatek/filogic/version.buildinfo),
  [feeds](https://downloads.openwrt.org/releases/25.12.6/targets/mediatek/filogic/feeds.buildinfo),
  [package manifest](https://downloads.openwrt.org/releases/25.12.6/targets/mediatek/filogic/openwrt-25.12.6-mediatek-filogic.manifest),
  [published checksums](https://downloads.openwrt.org/releases/25.12.6/targets/mediatek/filogic/sha256sums).

| Identity | 25.12.5 | 25.12.6 |
| --- | --- | --- |
| Annotated tag object | `e20bc3ec9eb9e3dbd0519ddc18f81f3eedc0f45e` | `22dd0e28678a6cd6fbadea2d5aaded3a805ab8a4` |
| Tag commit | `f0a60eee2fe051741c643ea6118718aae1ef17fb` | `64900e756efa667774214f9c6b17c113222e01f7` |
| Image revision | `r33051-f5dae5ece4` | `r33311-981c978eff` |
| Image revision commit | `f5dae5ece4805730c5e2850f8aa84765af2f6b32` | `981c978eff636fc7d81f0ed17b00e2a6317c949a` |
| Source date epoch | `1782737960` | `1792273538` |
| Packages feed | `5caa62e0bc9f7fb9b0c12a23267bceb7724214dd` | `093d551675b1119a06ef224d419905e8d6b2af1a` |
| LuCI feed | `128a7812f4be233c5dd7f7466f534fd888785caf` | `75a306df84a020c57a631ef5b4c02ace56d93387` |
| Routing feed | `3d7d0dc7fa43d3eb09498417407e95a6552e5312` | `48c808034414a2112cf9d5261a20a320e8d0d170` |

Telephony remains `2618106d5846a4a542fdf5809f0d3ed228ce439b`; video remains
`094bf58da6682f895255a35a84349a79dab4bf95`. The tag commit and image revision
are intentionally different, as in the existing baseline. A signed tag was
retrieved, but this source review does not claim cryptographic signature verification.

Published SHA-256 values (metadata evidence; not a claim of downloaded artifact verification):

| 25.12.6 Filogic artifact | SHA-256 |
| --- | --- |
| Stock `xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin` | `286dbbaf16588c22daeaf6dbc8ca02573a1c30fbeb8592e3ba58b865c8726043` |
| Linux x86_64 SDK, GCC 14.3.0 / musl | `1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e` |
| Linux x86_64 ImageBuilder | `8ce0da1e2fb3d0454ebeb1e3df5705f2145e09ffe6f00d5077c18369719daf83` |

## Replacement-component matrix

“Unchanged” below means the complete relevant buildroot package directory is
identical between release tags, including recipe, patches, init files and ACLs.
It does not imply that two rebuilt ELF files must have identical hashes.

| Project component / dependency | Upstream evidence | Required response |
| --- | --- | --- |
| `rpcd` | `28faf6403792d25b9826043aaf37880624c19568` → `d99f703e4035d03fbcfbada3cb697db346c2b984` | Apply equivalent file ACL and session-directory security fixes; test empty-file reads and reload/apply/rollback compatibility. |
| `httpd` / uhttpd | `7b1bec45826bd78c8afc993435bdc0f1df2fe399` → `373145f72c884c36a2b16f7f47e74ffae06bd754` | Review every changed HTTP/ubus boundary against the Rust implementation; preserve safe existing behavior and cover changed input cases. |
| `netifd` | C source stays `cbb83a1857407a28a63dc09412a1f209195914ef`; package r1 → r2 | New retained DHCP script declares `sendclientid`; verify dynamic schema discovery, UCI forwarding and helper lifecycle. |
| `procd` | Unchanged, `58eb263d5abe03f8c1280bdfa65a3b052614215d` | Existing lifecycle, jail and ubus contract remains the reference. |
| `reload-config` | `package/system/procd/files/reload_config` unchanged | Keep existing implementation; no upstream-triggered redesign. |
| `ubus`, `ubusd` | Unchanged, `24864e7840b3a02a9ef76284a373f6b2f00b8a9b`, ABI `20251202` | Keep protocol/ACL compatibility tests. |
| `uci` | Unchanged, `66127cd76c5d0bd46d5a90302cc6110f53a4e2f8`, ABI `20250120` | Session-directory changes belong in rpcd; UCI file/delta format does not change. |
| `fw4` | Unchanged, `b6e5157527d361f99ad52eaa6da273cb0f2dfd59`, r2 | No new ruleset semantics from upstream; retain kernel/nftables integration checks. |
| `odhcpd` | Unchanged, `5d7be43f8b9dec0eb47e245cfab81108bb131273` | Keep IPv6/RA/lease compatibility tests. Do not confuse server with changed `odhcp6c` client scripts. |
| `dnsmasq` | Entire directory unchanged, `2.93-r1`, including init script and ACL | Preserve the existing reference and PGO evidence; do not requalify old training as a new image result. |
| `logd` / ubox | Unchanged, `6f78fa496bf36c55864a41e353df7d13f04b1077` | No upstream-required rewrite. LuCI fixes log escaping at the producer. |
| Shared `platform`, dnsmasq `platform` | No standalone OpenWrt counterpart; toolchain directory and musl recipe unchanged | Run Linux syscall/FFI tests with the new SDK/image; no inferred API rewrite. |
| libubox | Unchanged, `7dd127841e82eb1cfb61185da37dde7b9bd9ba6d`, ABI `20260213` | No blob/uloop ABI migration. |
| ucode | Commit stays `85922056ef7abeace3cca3ab28bc1ac2d88e31b1`; r1 → r2 | Added const-pointer compiler patch explicitly has no behavioral change; retain updated package. |

### rpcd security and compatibility details

The [complete pinned rpcd diff](https://github.com/openwrt/rpcd/compare/28faf6403792d25b9826043aaf37880624c19568...d99f703e4035d03fbcfbada3cb697db346c2b984)
contains four changes:

- `e37ed9d`: check the lexical ACL and the resolved symlink target for operations
  that follow links; resolve the parent for a new file, reject dangling final
  symlinks, and operate on the authorized resolved path. Preserve link-oriented
  behavior for methods that intentionally use `lstat`/unlink. Relevant advisory:
  [GHSA-q5gr-86pq-vvwr](https://github.com/openwrt/openwrt/security/advisories/GHSA-q5gr-86pq-vvwr).
- `4062f66`: reading an empty file returns empty data successfully.
- `a6c6b63`: compatibility guard for newer ucode module loading, not a changed
  JSON/ubus method contract in this pinned ucode version.
- `d99f703`: generate a separate random runtime dirname per session. Use it for
  `uci-*` and frozen-session filenames; do not expose the bearer SID in paths.
  Restore dirname from the freeze filename, including old-format files, so staged
  UCI deltas survive reload. Resolve dirname without extending session lifetime.
  Apply, rollback and destroy must use the same mapping. Relevant advisory:
  [GHSA-r2w2-q7cw-cfp2](https://github.com/openwrt/openwrt/security/advisories/GHSA-r2w2-q7cw-cfp2).

The paired [LuCI ACL correction](https://github.com/openwrt/luci/commit/58d43e57af916e4f140e758d0fa2524582d383ff)
adds `/proc/*/mounts` to `luci-mod-system`, alongside `/proc/mounts`.
This is necessary because `/proc/mounts` resolves through `/proc/self` to the
process-specific file. Other optional apps similarly add resolved `/proc` or
`/tmp/run` paths. Do not weaken the security check to compensate for obsolete ACLs.

### uhttpd security and compatibility details

The [pinned uhttpd comparison](https://github.com/openwrt/uhttpd/compare/7b1bec45826bd78c8afc993435bdc0f1df2fe399...373145f72c884c36a2b16f7f47e74ffae06bd754)
changes cumulative header count/byte limits, header-name validation and value
whitespace trimming; strict chunk size parsing, chunk CRLF and trailer handling;
closing connections with unread bodies; `/ubus/call/` parameter type checks;
non-POST URL cleanup and subscribe reference ownership; and Basic Auth for
URL-prefix handlers. Also review symlink-based MIME lookup, `TCP_NODELAY`,
`IP_FREEBIND`, SNI redirects and Lua buffered I/O against the implemented feature
boundary. C memory-lifetime defects do not automatically imply equivalent Rust
defects, but request behavior and resource bounds still require tests.

The release announcement links all six published uhttpd advisories, including
[header exhaustion](https://github.com/openwrt/uhttpd/security/advisories/GHSA-vhx4-3p5q-m59q),
[request smuggling](https://github.com/openwrt/uhttpd/security/advisories/GHSA-c2wg-hcff-hqrm)
and [prefix-handler authentication](https://github.com/openwrt/uhttpd/security/advisories/GHSA-5cgm-8h9x-v28c).
The announcement says “five” advisories but enumerates six; the review uses the
enumerated changes and source, rather than that count.

## Retained execution plane, callers and image integration

| Area | Confirmed delta and consequence |
| --- | --- |
| DHCPv4/v6 clients | `sendclientid=auto` preserves 25.12.5 behavior: explicit client ID, otherwise device DUID, otherwise hardware ID. `global` ignores explicit ID; `hardware` chooses the interface MAC/DUID-LL; IPv4 additionally supports `none` (`udhcpc -C`). Retain upstream scripts rather than duplicating these choices in Rust. `odhcp6c` changes `07d324ee...` → `10a52220aec9d45803518d8cc4d63e552484ed61` (const-pointer correction), r1 → r3. |
| Wi-Fi scripts / LuCI wireless UI | `sae`/`sae-mixed` stop advertising GCMP-256 and SAE-EXT-KEY by default; remove `rsn_override`, add `gcmp256`, `sae_ext_key`, `sae-compat`, `transition_disable`. PMF enables supported beacon protection; default SAE groups become 19/20/21. 6 GHz uses H2E-only and WPA3 constraints. EAP phase2, certificate constraints, old private-key aliases and integer `multicast_to_unicast` handling are fixed. Keep the matched script/schema/UI set together. |
| hostapd / wpad | Same base revision, package r6 with new MLO bounds checks, APuP NULL handling, Mbed TLS certificate/EAP-TLS fixes, beacon-report ubus details. AX3000T is Wi-Fi 6, so AP-mode Wi-Fi 7-only defects are not its direct exposure; preserve the full maintained package. |
| Kernel / Wi-Fi drivers | Linux `6.12.94` → `6.12.112`; mac80211 `6.18.26` → `6.18.55`. mt76 base commit stays `39c960c3ada558b4c2e7915772483d3731573d09`, r2 → r3 with extensive backports, including mt7915 EEPROM bounds, HE checks, retry accounting, RX/TX/WED and lifecycle fixes. These are execution-plane updates, not a reason to replace hardware drivers. |
| AX3000T stock layout | `mt7981b-xiaomi-mi-router-ax3000t.dts`, its `.dtsi` and common Xiaomi `.dtsi` are unchanged. Board-specific network defaults and stock image recipe are unchanged. `platform.sh` adds `CI_DATA_UBIPART=ubi` alongside kernel `ubi_kernel` and root `ubi`, matching `nand.sh` support for a distinct data partition. Preserve stock bootloader/AN8855 scope and reject the ubootmod profile. |
| Generic base-files | NAND helpers separate kernel/root/data UBI selection and add an optional kernel-MTD name-collision override. Button handlers can be omitted at build time; defaults remain enabled. `reload_config` is in procd and is unchanged. |
| TLS / certificates | Mbed TLS `3.6.6` → `3.6.7`, OpenSSL `3.5.7` → `3.5.9`, wolfSSL `5.9.1` → `5.9.4`, CA bundle `20260601` → `20260816`; security updates listed in the announcement. Rust HTTP uses rustls, but retained wpad and other packages still depend on system TLS. Include applicable packages from the new release. |
| CGI upload/download/backup/exec | cgi-io `7314451cb99692c0862a70c3307ee08bd2fbd9c0` → `31cb3c89f02d918d7f17bf62a80c852fc38a1ca1`: malformed form decoding now clears field pointers and returns HTTP 400 before use. This is a retained executable reached through the Rust web server. [Source diff](https://github.com/openwrt/cgi-io/compare/7314451cb99692c0862a70c3307ee08bd2fbd9c0...31cb3c89f02d918d7f17bf62a80c852fc38a1ca1). |
| LuCI / rpcd plugins | Pinned feed diff: `libs/` unchanged (including rpcd-mod-luci/rrdns source); main changes are paired file ACLs, login-log escaping, wireless/DHCP options, UI fixes and translations. Updated `dispatcher.uc` escapes user/path values before logging; this belongs in the caller, not logd filtering. |
| iwinfo / PPP / optional network | iwinfo scan-buffer corruption fixed; PPP on-demand precompiled-filter option fixed. QMI/MBIM now report DNS with peerdns disabled. Optional umdns security fixes and optional app fixes are relevant only when installed; do not label them as implemented Rust components. |
| Toolchain / native interface | Complete `toolchain/` tree unchanged; new SDK still GCC `14.3.0`, image musl `1.2.5-r5`. This reduces ABI migration risk but does not substitute for new SDK hashes and Linux tests. |

Source-relevant Wi-Fi changes are in
[wifi-scripts at the release tag](https://github.com/openwrt/openwrt/tree/v25.12.6/package/network/config/wifi-scripts).
Hardware changes are in
[mt76 patches](https://github.com/openwrt/openwrt/tree/v25.12.6/package/kernel/mt76/patches),
[NAND helpers](https://github.com/openwrt/openwrt/blob/v25.12.6/package/base-files/files/lib/upgrade/nand.sh)
and [Filogic upgrade dispatch](https://github.com/openwrt/openwrt/blob/v25.12.6/target/linux/mediatek/filogic/base-files/lib/upgrade/platform.sh).

## Qualification boundary

This report establishes upstream identities and changes, not a runtime verdict.
Required tests are the specific security boundary regressions above, existing
component tests on Linux through `mbx`, and image integration against independently
verified 25.12.6 artifacts. New negative security expectations intentionally
supersede unsafe 25.12.5 behavior; safe requests should remain compatible.

Keep old source/image/runtime reports and frozen PGO evidence immutable. A new
release candidate needs its own image inventory, replaced-file hashes, retained
package versions, package ownership/dependencies and SDK identity. Hardware health,
Wi-Fi reassociation and rollback are not proven by source inspection or host tests.
No deployment or flashing is authorized by this review.
