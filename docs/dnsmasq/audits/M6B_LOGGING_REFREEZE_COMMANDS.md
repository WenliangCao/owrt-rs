# M6b logging reclose: exact selectors and new source binding

This is a local read-only audit at main `e6c0152c`, not a test execution. No
Oracle command or product build was performed by this agent. The existing
`E/M6B/pair-service-fixes-01/run-logging-targeted.sh` remains retained evidence.
Its selector is valid and selects exactly five scenarios, but its
`3c66651d…` / `7128d3b6…` product identity is the earlier candidate and must not
be reported as qualification of the new ACL-fixed pair.

## Inputs checked locally

The source archive PAX comments and build receipts in
`E/M6B/pair-udp-acl-01/` identify:

| Group | Source | opt3 ELF SHA256 | Bytes |
| --- | --- | --- | ---: |
| No A | `e8b1d6c411fba324888e3e202c0c133156afbed4` | `2326f4e104c6ea2c13bfd410335356bb34094db532272c92d8884352bb50becc` | 1,953,832 |
| A | `69bccf2738f2c07cbc6d8b8a950015d4cea10af3` | `21937fa33b2552801278ea6cb15f0e13cb733824e4cd236382f968a1c1c4324b` | 1,962,024 |

Both receipts say release, feature-off and opt-level 3. These are local receipt
observations; root must still check the actual remote artifacts before running.
Use the No-A source's tools for **both** product groups. The A source embeds an
older logging driver (`4d62a5e1…`), which still uses the old pipe selector.
The No-A source, current main and `tools-logging-8f.tar` have the same corrected
logging driver SHA `ec651fb4c0d8756a55f90a51d2db946720568049c0b8453b7a04c18625fec07d`.
The four dependency files were also individually compared between the 8f
archive and current main and are identical. The requirements SHA remains
`732d72afb17b11e228de8be5cf964ed8b13739e1df6f6908880f3e848cde8e63`.

## Targeted reclose: five cases, no scope truncation

| Scenario | Actual scope | Retained strict requirements |
| --- | --- | --- |
| `query-stale-producers` | `query-control` | Correct stale TTL-zero responses; C/R complete normalized log equality, including UDP 106 Forwarded with background context. Refresh upstream intentionally does not reply. |
| `query-stale-refresh-context` | `query-control` | Same stale answers/log equality plus `UDP 106 reply …` and `TCP 107 reply …`; complete response/content comparison. |
| `startup-fault-error-pipe` | `startup-fault` | AArch64 pipe2 syscall 59, EMFILE=24, exit 5, not ready, no forced termination; startup diagnostic bytes compared. |
| `startup-fault-error-pipe-flags` | `startup-fault` | Actual selected error writer F_SETFL at syscall 25, EIO=5, exit 5, not ready, no forced termination. |
| `startup-error-frame-interrupt` | `startup-fault` | Actual selected error writer writev at syscall 66, EINTR=4, follow exactly two children, exit 3, not ready, no forced termination. |

The old script's additional `query-transactions,error-frame` scopes are valid
but unnecessary: the `--scenarios` intersection still selects all five above.
The minimal exact scopes are `query-control,startup-fault`. An unknown selected
ID is rejected by the driver; it must not be changed to a broad fallback.
Every startup fault returns from tracing only after injection; failure to reach
the syscall is an infrastructure failure even if the program's ordinary error
message would otherwise match. No scenario-specific log normalization or
error/exit relaxation was added for these five scenarios.

Root may run the following A reclose command in a new remote script, keeping the
old script and attempt intact. It runs **five paired cases**, hence ten C/Rust
program invocations. A separate No-A reclose is another five paired cases, not
part of the same evidence count. `P` and `T` are the verified new pair and
corrected common tools; `O/pair` must not exist.

```sh
set -eu
P=/home/ubuntu/dnsmasq-m6b-20261007/pair-udp-acl-01
T="$P/noa/source/tools/dnsmasq"
O="$P/noa/private/logging-targeted-e8b1-69bc-01"
mkdir -p "$O"
sudo -n sh "$T/run_isolated.sh" python3 "$T/m5_logging.py" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --rust "$P/a/private/opt3/dnsmasq-rs" \
  --rust-sha256 21937fa33b2552801278ea6cb15f0e13cb733824e4cd236382f968a1c1c4324b \
  --source-commit 69bccf2738f2c07cbc6d8b8a950015d4cea10af3 \
  --output "$O/pair" --scopes query-control,startup-fault \
  --scenarios query-stale-producers,query-stale-refresh-context,startup-fault-error-pipe,startup-fault-error-pipe-flags,startup-error-frame-interrupt \
  > "$O/run.log" 2>&1 </dev/null
```

For the separate No-A run, keep `T`, replace `--rust` with
`"$P/noa/private/opt3/dnsmasq-rs"`, use the No-A source/SHA from the table and a
different fresh output `"$P/noa/private/logging-targeted-e8b1-01/pair"`.
Do not overwrite either existing successful or failed attempt.

## Complete logging-all-scopes reclose

Current `m5_logging.cases()` and the canonical `logging-all-scopes` family have
exactly the same **329 scenario IDs**, with no missing or extra IDs. All 34
scope names are listed below. Do not omit `--scopes`: the driver's default is
only `sink,cli,identity`, not the full family. Do not carry `--scenarios` into
the full replay.

```sh
set -eu
P=/home/ubuntu/dnsmasq-m6b-20261007/pair-udp-acl-01
T="$P/noa/source/tools/dnsmasq"
O="$P/noa/private/logging-all-scopes-69bc-01"
mkdir -p "$O"
sudo -n sh "$T/run_isolated.sh" python3 "$T/m5_logging.py" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --rust "$P/a/private/opt3/dnsmasq-rs" \
  --rust-sha256 21937fa33b2552801278ea6cb15f0e13cb733824e4cd236382f968a1c1c4324b \
  --source-commit 69bccf2738f2c07cbc6d8b8a950015d4cea10af3 \
  --output "$O/pair" \
  --scopes async,async-overflow,async-recovery,async-tcp-queue,async-transport,blocked-sink,cli,credential-fault,daemon,debug,dhcp-packets,dhcp-quiet-delay,error-frame,helper-inheritance,identity,identity-full,ownership-warning,query-control,query-dhcp,query-extreme,query-forward,query-local,query-policy,query-reference,query-transactions,root-access,script-logs,scriptuser-boundary,server-logs,sink,sink-fault,startup-fault,startup-output,tftp-logs \
  > "$O/run.log" 2>&1 </dev/null
```

This is 329 paired scenarios / 658 C-and-Rust program invocations. It is the
primary logging family only: the separate canonical DHCP companion and ID-wrap
families remain required and are not replaced by its successful result.
In particular, `log-dhcp` includes external companion scenario mappings, so
primary `closed` alone is not a complete logging-family acceptance claim.

After each run, root must verify `result.json`: exact distinct selected ID
inventory (5 targeted, or the canonical 329 full), `failures=[]`, every row's
`failures=[]`, `reference_only=false`, exact source/Rust SHA, and C SHA
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
Check each startup `fault.json` has `injected=true`, the unchanged injected errno,
correct actual caller/writer, and expected process depth. Reuse neither an old
five-case result nor the original 329 ae1 run as new-source qualification.
Return all new raw results and final state, verify full metadata locally, then
prune the corresponding remote raw; retain the failed first attempts separately.
