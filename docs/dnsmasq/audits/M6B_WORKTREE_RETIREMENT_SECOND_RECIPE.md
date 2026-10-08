# M6b 第二批工作树退役配方（待 root 核定）

只读本地Git、工具和已有evidence；未创建tag、归档工作树、删除分支/工作树、
访问Oracle或构建/测试产品。依照既有[M6B退役记录](M6B_WORKTREE_RETIREMENT_20261008.md)
先保全、再复核、最后移除；旧七树preservation/completion不覆盖。

盘点时间 `2026-10-08T10:49:59.833601+00:00`，当时main `62497a16fd89498c55b5e2579415fc80931d929e`；完整路径、tip、状态、
ignored数量/字节、tip tags和git cherry结果在
`E/M6B/worktree-retirement-20261008/second-review-01/inventory.json`，SHA256
`85d6199d2c5ed66f8511b3dd9d248aa08d9279f348ad2227ad3fc1e194c76ca6`。
27棵注册M6b树tracked/untracked均干净。patch-equivalent只是整合证据，不是功能
验收，也不取消原保护指令。执行前重新确认owner已交付且tip/status未变化。

## 可提请root退役的11棵已交付工具/修复树

这11个tip都无patch-unique提交，也都没有精确tip archive tag；每棵须先打新tag。
a-evidence的旧408 tag不能代替156c tip；a-resource-runplan目录当前检出
neighbor-tail-resume，删除必须用下表当前branch。root曾明确保留a-evidence及
reverse两树，仍须由root确认已无owner；候选表不自动解除保留。

| Worktree suffix / branch | Exact tip | Ignored files / bytes | Unique patches |
| --- | --- | ---: | ---: |
| `m6b-a-evidence-review` / `m6b/a-evidence-review` | `156c00975be37f57f5b5c1026c4eee0e85af0f96` | 0 / 0 | 0 |
| `m6b-a-interface-route-final-plan` / `m6b/a-interface-route-final-plan` | `fbc70932d705f84335604ae14e82c3660f01ffef` | 0 / 0 | 0 |
| `m6b-a-resource-runplan` / `m6b/neighbor-tail-resume` | `9acdd16ed01a6d59f6563524f742538395a50064` | 0 / 0 | 0 |
| `m6b-hostsdir-init-finish` / `m6b/hostsdir-init-finish` | `44fb920ddc3a88ea0b3a7c624394dc2d23e91c7b` | 0 / 0 | 0 |
| `m6b-interface-acl-new-caller-tools` / `m6b/interface-acl-new-caller-tools` | `d45562297055e70a12481a425cfeaadd52878832` | 0 / 0 | 0 |
| `m6b-interface-count-stop` / `m6b/interface-count-stop` | `49891caf27568c1d6363aa786078449468cc985d` | 0 / 0 | 0 |
| `m6b-interface-fault-actor` / `m6b/interface-fault-actor` | `bf2daf4c722f089e9f7587c49ef394d1380eab5c` | 9 / 299,063 | 0 |
| `m6b-reverse-cname-family` / `m6b/reverse-cname-family` | `fe1d7e62d096d22a3a9ea2adbbb647c3b8af6e59` | 0 / 0 | 0 |
| `m6b-reverse-import-direction-noa` / `m6b/reverse-import-direction-noa` | `0e7067171633331ed5819507ed6c987dd9aff9fc` | 0 / 0 | 0 |
| `m6b-reverse-order-c-helper` / `m6b/reverse-order-c-helper` | `705897c3f60a148307dc14a64bb08f4d383912ff` | 0 / 0 | 0 |
| `m6b-reverse-order-sidecar-tools` / `m6b/reverse-order-sidecar-tools` | `4990f63f110164020347116ca0881529145e336f` | 0 / 0 | 0 |

interface-fault-actor的9个ignored文件299,063B必须保全；其它10树当前ignored为空，
仍须执行前复查。实际运行证据在主仓库E/M6B，不随worktree删除。

## 额外核对后才能退役的三个实现tip

| Worktree suffix / branch | Exact tip | Ignored files / bytes | Unique patches |
| --- | --- | ---: | ---: |
| `m6b-interface-runnable` / `m6b/interface-runnable` | `c2e39baa3a460277c9d7d55bf37288945671647a` | 1,363 / 504,532,907 | 1 |
| `m6b-newaddr-publication-contract` / `m6b/newaddr-publication-contract` | `ac0d62aad7ba27ab1dd0c7b1e43f4a00ef05d0f7` | 0 / 0 | 1 |
| `m6b-udp-live-acl-admission` / `m6b/udp-live-acl-admission` | `ea2dcc88e0a7937d1254fb6abd82ceb0a967d0ee` | 0 / 0 | 1 |

这三个有patch-unique提交：2c9a17ca是旧interface大补丁；ac0d62aa与root整合版本
不同；ea2dcc88被root按公共main适配为e8b1。root须明确唯一部分已整合、替代或
退休；精确tip tag保存全部历史，另保留committed.patch/cherry结果。
interface-runnable的504,532,907B ignored target不得只留摘要后丢弃。

## 当前不能移除

- 当前A产品：m6b-tcp-a-route-ready / m6b/tcp-a-route-ready，69bccf2738f2c07cbc6d8b8a950015d4cea10af3。
- 活跃agent树：a-current-gate-audit；a-interleaved-pressure目录的当前分支
  **m6b/a-resource-recipe-69bcc**；本logging-triage。本配方合入并root释放owner后，
  logging树才进入下一批，不能按盘点c141旧tip删除。
- a-libtest-adapters / m6b/a-libtest-adapters，880ca97c：root明确保留后继工具修复。
- tcp-a-resource-diagnostic / m6b/tcp-a-resource-diagnostic，f3014683：内部资源门仍需。
- main/主工作树、用户docs/prompts的全部dirty/untracked、非M6b detached树及
  主仓库整个evidence不在此清理范围。

五个route树仍沿用旧记录的保护，直到root明确其未完成route-clears/fault工作
不再依赖checkout；patch-equivalent不自动解除保护。释放后才按同样流程归档：

| Worktree suffix / branch | Exact tip | Ignored files / bytes | Unique patches |
| --- | --- | ---: | ---: |
| `m6b-route-clear-fixture` / `m6b/route-clear-fixture` | `809cb69e5c6e83fba2de61150ed7fc6b786ba9da` | 5 / 336,441 | 0 |
| `m6b-route-resend-caller` / `m6b/route-resend-caller` | `d0e60e7492cdfa14dd07ae235196788c5d7c7bfb` | 5 / 262,891 | 0 |
| `m6b-route-resend-clears` / `m6b/route-resend-clears` | `e0eec388981bb87a1caca49129d53314b0e2b560` | 5 / 307,943 | 0 |
| `m6b-route-resend-fix` / `m6b/route-resend-fix` | `d60d832bfe0f7587f7ebbb2a0c6df9a8c09a5871` | 1,687 / 836,108,175 | 0 |
| `m6b-route-resend-main-caller` / `m6b/route-resend-main-caller` | `629212dab405fd9d8674cc8eb7066f75fbfd03e1` | 1,250 / 348,996,780 | 0 |

两棵旧A产品树也继续保护；root明确释放后可以退物理checkout，但ignored产物
尚不能凭旧tag冒称已归档。保留失败实验，不混入当前A门：

| Worktree suffix / branch | Exact tip | Ignored files / bytes | Unique patches |
| --- | --- | ---: | ---: |
| `m6b-tcp-a-ready` / `m6b/tcp-a-ready` | `def785817531a4c63332888b0507ffb1b7a0743a` | 3,927 / 1,593,293,837 | 13 |
| `m6b-tcp-scheme-a` / `m6b/tcp-scheme-a` | `a9f069a457d5eb3681082875e865cebc45ecbaf5` | 3,016 / 969,874,598 | 6 |

已有精确tip tag：tcp-a-ready为archive/m6b/tcp-a-4816-def78581；tcp-scheme-a为
archive/m6b/tcp-scheme-a-pre-readiness-20261007。所有未合入A历史保持tag可达。

## 三个无注册worktree的旧branch

均patch-equivalent，可在root核定后打精确tip tag再仅删除branch，不能误删复用
相同目录的活跃新分支。

| Branch | Exact tip | Unique patches |
| --- | --- | ---: |
| m6b/a-interleaved-pressure | 053b1939639a982537247701a1231d7757d2c461 | 0 |
| m6b/a-resource-review | 1600dbecc729b7332402be9ce0d0afc8fdfe40a2 | 0 |
| m6b/a-resource-runplan | 8229b7846b83eba9ec5efdeeb1483fd1ab9ad181 | 0 |

## 单树执行步骤

root只执行已核定的一棵，不展开m6b-*通配符。下面以已交付fault actor为例；
任何tip/status/owner变化都停止该树删除，保留收据。

```sh
RETIRE_REPO=/Users/USER/Developer/owrt-control-plane-rs
RETIRE_SUFFIX=interface-fault-actor
RETIRE_BRANCH=m6b/interface-fault-actor
RETIRE_TIP=bf2daf4c722f089e9f7587c49ef394d1380eab5c
RETIRE_WT="$RETIRE_REPO/private/dnsmasq-rewrite/worktrees/m6b-$RETIRE_SUFFIX"
RETIRE_E="$RETIRE_REPO/private/dnsmasq-rewrite/evidence/M6B/worktree-retirement-20261008/approved-second-batch/$RETIRE_SUFFIX"
RETIRE_TAG="archive/m6b/retired-20261008-second-$RETIRE_SUFFIX"
mkdir -p "$RETIRE_E"
test "$(git -C "$RETIRE_WT" rev-parse HEAD)" = "$RETIRE_TIP"
test "$(git -C "$RETIRE_REPO" rev-parse "$RETIRE_BRANCH")" = "$RETIRE_TIP"
test -z "$(git -C "$RETIRE_WT" status --porcelain --untracked-files=all)"
git -C "$RETIRE_WT" status --short --ignored > "$RETIRE_E/status-before.txt"
git -C "$RETIRE_REPO" cherry -v main "$RETIRE_BRANCH" > "$RETIRE_E/cherry-before.txt"
# Existing tags must be verified, never overwritten with -f.
git -C "$RETIRE_REPO" tag "$RETIRE_TAG" "$RETIRE_TIP"
test "$(git -C "$RETIRE_REPO" rev-parse "$RETIRE_TAG^{commit}")" = "$RETIRE_TIP"
git -C "$RETIRE_REPO" diff --binary main..."$RETIRE_BRANCH" > "$RETIRE_E/committed.patch"
```

Ignored为空时精确tag/status/cherry/patch即可；非空须完整metadata保全。本机无
GNU tar，旧Linux pack入口读/proc不适用。下列Mac PAX前端归档整个worktree，
含全部ignored及tracked当时副本/Gitdir指针，使用既有严格inventory/verify。
archive在主evidence，不在待删除树；此配方尚未执行。

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$RETIRE_REPO/tools/dnsmasq" python3 - "$RETIRE_WT" "$RETIRE_E" <<'PY'
import base64, hashlib, json, sys, tarfile
from decimal import Decimal
from pathlib import Path
from m5_option_matrix_archive import inventory, verify
wt, out = map(Path, sys.argv[1:])
archive, manifest = out / 'worktree.tar.gz', out / 'worktree-manifest.json'
assert not archive.exists() and not manifest.exists()
assert wt.is_dir() and not wt.is_symlink() and not out.is_relative_to(wt)
entries = inventory(wt)
with tarfile.open(archive, 'w:gz', format=tarfile.PAX_FORMAT) as tar:
    for relative, expected in entries.items():
        path = wt if relative == '.' else wt / relative
        name = wt.name if relative == '.' else wt.name + '/' + relative
        member = tar.gettarinfo(str(path), arcname=name)
        member.pax_headers['mtime'] = format(Decimal(expected['mtime_ns']) / Decimal(1_000_000_000), 'f')
        for key, value in expected['xattrs'].items():
            member.pax_headers['SCHILY.xattr.' + key] = base64.b64decode(value).decode('utf-8', 'surrogateescape')
        if member.isfile():
            with path.open('rb') as stream: tar.addfile(member, stream)
        else: tar.addfile(member)
assert inventory(wt) == entries, 'worktree changed during archival'
sha = hashlib.sha256()
with archive.open('rb') as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b''): sha.update(block)
report = dict(run=str(wt), prefix=wt.name, archive_name=archive.name,
              archive_sha256=sha.hexdigest(), archive_bytes=archive.stat().st_size,
              entries=entries)
manifest.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
result = verify(archive, manifest, None)
assert result['verified'] is True
(out / 'full-metadata-verification.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
PY
```

root核定收据后重新核对tip/clean/tag；记录remove/delete完整argv、exit和最终状态。
没ignored用正常remove；有ignored只在完整保全复核成功后可单路径force-remove，
不能因默认remove拒绝就直接force，也不由archive脚本递归删除。

```sh
# Exactly one, chosen from the rechecked inventory:
git -C "$RETIRE_REPO" worktree remove "$RETIRE_WT"
# OR only for approved, fully archived ignored-bearing worktree:
# git -C "$RETIRE_REPO" worktree remove --force "$RETIRE_WT"
# After successful remove and a final durable-tag identity check:
git -C "$RETIRE_REPO" branch -D "$RETIRE_BRANCH"
```

最终逐路径确认tree/branch不存在、tag仍可达、受保护树tip/status和用户prompts
status不变。盘点时/private/tmp worktree注册0，prune --dry-run --verbose无输出，
无需全局prune。新失效记录须先保存dry-run、逐条核定，不按年龄清理别的任务。
