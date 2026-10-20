# Privacy history migration — 2026-10-20

The repository remains **private**. This is not authorization to publish it.
The owner authorized removal of personal identifiers from the current files and
Git history. The original history and uncommitted work were backed up outside
this repository, with restricted permissions, before rewriting.

## Changes

- Replaced the private author/committer email with the GitHub noreply identity.
- Replaced actual device MAC values and a related test address with synthetic
  values, including the corresponding numeric test arrays.
- Replaced the observed Wi-Fi name and personal home-directory prefixes.
- Rewrote commit and tag ancestry while retaining commit timestamps and original
  evidence identifiers inside manifests and reports.
- Retired two obsolete local Codex tree checkpoints after preserving their
  original refs in the offline backup. These direct tree refs require separate
  handling because normal commit-history filtering does not rewrite them.

The main snapshot has exactly 47 changed files from redaction. Production Rust
behavior is unchanged; only netifd test inputs and expected values changed.
The complete local commit map contains 7,231 original commits, of which 7,054
changed identity. The remote publication scope is the existing main branch and
408 tags; additional local archive refs are not uploaded.

## Source and release identity

The [commit map](commit-map-20261020.txt) maps original evidence IDs to sanitized
Git IDs. See [usage](README.md). Current build tooling resolves Git lookups through
this map while keeping the original accepted-product identity in build reports.
Source-file digests, epochs, PGO profile identities and ELF checks remain enforced.
Unknown IDs are passed to Git normally; mapping never permits a digest mismatch.

Both frozen DNS source closures contain 212 files and retain their exact recorded
SHA256 digests and epochs after extraction from sanitized Git objects. None of the
redacted files belongs to those closures. Original source manifests, PGO plans,
profiles and uploaded release attachments are not rebuilt or replaced.

All 10 existing releases retain their 113 uploaded attachments. Release notes add
an original-to-sanitized tag commit notice without replacing their original text.
GitHub-generated source archives necessarily follow the rewritten tags. Old tags'
original tooling is historical evidence; use current tooling and the map to
resolve old source IDs, rather than assuming every historical workflow is updated.

## Verification and remaining hosting boundary

An independent scan of every stored object in the sanitized full-ref mirror
covered 53,670 objects with zero matches for the known private identifiers,
including numeric MAC arrays and checked alternate encodings. Current tree
comparison verified every file equals the intended redaction and preserves its
path, mode and type. Gitleaks reported 607 candidates, all matching previously
reviewed false-positive contexts; there were no new candidate contexts.

On the remote Linux host, 54 Python provenance/image checks and all 175 netifd
Rust tests passed, with no failures or skipped tests. No Rust build ran on the
Mac, and no physical router was accessed during this cleanup.

The earlier [full privacy audit](../reviews/PRE_PUBLIC_PRIVACY_20261020.md) covered
release attachments, Actions logs and artifacts, and PR content. It found no
confirmed actual private key, access token, password or personal server address.
Scanning is bounded to the documented indicators and formats, not proof against
arbitrary unknown or obfuscated secrets.

GitHub's read-only `refs/pull/1/head` retains the old PR ancestry, which contains
device identifiers. Force-updating branches and tags cannot remove that ref or
cached old commit views. A concrete Support request and affected commit list are
prepared privately outside this repository. No request has been sent. GitHub
Support decides whether this personal-information cleanup qualifies for removal.
The repository must remain private pending resolution of that boundary and a
separate decision by the owner to publish.

See GitHub's [sensitive-data removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

## Other clones

Do not merge or push the original ancestry back into this repository. Preserve
needed local changes outside Git, then use a fresh clone of the sanitized history.
Keep the original backup private. Ignoring a folder does not hide tracked files
or historical versions, and a public repository cannot have private subfolders.
