# Privacy history migration — 2026-10-20

The owner authorized removal of personal identifiers from the current files and
Git history, followed by publication in a new, independent `WenliangCao/owrt-rs`
repository. The original repository stays private. The original history and
uncommitted work were backed up outside this repository, with restricted
permissions, before rewriting.

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

All 10 existing releases are migrated with their 113 attachments, preserving
every attachment byte and SHA256. Release notes retain original build identities
and add an original-to-sanitized tag commit notice. Links to migrated source and
release content use the new repository; old CI run IDs remain archival evidence.
GitHub assigns new release/asset IDs and publication timestamps; the migration
notes record the original release dates.
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

The original repository retained a read-only `refs/pull/1/head` and cached old
commits after its branches and tags were rewritten. The owner chose to retain
that repository privately and publish through a newly created repository instead
of depending on removal of GitHub's old PR/cache objects.

The public repository is independent, not a fork or GitHub repository import.
Only the sanitized main branch, 408 existing tags, and the audited release assets
are transferred. Old PRs, Actions runs, local archive refs, backups and private
configuration are not transferred. The original repository remains private.

Publication checks cover every object fetched from the new repository, known
sensitive old object IDs, and anonymous access to the original PR/commit paths.
Keeping an original SHA as text in an evidence manifest or commit map does not
transfer the corresponding original Git object. Current build tooling also maps
the legacy release repository name to `WenliangCao/owrt-rs` for profile downloads;
frozen manifests, filenames, profile sizes and digest checks remain unchanged.
The download alias and existing source/provenance checks passed all 55 Python
tests on the remote Linux host before publication.

See GitHub's [sensitive-data removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

## Other clones

Do not merge or push the original ancestry back into this repository. Preserve
needed local changes outside Git, then use a fresh clone of the sanitized history.
Keep the original backup private. Ignoring a folder does not hide tracked files
or historical versions, and a public repository cannot have private subfolders.
