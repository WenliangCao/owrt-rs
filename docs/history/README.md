# Source identities after privacy cleanup

The 2026-10-20 privacy rewrite changed Git commit IDs. The accompanying
`commit-map-20261020.txt` preserves the complete original-to-sanitized mapping
produced by `git-filter-repo`, including unchanged commits. It contains IDs only,
not original commit objects or personal metadata.

Historical reports, frozen source manifests, profile asset names, and uploaded
release attachments retain their original identities. A mapped commit is a
sanitized source location; it does not claim that a published artifact was built
from a different commit. Rewritten release tags and GitHub-generated source
archives therefore have different Git/archive identities from the original ones.

Current dnsmasq build tools resolve the original `source_commit` through this map
only when querying Git. They still verify every frozen input SHA256, the complete
input digest, the original source epoch, the PGO profile, and the accepted ELF.
Build reports distinguish the original `accepted_product_commit` from the
resolved `accepted_product_git_commit`; diagnostic reports use the corresponding
`checked_product_*` fields. Source archive receipts record both `commit` and
`git_commit`. Archive hashes can change even when all extracted input bytes match.

Use the current build tools to resolve historical frozen sources. Tooling inside
an old tag predates this mapping and may still query unavailable original IDs.
The mapping cannot make a changed input satisfy a historical frozen checksum.
