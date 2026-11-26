//! Resolves original evidence commits after the 2026-10-20 privacy rewrite.
//!
//! Only Git lookups are translated; source hashes and evidence IDs keep
//! naming the original commit.

use std::collections::BTreeMap;
use std::path::Path;

use crate::util::{self, ensure, is_hex, Result};

const COMMIT_MAP: &str = "docs/history/commit-map-20261020.txt";

pub fn resolve_commit(repo: &Path, commit: &str) -> Result<String> {
    ensure!(is_hex(commit, 40), "source commit must be a full lowercase SHA1");
    let text = util::read_text(&repo.join(COMMIT_MAP))?;
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().unwrap_or("").split_whitespace().collect();
    ensure!(header == ["old", "new"], "invalid privacy commit-map header");
    let mut mapping = BTreeMap::new();
    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        ensure!(
            fields.len() == 2 && fields.iter().all(|field| is_hex(field, 40) && *field != "0".repeat(40)),
            "invalid privacy commit-map entry"
        );
        ensure!(mapping.insert(fields[0], fields[1]).is_none(), "duplicate privacy commit-map entry");
    }
    Ok(mapping.get(commit).map_or(commit, |sanitized| sanitized).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    #[test]
    fn maps_rewritten_commits_and_rejects_malformed_maps() {
        let repo = TempDir::new("history");
        let map = repo.path().join(COMMIT_MAP);
        std::fs::create_dir_all(map.parent().unwrap()).unwrap();
        let (old, new, other) = ("a".repeat(40), "b".repeat(40), "c".repeat(40));
        std::fs::write(&map, format!("old new\n{old} {new}\n")).unwrap();
        assert_eq!(resolve_commit(repo.path(), &old).unwrap(), new);
        assert_eq!(resolve_commit(repo.path(), &other).unwrap(), other);
        assert!(resolve_commit(repo.path(), "abc").is_err());
        std::fs::write(&map, format!("old new\n{old} {new}\n{old} {other}\n")).unwrap();
        assert!(resolve_commit(repo.path(), &other).is_err());
        std::fs::write(&map, format!("old new\n{old} {}\n", "0".repeat(40))).unwrap();
        assert!(resolve_commit(repo.path(), &other).is_err());
    }
}
