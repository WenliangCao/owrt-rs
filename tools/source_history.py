"""Resolve original evidence commits after the 2026-10-20 privacy rewrite."""
from pathlib import Path
import re


COMMIT_MAP = Path("docs/history/commit-map-20261020.txt")


def resolve_commit(repo, commit):
    """Translate Git lookups only; source hashes and evidence IDs stay unchanged."""
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source commit must be a full lowercase SHA1")
    lines = (Path(repo) / COMMIT_MAP).read_text().splitlines()
    if not lines or lines[0].split() != ["old", "new"]:
        raise ValueError("invalid privacy commit-map header")
    mapping = {}
    for line in lines[1:]:
        fields = line.split()
        if len(fields) != 2 or any(not re.fullmatch(r"[0-9a-f]{40}", field)
                                   or field == "0" * 40 for field in fields):
            raise ValueError("invalid privacy commit-map entry")
        original, sanitized = fields
        if original in mapping:
            raise ValueError("duplicate privacy commit-map entry")
        mapping[original] = sanitized
    return mapping.get(commit, commit)
