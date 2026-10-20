"""Privacy rewrite preserves frozen source bytes without changing evidence IDs."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import ci_build_dnsmasq as builder
import ci_check_dnsmasq_target as target
from source_history import COMMIT_MAP, resolve_commit


class CommitMapTests(unittest.TestCase):
    def test_current_commits_pass_through_and_malformed_maps_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            mapping = repo / COMMIT_MAP
            mapping.parent.mkdir(parents=True)
            original, sanitized, current = "a" * 40, "b" * 40, "c" * 40
            row = f"{original} {sanitized}\n"
            mapping.write_text("old new\n" + row)
            self.assertEqual(resolve_commit(repo, original), sanitized)
            self.assertEqual(resolve_commit(repo, sanitized), sanitized)
            self.assertEqual(resolve_commit(repo, current), current)
            for invalid in ("HEAD", "a" * 8, "A" * 40, "--all", None):
                with self.subTest(commit=invalid), self.assertRaises(ValueError):
                    resolve_commit(repo, invalid)
            for invalid in ("", "new old\n" + row, "old new\n" + row + row,
                            "old new\n" + original + " " + "0" * 40 + "\n"):
                mapping.write_text(invalid)
                with self.subTest(mapping=invalid), self.assertRaises(ValueError):
                    resolve_commit(repo, original)


class FrozenSourceHistoryTests(unittest.TestCase):
    def specs(self):
        for name in ("dnsmasq-pgo-use-e21245d2.json", "dnsmasq-pgo-frozen-v032.json"):
            yield name, json.loads((builder.REPO / "manifests" / name).read_text())

    def test_both_release_archives_preserve_all_frozen_bytes_and_epochs(self):
        for name, spec in self.specs():
            with self.subTest(spec=name), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                (work / "out").mkdir()
                frozen = builder.release_source(work, spec)
                files, digest = builder.source_identity(spec, frozen)
                self.assertEqual(len(files), 212)
                self.assertEqual(files, spec["source_files"])
                self.assertEqual(digest, spec["source_digest"])
                self.assertEqual(builder.source_epoch(spec, "c" * 40), str(spec["source_date_epoch"]))
                self.assertNotEqual(resolve_commit(builder.REPO, spec["source_commit"]), spec["source_commit"])
                changed = copy.deepcopy(spec)
                changed["source_digest"] = "0" * 64
                with self.assertRaisesRegex(ValueError, "source/SDK recipe differs"):
                    builder.source_identity(changed, frozen)

    def test_diagnostic_archive_records_original_and_sanitized_commits(self):
        for name, spec in self.specs():
            with self.subTest(spec=name), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                target.freeze_source(out, spec)
                receipt = json.loads((out / "source-manifest.json").read_text())
                self.assertEqual(receipt["commit"], spec["source_commit"])
                self.assertEqual(receipt["git_commit"], resolve_commit(builder.REPO, spec["source_commit"]))
                self.assertEqual(receipt["files"], spec["source_files"])
                self.assertEqual(receipt["digest"], spec["source_digest"])


if __name__ == "__main__":
    unittest.main()
