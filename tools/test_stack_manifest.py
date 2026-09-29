import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from stack_manifest import build, sha


class StackManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "bins").mkdir()
        (self.root / "tools").mkdir()
        (self.root / "stack-switch.sh").write_text("current switch\n")
        (self.root / "tools/live.sh").write_text("current collector\n")
        self.old = {"image": "exact-image", "fix_commit": "old", "validation_tools_commit": "old-tools",
                    "canonical_build": {"run_id": 1}, "validation_summary": "old pass", "components": {}}
        hashes, original = {}, []
        for name in ("ubusd", "netifd", "httpd", "fw4", "rpcd", "procd", "logd", "uci", "reload-config"):
            binary = "reload_config_rs" if name == "reload-config" else name + "-rs"
            path = self.root / "bins" / binary
            path.write_bytes(binary.encode())
            hashes[binary] = sha(path)
            digest = hashlib.sha256(name.encode()).hexdigest()
            original.append(f"{digest}  /rom/sbin/{name}\n")
            self.old["components"][name] = {"original": {"path": "/rom/sbin/" + name, "sha256": digest, "bytes": 1},
                                           "rust": {"builder": "old", "sha256": "stale"}}
        (self.root / "original.sha256").write_text("".join(original))
        image = {"source_commit": "new", "binary_sha256": hashes}
        (self.root / "canonical-manifest.json").write_text(json.dumps(image))
        core = {"source_commit": "new", "binary_sha256": {}, "image_manifest_sha256": sha(self.root / "canonical-manifest.json")}
        (self.root / "canonical-core-manifest.json").write_text(json.dumps(core))
        self.workflow = {"headSha": "new", "databaseId": 42, "conclusion": "success"}

    def test_stale_identity_and_old_validation_are_not_inherited(self):
        result = build(self.root, self.old, self.workflow)
        self.assertEqual(result["canonical_build"], {"source_commit": "new", "run_id": 42, "conclusion": "success"})
        self.assertEqual(result["fix_commit"], "new")
        self.assertNotIn("validation_tools_commit", result)
        self.assertNotIn("validation_summary", result)
        self.assertEqual(result["scripts_sha256"]["tools/live.sh"], sha(self.root / "tools/live.sh"))
        self.assertTrue(all(v["rust"]["builder"] == "GitHub release-image 42" for v in result["components"].values()))
        self.assertEqual(self.old["fix_commit"], "old")

    def test_wrong_workflow_or_binary_is_rejected(self):
        for change in ({"headSha": "wrong"}, {"conclusion": "failure"}, {"databaseId": -1}):
            with self.assertRaises(AssertionError): build(self.root, self.old, {**self.workflow, **change})
        (self.root / "bins/netifd-rs").write_bytes(b"wrong artifact")
        with self.assertRaisesRegex(AssertionError, "canonical binary"): build(self.root, self.old, self.workflow)

    def test_wrong_original_image_or_core_pair_is_rejected(self):
        old = copy.deepcopy(self.old)
        old["components"]["fw4"]["original"]["sha256"] = "wrong"
        with self.assertRaisesRegex(AssertionError, "original image"): build(self.root, old, self.workflow)
        core = json.loads((self.root / "canonical-core-manifest.json").read_text())
        core["image_manifest_sha256"] = "wrong"
        (self.root / "canonical-core-manifest.json").write_text(json.dumps(core))
        with self.assertRaisesRegex(AssertionError, "canonical manifest"): build(self.root, self.old, self.workflow)


if __name__ == "__main__":
    unittest.main()
