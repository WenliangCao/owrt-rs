import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pgo_training_only as training


class TrainingOnlyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.elf = self.root / "instrumented"
        self.elf.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\xb7\x00" + b"synthetic")
        self.reference = {"source_commit": "a" * 40, "source_digest": "b" * 64,
                          "source_date_epoch": "1792244626", "source_file_count": 193,
                          "pgo_stage": "generate", "pgo": {"build_slot": "/fixed/slot", "profile_output_dir": "/tmp/dnsmasq-synthetic-pgo"}}
        files = {"components/platform/Cargo.toml": "d" * 64,
                 "packaging/openwrt/owrt-dnsmasq/static-pie-linker.py": "c" * 64}
        self.reference.update(source_files=files, source_file_count=len(files),
            source_digest=hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        self.baseline = {"source_files": {"old-body": "f" * 64}, "sdk": {"archive_sha256": "e" * 64}}
        flags = "-Dwarnings"
        added = "-Cprofile-generate=/tmp/dnsmasq-synthetic-pgo"
        self.ci = {**self.reference, "source_files": self.reference["source_files"],
                   "sdk": self.baseline["sdk"], "status": "built-instrumented-training-only",
                   "artifact_purpose": "instrumented-training-only", "release_qualified": False,
                   "pgo_stage": "generate", "elf": {"sha256": training.sha(self.elf), "size": self.elf.stat().st_size},
                   "toolchain": {"rustc": "release: 1.98.1\nhost: x86_64-unknown-linux-gnu\nLLVM version: 22.1.8"},
                   "compiler_warnings": {"strict_compiler_warnings_zero": True},
                   "pgo": {"mode": "generate", "build_slot": "/fixed/slot", "profile_output_dir": "/tmp/dnsmasq-synthetic-pgo",
                           "invocation": {"mode": "generate", "cargo_verbosity": "normal", "recipe_rustflags": flags, "added_rustflags": added,
                                          "effective_rustflags": flags + " " + added,
                                          "static_pie_linker_sha256": "c" * 64}}}

    def file(self, path, content=b"synthetic raw profile"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return {"path": str(path), "sha256": training.sha(path), "bytes": path.stat().st_size}

    def test_canonical_instrumented_contract(self):
        self.assertEqual(training.validate_ci(self.ci, self.reference, self.baseline, self.elf),
                         Path("/tmp/dnsmasq-synthetic-pgo"))

    def test_committed_workload_manifest_and_changed_identity(self):
        manifest = Path(__file__).resolve().parents[2] / "manifests/dnsmasq-pgo-training-v032.json"
        item = {"path": str(manifest), "sha256": training.sha(manifest)}
        _, reference = training.reference_plan(item)
        self.assertEqual(reference["training_seed"], 539365398)
        self.assertEqual(reference["evaluation_seed"], 2699265)
        self.assertEqual(reference["expected_profile_count"], 50)
        self.assertEqual(len(reference["scenes"]), 11)
        self.assertEqual(reference["helper_elf_sha256"], training.HELPER_SHA256)
        self.assertNotIn("baseline_receipt", reference)
        self.assertNotIn("generate_elf", reference)
        self.assertNotIn("source_commit", reference)
        reference["training_seed"] += 1
        changed = self.file(self.root / "changed-reference.json", json.dumps(reference).encode())
        with self.assertRaisesRegex(ValueError, "frozen workload manifest changed"):
            training.reference_plan(changed)

    def test_changed_sdk_is_rejected_without_old_product_receipt(self):
        reference = {"sdk": {"archive_sha256": "f" * 64}}
        with self.assertRaisesRegex(ValueError, "SDK archive differs"):
            training.validate_ci(self.ci, self.reference, reference, self.elf)

    def test_new_workload_plan_binds_its_own_sdk_and_fresh_helpers(self):
        manifest = Path(__file__).resolve().parents[2] / "manifests/dnsmasq-pgo-training-v033.json"
        _, reference = training.reference_plan({"path": str(manifest), "sha256": training.sha(manifest)})
        self.assertEqual(reference["openwrt"], "25.12.6")
        self.assertEqual(reference["sdk"]["archive_sha256"],
            "1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e")
        self.assertEqual(reference["helper_elf_sha256"], training.WORKLOAD_MANIFESTS[training.sha(manifest)])
        self.assertNotEqual(reference["helper_elf_sha256"], training.HELPER_SHA256)
        self.assertEqual(len(reference["scenes"]), 11)
        self.assertEqual(reference["expected_profile_count"], 50)
        self.assertNotIn("source_commit", reference)
        self.assertNotIn("merged_profile", reference)

    def test_old_host_plain_and_different_source_refused(self):
        for key, bad in (("status", "built-and-audited"), ("release_qualified", True),
                         ("pgo_stage", "use"), ("source_commit", "f" * 40), ("source_digest", "f" * 64)):
            value = copy.deepcopy(self.ci)
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                training.validate_ci(value, self.reference, self.baseline, self.elf)
        value = copy.deepcopy(self.ci)
        value["toolchain"]["rustc"] = value["toolchain"]["rustc"].replace("x86_64", "aarch64")
        with self.assertRaisesRegex(ValueError, "canonical x86"):
            training.validate_ci(value, self.reference, self.baseline, self.elf)

    def test_changed_flags_elf_and_warnings_refused(self):
        for field in ("effective_rustflags", "added_rustflags"):
            value = copy.deepcopy(self.ci)
            value["pgo"]["invocation"][field] += " -Cprofile-use=old.profdata"
            with self.subTest(field=field), self.assertRaises(ValueError):
                training.validate_ci(value, self.reference, self.baseline, self.elf)
        value = copy.deepcopy(self.ci)
        value["compiler_warnings"]["strict_compiler_warnings_zero"] = False
        with self.assertRaises(ValueError):
            training.validate_ci(value, self.reference, self.baseline, self.elf)
        self.elf.write_bytes(self.elf.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "ELF identity"):
            training.validate_ci(self.ci, self.reference, self.baseline, self.elf)

    def smoke(self):
        return {"status": "complete", "live_elf_sha256": training.sha(self.elf), "exit_status": 0,
                "forced_cleanup": False, "queries": [{}, {}],
                "protections": {"relro_read_only": True, "no_writable_executable_mapping": True, "stack_nx": True},
                "profile": self.file(self.root / "smoke" / "7.profraw")}

    def test_integrated_source_does_not_reuse_old_product_map(self):
        value = copy.deepcopy(self.ci)
        value["source_files"] = self.baseline["source_files"]
        with self.assertRaisesRegex(ValueError, "integrated source"):
            training.validate_ci(value, self.reference, self.baseline, self.elf)
        value = copy.deepcopy(self.ci)
        value["pgo"]["invocation"]["cargo_verbosity"] = "very-verbose"
        with self.assertRaisesRegex(ValueError, "verbosity"):
            training.validate_ci(value, self.reference, self.baseline, self.elf)

    def test_smoke_must_bind_actual_elf_and_clean_exit(self):
        smoke = self.smoke()
        training.validate_smoke(smoke, training.sha(self.elf))
        for key, bad in (("live_elf_sha256", "f" * 64), ("exit_status", 1), ("forced_cleanup", True)):
            value = copy.deepcopy(smoke)
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                training.validate_smoke(value, training.sha(self.elf))
        Path(smoke["profile"]["path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "identity differs"):
            training.validate_smoke(smoke, training.sha(self.elf))

    def collection(self):
        plan = {"training_directory": str(self.root / "training"), "scenes": [[str(i)] for i in range(11)],
                "smoke_profile": self.smoke()["profile"]}
        rows = [{"scene": scene, "valid": True, "errors": [], "profiles": []} for scene in plan["scenes"]]
        for i in range(50):
            rows[i % 11]["profiles"].append(self.file(self.root / "training" / "profiles" / str(i % 11) / f"{i}.profraw"))
        return plan, {"status": "complete", "scenes": rows}

    def test_complete_collection_and_duplicate_rejection(self):
        plan, collection = self.collection()
        self.assertEqual(len(training.training_profiles(plan, collection)), 50)
        collection["scenes"][0]["profiles"][1] = collection["scenes"][0]["profiles"][0]
        with self.assertRaisesRegex(ValueError, "50 unique"):
            training.training_profiles(plan, collection)

    def test_smoke_and_unaccounted_profiles_refused(self):
        plan, collection = self.collection()
        value = copy.deepcopy(collection)
        value["scenes"][0]["profiles"][0] = plan["smoke_profile"]
        with self.assertRaisesRegex(ValueError, "foreign or smoke"):
            training.training_profiles(plan, value)
        self.file(self.root / "training" / "profiles" / "extra.profraw")
        with self.assertRaisesRegex(ValueError, "unaccounted"):
            training.training_profiles(plan, collection)

    def test_failed_attempt_preserved_and_not_restarted(self):
        request = self.root / "request.json"
        attempt = self.root / "attempt"
        request.write_text(json.dumps({"attempt": str(attempt)}))
        with patch.object(training.sys, "platform", "linux"), \
                patch.object(training.os, "uname", return_value=SimpleNamespace(machine="aarch64", nodename="instance-synthetic")), \
                patch.object(training, "prepare", side_effect=ValueError("bad input")):
            with self.assertRaisesRegex(ValueError, "bad input"):
                training.execute(request)
            first = (attempt / "state.json").read_bytes()
            self.assertEqual(json.loads(first)["status"], "failed")
            with self.assertRaisesRegex(ValueError, "already exists"):
                training.execute(request)
            self.assertEqual((attempt / "state.json").read_bytes(), first)
            self.assertEqual((attempt / "request.json").read_bytes(), request.read_bytes())


if __name__ == "__main__":
    unittest.main()
