"""PGO transport, historical source and resolved compiler regression gates."""
import copy
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import ci_dnsmasq_build as runtime
import ci_dnsmasq_pgo_inputs as inputs
import ci_dnsmasq_profile as profiles
import ci_dnsmasq_profile_transport as transport
import ci_dnsmasq_pgo_cargo as wrapper


class InputsTests(unittest.TestCase):
    def setUp(self):
        repository = patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"})
        repository.start()
        self.addCleanup(repository.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repository = "owner/repo"

    def test_resolved_compiler_is_not_the_rustup_proxy_and_release_is_checked(self):
        rustc = self.root / "actual-rustc"
        rustc.write_bytes(b"compiler binary")
        env = {"RUSTUP_TOOLCHAIN": "1.100.0"}
        calls = []
        def run(argv, log, **kwargs):
            calls.append(argv)
            return str(rustc) + "\n" if argv[0] == "rustup" else "release: 1.100.0\nLLVM version: 23.1.5\n"
        identity = runtime.compiler("1.100.0", env, self.root, run)
        self.assertEqual(calls[0], ["rustup", "which", "--toolchain", "1.100.0", "rustc"])
        self.assertEqual(calls[1][0], str(rustc))
        self.assertEqual(env["RUSTC"], str(rustc))
        self.assertEqual(identity["sha256"], runtime.sha(rustc))
        with self.assertRaisesRegex(ValueError, "release differs"):
            runtime.compiler("1.98.1", env, self.root, run)

    def test_wrapper_binds_only_the_expected_resolved_compiler(self):
        rustc, linker, adapter = [self.root / n for n in ("rustc", "linker", "adapter")]
        for path in (rustc, linker, adapter):
            path.write_bytes(path.name.encode())
        env = {"RUSTC": str(rustc), "RUSTFLAGS": "-Dwarnings",
               "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": str(linker)}
        plan = {"mode": "generate", "build_dir": str(self.root), "profile_output_dir": "/tmp/dnsmasq-test-pgo",
                "recipe_environment": dict(env), "rustc_sha256": runtime.sha(rustc),
                "static_pie_linker_sha256": runtime.sha(linker),
                "build_adapter": {"path": str(adapter), "sha256": runtime.sha(adapter)}}
        argv = ["build", "--release", "--frozen", "--manifest-path", str(self.root / "dnsmasq/Cargo.toml"), "--bin", "dnsmasq-rs"]
        result = wrapper.prepare(plan, argv, env)
        self.assertEqual(result["rustc_sha256"], runtime.sha(rustc))
        rustc.write_bytes(b"changed compiler, same path")
        with self.assertRaisesRegex(ValueError, "RUSTC identity"):
            wrapper.prepare(plan, argv, env)
        with self.assertRaisesRegex(ValueError, "recipe environment"):
            wrapper.prepare(plan, argv, {**env, "RUSTC": "/other/rustc"})

    def test_legacy_recipe_adaptation_does_not_rewrite_frozen_source(self):
        source, out = self.root / "source", self.root / "out"
        source.mkdir(); out.mkdir()
        original = "$(V1_CARGO) build --release --target-dir $(PKG_BUILD_DIR)/dnsmasq/target\n"
        (source / "Makefile").write_text(original)
        report = {}
        adapted = runtime.recipe(source, out, report)
        self.assertEqual((source / "Makefile").read_text(), original)
        self.assertNotIn("--target-dir", (adapted / "Makefile").read_text())
        self.assertFalse(report["recipe_adaptation"]["historical_source_map_modified"])
        self.assertNotEqual(report["recipe_adaptation"]["original_sha256"], report["recipe_adaptation"]["adapted_sha256"])

    def test_cargo_json_selects_actual_executable_without_a_target_path_guess(self):
        elf = self.root / "shared-cache-product"
        elf.write_bytes(b"actual synthetic compiler output")
        build = self.root / "sdk-build/dnsmasq"
        product_manifest = build / "Cargo.toml"
        platform_manifest = build / "platform/Cargo.toml"
        library = self.root / "shared-cache-platform.rlib"
        library.write_bytes(b"actual synthetic platform library")
        script = self.root / "adapter.py"
        rows = [
            {"reason": "compiler-artifact", "manifest_path": str(product_manifest),
             "target": {"name": "dnsmasq-rs", "kind": ["bin"]},
             "executable": str(elf), "fresh": False},
            {"reason": "compiler-artifact", "manifest_path": str(platform_manifest),
             "target": {"name": "dnsmasq_platform", "kind": ["lib"]},
             "filenames": [str(library)], "fresh": False},
        ]
        script.write_text("#!/usr/bin/env python3\nimport json\n" +
                          "[print(json.dumps(row)) for row in " + repr(rows) + "]\n")
        script.chmod(0o755)
        plan = {"cargo": "/fake/cargo", "build_dir": str(self.root / "sdk-build"),
                "install_elf": str(self.root / "install/dnsmasq"),
                "artifact_receipt": str(self.root / "artifact.json"),
                "build_adapter": {"path": str(script)}}
        with patch.object(runtime.subprocess, "check_output", return_value="huacnlee/cargo test"):
            self.assertEqual(runtime.compile_artifact(plan, ["build"], dict(__import__('os').environ)), 0)
        self.assertEqual(Path(plan["install_elf"]).read_bytes(), elf.read_bytes())
        receipt = json.loads(Path(plan["artifact_receipt"]).read_text())
        self.assertIn("--message-format=json-render-diagnostics", receipt["argv"])
        self.assertFalse(any("target-dir" in arg for arg in receipt["argv"]))
        self.assertEqual(receipt["platform_rlibs"], [{"path": str(library), "bytes": library.stat().st_size,
                                                       "sha256": runtime.sha(library)}])
        Path(plan["artifact_receipt"]).unlink()
        Path(plan["artifact_receipt"]).with_suffix(".jsonl").unlink()
        foreign = {**rows[0], "manifest_path": str(self.root / "foreign/Cargo.toml")}
        script.write_text("#!/usr/bin/env python3\nimport json\nprint(" + repr(json.dumps(foreign)) + ")\n")
        with patch.object(runtime.subprocess, "check_output", return_value="huacnlee/cargo test"), \
                self.assertRaisesRegex(ValueError, "one Cargo executable and platform library"):
            runtime.compile_artifact(plan, ["build"], dict(os.environ))
        with patch.object(runtime.subprocess, "check_output", return_value="cargo stock"):
            with self.assertRaisesRegex(ValueError, "huacnlee/cargo"):
                runtime.compile_artifact(plan, ["build"], {})

    def test_historical_freeze_keeps_its_exact_map_on_the_new_runner(self):
        historic = inputs.load(inputs.builder.REPO / "packaging/image/native-25.12.6.json")["dnsmasq_build"]
        old = copy.deepcopy(historic)
        self.assertEqual(old["source_commit"], "0e077f258811c6250edfe188de62a52e48d7a8df")
        frozen = inputs.pipeline.target.freeze_source(self.root, historic)
        actual = inputs.builder.audit.inputs(frozen, version="25.12.6")
        self.assertEqual(actual, old["source_files"])
        self.assertEqual(len(actual), 231)
        self.assertIn("tools/mbx_cargo.sh", actual)
        self.assertNotIn("tools/cargo.sh", actual)
        self.assertEqual(historic, old)

    def test_aa_freeze_uses_actual_v033_and_original_lock_not_checkout(self):
        path = self.root / "generate.json"
        result = inputs.generate(inputs.V033, "v033-aa", path)
        self.assertEqual(inputs.toolchain(path), "1.98.1")
        self.assertEqual(result["source_commit"], inputs.V033)
        data = subprocess.check_output(["git", "-C", str(inputs.builder.REPO), "show",
                                        inputs.V033 + ":components/dnsmasq/Cargo.lock"])
        self.assertEqual(result["source_files"]["components/dnsmasq/Cargo.lock"], hashlib.sha256(data).hexdigest())
        self.assertNotEqual(result["source_commit"], result["deployed_baseline"]["source_commit"])
        with self.assertRaises(FileExistsError):
            inputs.generate(inputs.V033, "v033-aa", path)
        with self.assertRaisesRegex(ValueError, "actual v033"):
            inputs.generate("HEAD", "v033-aa", self.root / "bad.json")

    def make_bundle(self):
        directory = self.root / "bundle"
        directory.mkdir()
        files = {"components/platform/Cargo.toml": "a" * 64,
                 "components/dnsmasq/platform/Cargo.toml": "b" * 64,
                 "manifests/release-25.12.6.json": "c" * 64}
        spec = {"source_commit": "a" * 40, "source_date_epoch": 1234, "openwrt": "25.12.6",
                "source_file_count": len(files), "source_files": files, "pgo_stage": "generate",
                "source_digest": hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                "elf_max_bytes": 2_500_000, "apk_max_bytes": 1_400_000, "package_release": "4",
                "instrumentation_budget": dict(inputs.pipeline.INSTRUMENTATION_BUDGET),
                "pgo": {"build_slot": inputs.pipeline.BUILD_SLOT, "profile_output_dir": inputs.pipeline.PROFILE_OUTPUT,
                        "retain_link_map": True}}
        built = {**spec, "status": "built-instrumented-training-only", "release_qualified": False,
                 "pgo": {"mode": "generate"}, "compiler_warnings": {"strict_compiler_warnings_zero": True},
                 "elf": {"sha256": "d" * 64}, "resolved_rustc": {"sha256": "e" * 64}}
        (directory / "generation-spec.json").write_text(json.dumps(spec))
        (directory / "generator-manifest.json").write_text(json.dumps(built))
        (directory / "profile.profdata").write_bytes(b"new profile")
        receipt = {**{k: spec[k] for k in ("source_commit", "source_digest", "source_date_epoch", "source_file_count")},
            "status": "training-complete-unqualified", "release_qualified": False, "product_training_reused": False,
            "profile_count": 50, "scene_count": 11, "ci_build": {"sha256": profiles.sha(directory / "generator-manifest.json")},
            "source_spec": {"sha256": profiles.sha(directory / "generation-spec.json")}, "generate_elf": built["elf"],
            "merged_profile": {"sha256": profiles.sha(directory / "profile.profdata"), "bytes": 11}}
        (directory / "training-profile.json").write_text(json.dumps(receipt))
        return directory, spec, built, receipt

    @staticmethod
    def zip_files(files):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            for name, content in files.items():
                archive.writestr(name, content)
        return data.getvalue()

    def test_use_and_freeze_keep_source_and_require_zero_warning_build(self):
        directory, spec, built, _ = self.make_bundle()
        path = directory / "generation-spec.json"
        artifact = {"kind": "github-actions-artifact", "repository": self.repository, "artifact_id": 1,
                    "run_id": 2, "head_sha": "b" * 40, "archive_sha256": "b" * 64}
        use_path = self.root / "use.json"
        data = self.zip_files({name: (directory / name).read_bytes() for name in profiles.MEMBERS})
        with patch.object(profiles, "get_profile", return_value=(data, {}, [])):
            inputs.use(path, artifact, use_path)
        use = inputs.load(use_path)
        self.assertEqual(use["source_files"], spec["source_files"])
        self.assertNotIn("profile_url", use["pgo"])
        runner = "b" * 40
        report = {**built, "runner_commit": runner, "pgo_stage": "candidate-use", "status": "created-unqualified-pgo-candidate",
                  "pgo": {**use["pgo"], "mode": "use", "profile_diagnostics": []},
                  "warnings": {"strict_compiler_warnings_zero": True},
                  "elf": {"sha256": "e" * 64, "size": 2_300_000}}
        manifest = self.root / "candidate.json"
        manifest.write_text(json.dumps(report))
        frozen = self.root / "frozen.json"
        item = {"kind": "github-actions-artifact", "repository": self.repository, "artifact_id": 10,
                "run_id": 20, "head_sha": runner, "archive_sha256": "c" * 64}
        artifact_json = self.root / "candidate-artifact.json"
        artifact_json.write_text(json.dumps(item))
        run = {"id": 20, "head_sha": runner}
        evidence = {"artifact": {"name": f"dnsmasq-pgo-freeze-candidate-{runner}-20"}, "run": run}
        report["elf"].update(sha256=profiles.sha_bytes(b"candidate ELF"), size=len(b"candidate ELF"))
        manifest.write_text(json.dumps(report))
        archive = self.zip_files({"manifest.json": manifest.read_bytes(), "build-spec.json": use_path.read_bytes(),
                                  "dnsmasq-rs": b"candidate ELF"})
        with patch.object(profiles, "metadata", return_value=evidence), \
                patch.object(profiles, "get_archive", return_value=(archive, evidence, [])):
            inputs.freeze(use_path, manifest, artifact_json, frozen)
        accepted = inputs.load(frozen)
        self.assertEqual(accepted["reference_elf_sha256"], profiles.sha_bytes(b"candidate ELF"))
        self.assertEqual(accepted["candidate_build_manifest_sha256"], profiles.sha(manifest))
        self.assertEqual(accepted["candidate_build_artifact"], item)
        report["pgo"]["profile_diagnostics"] = ["hash mismatch"]
        manifest.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "zero warnings/profile mismatches"):
            inputs.freeze(use_path, manifest, artifact_json, self.root / "bad.json")
        report["pgo"]["profile_diagnostics"] = []
        report["compiler_warnings"]["strict_compiler_warnings_zero"] = False
        manifest.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "zero warnings/profile mismatches"):
            inputs.freeze(use_path, manifest, artifact_json, self.root / "bad2.json")

        report["compiler_warnings"]["strict_compiler_warnings_zero"] = True
        report["runner_commit"] = "f" * 40
        manifest.write_text(json.dumps(report))
        with patch.object(profiles, "metadata", return_value=evidence), \
                patch.object(profiles, "get_archive", return_value=(archive, evidence, [])), \
                self.assertRaisesRegex(ValueError, "successful CI run"):
            inputs.freeze(use_path, manifest, artifact_json, self.root / "wrong-run.json")

    def test_candidate_native_spec_does_not_reuse_old_component_hashes(self):
        template_path = inputs.builder.REPO / "packaging/image/native-25.12.6.json"
        original = template_path.read_bytes()
        template = json.loads(original)
        dns = copy.deepcopy(template["dnsmasq_build"])
        dns["candidate_build_artifact"] = {"kind": "github-actions-artifact", "repository": self.repository,
            "artifact_id": 10, "run_id": 20, "head_sha": "b" * 40, "archive_sha256": "c" * 64}
        dns["candidate_build_manifest_sha256"] = "d" * 64
        dns_path = self.root / "dns.json"
        dns_path.write_text(json.dumps(dns))
        hashes = {item["binary"]: hashlib.sha256(name.encode()).hexdigest()
                  for name, item in template["components"].items() if name != "dnsmasq"}
        receipt = self.root / "core-target-check.json"
        product = dns["source_commit"]
        product_tree = subprocess.check_output(["git", "-C", str(inputs.builder.REPO), "rev-parse",
                                                product + ":components"], text=True).strip()
        toolchain = subprocess.check_output(["git", "-C", str(inputs.builder.REPO), "show",
                                             product + ":rust-toolchain.toml"])
        comparison = {"source_commit": product, "runner_commit": "b" * 40,
                      "component_tree": product_tree,
                      "toolchain_sha256": hashlib.sha256(toolchain).hexdigest(),
                      "adapter_files": {"tools/ci_check_core.py": "c" * 64}}
        report = {"status": "passed", "phase": "target", "source_commit": product,
                  "comparison_source": comparison, "binary_sha256": hashes,
                  "warnings": {"strict_compiler_warnings_zero": True}}
        receipt.write_text(json.dumps(report))
        dest = self.root / "native-new.json"
        with patch.object(inputs.pipeline, "load_spec", return_value=dns):
            inputs.native(dns_path, [receipt], dest)
        self.assertEqual(template_path.read_bytes(), original)
        candidate = inputs.load(dest)
        self.assertEqual(candidate["components"]["fw4"]["reference_elf_sha256"], hashes["fw4-rs"])
        self.assertEqual(candidate["version"], "0.3.4-r1")
        self.assertEqual(candidate["comparison_build"]["runner_commit"], "b" * 40)
        report["status"] = "failed"
        receipt.write_text(json.dumps(report))
        with patch.object(inputs.pipeline, "load_spec", return_value=dns), \
                self.assertRaisesRegex(ValueError, "passed zero-warning"):
            inputs.native(dns_path, [receipt], self.root / "bad-native.json")

        report["status"] = "passed"
        report["comparison_source"]["source_commit"] = "f" * 40
        receipt.write_text(json.dumps(report))
        with patch.object(inputs.pipeline, "load_spec", return_value=dns), \
                self.assertRaisesRegex(ValueError, "pinned product/runner"):
            inputs.native(dns_path, [receipt], self.root / "wrong-product.json")

        names = list(hashes)
        split = len(names) // 2
        comparison["source_commit"] = product
        first, second = dict(report), dict(report)
        first["comparison_source"] = dict(comparison)
        first["binary_sha256"] = {name: hashes[name] for name in names[:split]}
        second["comparison_source"] = {**comparison, "runner_commit": "d" * 40}
        second["binary_sha256"] = {name: hashes[name] for name in names[split:]}
        first_path, second_path = self.root / "core-first.json", self.root / "core-second.json"
        first_path.write_text(json.dumps(first))
        second_path.write_text(json.dumps(second))
        with patch.object(inputs.pipeline, "load_spec", return_value=dns), \
                self.assertRaisesRegex(ValueError, "different runner adapters"):
            inputs.native(dns_path, [first_path, second_path], self.root / "mixed-runners.json")

    def test_profile_bundle_rejects_foreign_source_reused_training_and_modified_profile(self):
        directory, spec, built, receipt = self.make_bundle()
        identities, _ = profiles.verify_bundle(directory, spec)
        pgo = {"profile_sha256": profiles.sha(directory / "profile.profdata"), "profile_bytes": 11, "training": identities}
        profiles.verify_bundle(directory, spec, pgo)
        for key in ("source_commit", "source_digest"):
            with self.assertRaisesRegex(ValueError, "spec differs"):
                profiles.verify_bundle(directory, {**spec, key: "f" * len(spec[key])})
        (directory / "profile.profdata").write_bytes(b"old profile")
        with self.assertRaisesRegex(ValueError, "profile identity"):
            profiles.verify_bundle(directory, spec)
        (directory / "profile.profdata").write_bytes(b"new profile")
        receipt["product_training_reused"] = True
        (directory / "training-profile.json").write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "fresh complete"):
            profiles.verify_bundle(directory, spec)

    def test_artifact_requires_exact_id_run_digest_commit_and_successful_authorized_branch(self):
        item = {"kind": "github-actions-artifact", "repository": self.repository, "artifact_id": 1,
                "run_id": 2, "head_sha": "a" * 40, "archive_sha256": "b" * 64}
        artifact = {"id": 1, "expired": False, "size_in_bytes": 123,
                    "workflow_run": {"id": 2, "head_sha": "a" * 40}, "digest": "sha256:" + "b" * 64}
        run = {"id": 2, "head_sha": "a" * 40, "head_branch": profiles.CI_BRANCH, "conclusion": "success",
               "event": "workflow_dispatch", "path": f".github/workflows/{profiles.WORKFLOW}"}
        with patch.object(profiles, "api", side_effect=[artifact, run]):
            profiles.metadata(item)
        for change in ({"expired": True}, {"id": 9}, {"digest": "sha256:" + "c" * 64}):
            with patch.object(profiles, "api", side_effect=[{**artifact, **change}, run]):
                with self.assertRaisesRegex(ValueError, "identity differs"):
                    profiles.metadata(item)
        for change in ({"head_branch": "main"}, {"conclusion": "failure"}, {"path": "another.yml"}):
            with patch.object(profiles, "api", side_effect=[artifact, {**run, **change}]):
                with self.assertRaisesRegex(ValueError, "authorized CI branch"):
                    profiles.metadata(item)
        with patch.object(profiles, "api", side_effect=[artifact, {**run, "head_sha": "f" * 40}]):
            with self.assertRaisesRegex(ValueError, "run commit differs"):
                profiles.metadata(item)

    def test_partitioned_profile_round_trip_and_rejects_reordered_or_tampered_chunks(self):
        bundle, spec, built, receipt = self.make_bundle()
        spec_path = bundle / "generation-spec.json"
        head = "a" * 40
        elf = b"synthetic instrumented ELF"
        built.update(runner_commit=head, elf={"sha256": profiles.sha_bytes(elf)})
        built_path = bundle / "generator-manifest.json"
        built_path.write_text(json.dumps(built))
        receipt.update(ci_build={"sha256": profiles.sha(built_path)}, generate_elf=built["elf"])
        profile = b"a" * (transport.CHUNK_BYTES + 1)  # Stored in the fixture ZIP without compression.
        (bundle / "profile.profdata").write_bytes(profile)
        receipt["merged_profile"] = {"sha256": profiles.sha_bytes(profile), "bytes": len(profile)}
        (bundle / "training-profile.json").write_text(json.dumps(receipt))
        data = self.zip_files({name: (bundle / name).read_bytes() for name in profiles.MEMBERS})
        fields = {"spec": "packaging/image/fake.json", "transfer": "8" * 32,
                  "bundle_sha256": profiles.sha_bytes(data), "generation_run": "20"}
        api_responses, archives = {}, {}

        def artifact(run_id, name, data, title):
            artifact_id = run_id + 100
            archives[artifact_id] = data
            source = {"id": run_id, "head_sha": head}
            run = {**source, "head_branch": profiles.CI_BRANCH, "conclusion": "success", "run_attempt": 1,
                   "event": "workflow_dispatch", "path": f".github/workflows/{profiles.WORKFLOW}",
                   "display_title": title}
            row = {"id": artifact_id, "name": name, "digest": "sha256:" + profiles.sha_bytes(data),
                   "expired": False, "size_in_bytes": len(data), "workflow_run": source}
            api_responses[f"repos/{self.repository}/actions/runs/{run_id}"] = run
            api_responses[f"repos/{self.repository}/actions/runs/{run_id}/artifacts"] = {"artifacts": [row]}
            api_responses[f"repos/{self.repository}/actions/artifacts/{artifact_id}"] = row

        generator_zip = self.zip_files({"manifest.json": built_path.read_bytes(), "dnsmasq-rs": elf,
                                        "build-spec.json": spec_path.read_bytes()})
        artifact(20, f"dnsmasq-pgo-generate-{head}-20", generator_zip, "generate")
        for index, start in enumerate(range(0, len(data), transport.CHUNK_BYTES)):
            chunk = data[start:start + transport.CHUNK_BYTES]
            out = self.root / f"chunk-{index}"
            transport.store_chunk({**fields, "part": str(index), "payload": base64.b64encode(chunk).decode()}, out)
            label = f"{transport.PREFIX}-chunk-{fields['transfer']}-{index}"
            artifact(10 + index, f"{label}-1", self.zip_files({p.name: p.read_bytes() for p in out.iterdir()}), label)

        def download(url):
            return archives[int(url.split("/")[-2])]

        def assemble(order, out):
            transport.assemble({**fields, "part": order}, self.repository, head, out, self.root / "transport.json")

        with patch.object(transport, "spec_file", return_value=spec_path), \
                patch.object(profiles, "api", side_effect=api_responses.__getitem__), \
                patch.object(profiles, "gh", side_effect=download):
            target = self.root / "assembled"
            assemble("10,11", target)
            self.assertEqual((target / "profile.profdata").read_bytes(), profile)
            self.assertEqual(inputs.load(self.root / "transport.json")["generator"]["artifact_id"], 120)
            with self.assertRaisesRegex(ValueError, "run identity differs"):
                assemble("11,10", self.root / "reordered")
            archives[110] = b"x" + archives[110][1:]
            with self.assertRaisesRegex(ValueError, "archive digest/size differs"):
                assemble("10,11", self.root / "tampered")

    def test_artifact_zip_traversal_and_duplicate_members_fail_closed(self):
        for i, names in enumerate((["../outside"], ["profile.profdata"] * 4)):
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as archive:
                for name in names:
                    # Construct a duplicate-member attack without noisy zip warnings.
                    if name in archive.NameToInfo:
                        archive.NameToInfo.pop(name)
                    archive.writestr(name, "data")
            with self.assertRaisesRegex(ValueError, "artifact paths"):
                profiles.unpack(data.getvalue(), self.root / str(i))


if __name__ == "__main__":
    unittest.main()
