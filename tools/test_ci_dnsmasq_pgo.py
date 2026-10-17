"""Release PGO identity and override rejection without compiling a product."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ci_build_dnsmasq as builder
import ci_dnsmasq_pgo_cargo as wrapper
import ci_dnsmasq_map_cc as map_cc


class PgoReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.profile = self.root / "profile.profdata"
        self.profile.write_bytes(b"frozen synthetic profile")
        self.linker = self.root / "linker.py"
        self.linker.write_bytes(b"unchanged static PIE linker")
        self.env = {"RUSTUP_TOOLCHAIN": "1.98.1", "CARGO_BUILD_TARGET": "aarch64-unknown-linux-musl",
                    "CARGO_PROFILE_RELEASE_PANIC": "abort", "RUSTFLAGS": "-Cforce-unwind-tables=no",
                    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": str(self.linker)}
        self.plan = {"build_dir": str(self.root), "profile": str(self.profile),
                     "profile_sha256": wrapper.sha(self.profile), "profile_bytes": self.profile.stat().st_size,
                     "static_pie_linker_sha256": wrapper.sha(self.linker), "recipe_environment": dict(self.env)}
        self.argv = ["build", "--release", "--frozen", "--manifest-path", str(self.root / "dnsmasq/Cargo.toml"),
                     "--bin", "dnsmasq-rs", "--target-dir", str(self.root / "dnsmasq/target")]

    def test_recipe_receives_one_exact_profile_use_suffix(self):
        result = wrapper.prepare(self.plan, self.argv, self.env)
        self.assertEqual(result["effective_rustflags"], self.env["RUSTFLAGS"] +
                         f" -Cprofile-use={self.profile} -Cllvm-args=-pgo-warn-missing-function")
        self.assertEqual(result["mode"], "use")
        self.assertIsNone(wrapper.prepare(self.plan, ["--version"], self.env))

    def test_fixed_slot_rejects_existing_outputs_and_symlink_ancestors(self):
        slot = self.root / "sdk-build-slot"
        self.assertEqual(builder.pgo_build_slot(slot), slot)
        slot.mkdir()
        with self.assertRaises(ValueError):
            builder.pgo_build_slot(slot)
        alias = self.root / "alias"
        alias.symlink_to(slot, target_is_directory=True)
        with self.assertRaises(ValueError):
            builder.pgo_build_slot(alias / "fresh")

    def test_compilation_evidence_keeps_outputs_and_selected_fingerprints(self):
        build = self.root / "slot"
        target = build / "dnsmasq/target/aarch64-unknown-linux-musl/release"
        target.mkdir(parents=True)
        (target / "dnsmasq-rs").write_bytes(b"compiled-elf")
        for name in ["owrt-ubus-abcd", "dnsmasq-rs-efab", "dnsmasq-platform-1122", "rustix-3344", "unrelated-1234"]:
            folder = target / ".fingerprint" / name
            folder.mkdir(parents=True)
            (folder / "lib.json").write_text('{"metadata":"actual"}')
        host = build / "dnsmasq/target/release"
        folder = host / ".fingerprint/rustix-host"
        folder.mkdir(parents=True)
        (folder / "build-script-build-script-build.json").write_text('{"metadata":"host"}')
        script = host / "build/rustix-host"
        script.mkdir(parents=True)
        (script / "build-script-build").write_bytes(b"host executable")
        output = target / "build/rustix-3344"
        output.mkdir(parents=True)
        (output / "output").write_text("cargo:rustc-cfg=linux_raw\n")
        packages = self.root / "packages"
        packages.mkdir()
        (packages / "dnsmasq-2.93-r4.apk").write_bytes(b"actual-package")
        link_map = self.root / "link.map"
        link_map.write_text("actual same-build map\n")
        report = {"pgo": {}, "link_map": {"wrapper": str(self.linker), "output_path": str(link_map)}}
        builder.retain_pgo_compilation(self.root, build, packages, report)
        evidence = self.root / "pgo-compilation"
        self.assertEqual((evidence / "dnsmasq-prestrip").read_bytes(), b"compiled-elf")
        self.assertEqual((evidence / "dnsmasq-2.93-r4.apk").read_bytes(), b"actual-package")
        self.assertEqual((evidence / "link.map").read_text(), "actual same-build map\n")
        self.assertEqual(report["link_map"]["sha256"], wrapper.sha(link_map))
        self.assertIn("link.map", report["pgo"]["compilation_evidence"])
        fingerprints = json.loads((evidence / "cargo-fingerprints.json").read_text())
        self.assertEqual(len(fingerprints), 5)
        self.assertEqual(fingerprints["release/.fingerprint/rustix-host/build-script-build-script-build.json"],
                         {"metadata": "host"})
        self.assertIn("aarch64-unknown-linux-musl/release/.fingerprint/dnsmasq-platform-1122/lib.json", fingerprints)
        scripts = json.loads((evidence / "cargo-build-scripts.json").read_text())
        self.assertEqual(scripts["aarch64-unknown-linux-musl/release/build/rustix-3344/output"], "cargo:rustc-cfg=linux_raw\n")
        identities = json.loads((evidence / "cargo-identities.json").read_text())
        self.assertEqual(identities["release/build/rustix-host/build-script-build"]["sha256"],
                         wrapper.sha(script / "build-script-build"))

    def test_wrong_profile_linker_argv_and_codegen_overrides_are_rejected(self):
        for name, value in [("LLVM_PROFILE_FILE", "raw"), ("CARGO_PROFILE_RELEASE_OPT_LEVEL", "2"),
                            ("RUSTC_WRAPPER", "other"), ("RUSTFLAGS", "-Cprofile-generate=/tmp/profile")]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                wrapper.prepare(self.plan, self.argv, {**self.env, name: value})
        with self.assertRaises(ValueError):
            wrapper.prepare(self.plan, [*self.argv, "--features", "m6b-diagnostics"], self.env)
        self.profile.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            wrapper.prepare(self.plan, self.argv, self.env)
        self.profile.write_bytes(b"frozen synthetic profile")
        self.linker.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            wrapper.prepare(self.plan, self.argv, self.env)

    def test_fixed_asset_url_and_download_identity(self):
        url = "https://github.com/owner/repo/releases/download/build-inputs/profile.profdata"
        self.assertEqual(builder.profile_asset(url), ("owner/repo", "build-inputs", "profile.profdata"))
        for invalid in [url + "?token=secret", url.replace("github.com", "elsewhere.test"),
                        url.replace("profile.profdata", "*.profdata"), url.replace("build-inputs", "..")]:
            with self.subTest(url=invalid), self.assertRaises(ValueError):
                builder.profile_asset(invalid)
        spec = {"profile_url": url, "profile_sha256": wrapper.sha(self.profile),
                "profile_bytes": self.profile.stat().st_size}
        def fake_download(command, log):
            self.assertEqual(command[:4], ["gh", "release", "download", "build-inputs"])
            target = Path(command[command.index("--dir") + 1]) / "profile.profdata"
            target.write_bytes(self.profile.read_bytes())
        with patch.object(builder.audit, "run", side_effect=fake_download):
            path, _ = builder.download_profile(spec, self.root)
        self.assertEqual(wrapper.sha(path), spec["profile_sha256"])
        out = self.root / "bad"
        out.mkdir()
        with patch.object(builder.audit, "run", side_effect=fake_download), self.assertRaises(ValueError):
            builder.download_profile({**spec, "profile_sha256": "0" * 64}, out)

    def test_missing_or_mismatched_profile_diagnostics_fail_closed(self):
        report = {"pgo": {key: self.plan[key] for key in ("profile_sha256", "profile_bytes")}}
        receipt = wrapper.prepare(self.plan, self.argv, self.env)
        (self.root / "pgo-invocation.json").write_text(json.dumps(receipt))
        (self.root / "compile.log").write_text("Finished release profile\n")
        builder.verify_pgo_build(self.root, report)
        self.assertEqual(report["pgo"]["profile_diagnostics"], [])
        for warning in ["warning: no profile data available for function", "warning: hash mismatch",
                        "warning: profile data may be out of date", "malformed instrumentation profile"]:
            (self.root / "compile.log").write_text(warning)
            with self.subTest(warning=warning), self.assertRaises(ValueError):
                builder.verify_pgo_build(self.root, report)
        (self.root / "compile.log").write_text("Finished release profile\n")
        (self.root / "pgo-invocation.json").unlink()
        with self.assertRaises(ValueError):
            builder.verify_pgo_build(self.root, report)

    def test_generate_has_no_profile_input_and_keeps_diagnostic_gate(self):
        plan = {key: value for key, value in self.plan.items() if not key.startswith("profile")}
        plan.update(mode="generate", profile_output_dir="/tmp/dnsmasq-ci-pgo")
        result = wrapper.prepare(plan, self.argv, self.env)
        self.assertEqual(result["added_rustflags"], "-Cprofile-generate=/tmp/dnsmasq-ci-pgo")
        self.assertNotIn("profile_sha256", result)
        with self.assertRaisesRegex(ValueError, "must not consume"):
            wrapper.prepare({**plan, "profile_sha256": "e" * 64}, self.argv, self.env)
        with self.assertRaisesRegex(ValueError, "unknown PGO"):
            wrapper.prepare({**plan, "mode": "other"}, self.argv, self.env)
        (self.root / "pgo-invocation.json").write_text(json.dumps(result))
        (self.root / "compile.log").write_text("Finished release profile\n")
        report = {"pgo": {"mode": "generate", "profile_output_dir": plan["profile_output_dir"]}}
        builder.verify_pgo_build(self.root, report)
        (self.root / "compile.log").write_text("warning: hash mismatch\n")
        with self.assertRaisesRegex(ValueError, "profile missing/mismatch"):
            builder.verify_pgo_build(self.root, report)

    def test_unqualified_creation_cannot_bypass_frozen_reference(self):
        spec = {"pgo": {}, "reference_elf_sha256": "e" * 64}
        with self.assertRaisesRegex(ValueError, "cannot bypass"):
            builder.validate_pgo_stage(spec, "candidate-use", self.root)
        with self.assertRaisesRegex(ValueError, "diagnostic source archive"):
            builder.validate_pgo_stage({"pgo": {}}, "candidate-use", None)
        elf = self.root / "elf"
        elf.write_bytes(b"actual candidate")
        report = {"elf": {"matches_accepted_reference": False}}
        with self.assertRaisesRegex(ValueError, "differs from frozen reference"):
            builder.verify_pgo_elf("frozen-use", elf, report)
        builder.verify_pgo_elf("candidate-use", elf, report)
        self.assertFalse(report["release_qualified"])
        self.assertEqual(report["artifact_purpose"], "unqualified-candidate")
        elf.write_bytes(b"__llvm_profile_runtime")
        with self.assertRaisesRegex(ValueError, "generation runtime"):
            builder.verify_pgo_elf("candidate-use", elf, report)

    def test_accepted_frozen_use_does_not_change_qualification_report(self):
        elf = self.root / "elf"
        elf.write_bytes(b"frozen accepted ELF")
        report = {"elf": {"matches_accepted_reference": True}}
        builder.verify_pgo_elf("frozen-use", elf, report)
        self.assertNotIn("release_qualified", report)
        self.assertNotIn("artifact_purpose", report)

    def test_map_wrapper_changes_only_static_pie_link_and_has_frozen_identity(self):
        output = self.root / "private/link.map"
        env = {"PERF_SDK_CC": str(self.linker), "PERF_LINK_MAP": str(output)}
        self.assertEqual(map_cc.command(["--version"], env), [str(self.linker), "--version"])
        self.assertEqual(map_cc.command(["-static-pie", "object.o"], env),
                         [str(self.linker), "-static-pie", "object.o", "-Wl,-Map=" + str(output)])
        with self.assertRaisesRegex(ValueError, "private absolute"):
            map_cc.command(["-static-pie"], {**env, "PERF_LINK_MAP": "relative.map"})
        shim = self.root / "map-cc"
        shim.write_bytes(b"frozen map wrapper")
        recipe = {**self.env, **env, "DNSMASQ_STATIC_PIE_CC": str(shim)}
        mapping = {"wrapper": str(shim), "wrapper_sha256": wrapper.sha(shim),
                   "sdk_cc": str(self.linker), "sdk_cc_sha256": wrapper.sha(self.linker),
                   "output_path": str(output)}
        plan = {**self.plan, "map_compiler": mapping, "recipe_environment": recipe}
        receipt = wrapper.prepare(plan, self.argv, recipe)
        self.assertEqual(receipt["map_compiler"], mapping)
        self.assertEqual(receipt["recipe_rustflags"], self.env["RUSTFLAGS"])
        shim.write_bytes(b"changed map wrapper")
        with self.assertRaisesRegex(ValueError, "wrapper or SDK compiler identity changed"):
            wrapper.prepare(plan, self.argv, recipe)


if __name__ == "__main__":
    unittest.main()
