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
        for name in ["owrt-ubus-abcd", "dnsmasq-rs-efab", "unrelated-1234"]:
            folder = target / ".fingerprint" / name
            folder.mkdir(parents=True)
            (folder / "lib.json").write_text('{"metadata":"actual"}')
        packages = self.root / "packages"
        packages.mkdir()
        (packages / "dnsmasq-2.93-r4.apk").write_bytes(b"actual-package")
        report = {"pgo": {}}
        builder.retain_pgo_compilation(self.root, build, packages, report)
        evidence = self.root / "pgo-compilation"
        self.assertEqual((evidence / "dnsmasq-prestrip").read_bytes(), b"compiled-elf")
        self.assertEqual((evidence / "dnsmasq-2.93-r4.apk").read_bytes(), b"actual-package")
        self.assertEqual(set(json.loads((evidence / "cargo-fingerprints.json").read_text())),
                         {"owrt-ubus-abcd/lib.json", "dnsmasq-rs-efab/lib.json"})

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
        report = {"pgo": {"profile_sha256": self.plan["profile_sha256"]}}
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


if __name__ == "__main__":
    unittest.main()
