#!/usr/bin/env python3
"""Release promotion regressions using synthetic artifacts, never a router."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "tools/native_release_prepare.py"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.canonical = self.root / "canonical"
        self.canonical.mkdir()
        self.output = self.root / "release"
        self.source = subprocess.check_output(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()
        firmware = b"synthetic firmware fixture\n"
        (self.canonical / "fixture.bin").write_bytes(firmware)
        components = json.loads((REPO / "packaging/image/native-25.12.5.json").read_text())["components"]
        components.pop("dnsmasq", None)  # This helper retains the historical Rust9 tag contract.
        for value in components.values():
            value.update(rust_sha256="0"*64, rust_bytes=1,
                         recovery_path="/usr/libexec/owrt-stock"+value["path"])
        self.manifest = {
            "deployment_layout": "native-nine", "source_commit": self.source,
            "openwrt": "25.12.6", "profile": "xiaomi_mi-router-ax3000t",
            "packages": {"owrt-control-plane": "0.2.3-r4"},
            "image": {"file": "fixture.bin", "size": len(firmware), "sha256": digest(firmware)},
            "components": components, "apk_sha256": {}, "stock_packages": {},
            "stock_image": {"url": "https://example.invalid/fixture.bin", "sha256": "1"*64},
            "kernel_sha256": "2"*64, "toolchain": {"fixture": True},
        }
        self.validation = {
            "status": "native_nine_firmware_qualified_and_cleaned",
            "firmware_source_commit": self.source, "firmware_sha256": digest(firmware),
            "scope": {"physical_power_cycle_tested": True},
            "cleanup": {"temporary_guard_removed": True, "C_fallback_occurred": False},
            "canonical_run": 123,
            "firmware_identity": {"ROM_regular_file_hashes_match_canonical": 923,
                                  "installed_package_versions_match_canonical": 167},
            "configuration": {"config_files_unchanged": 21, "other_protected_files_unchanged": 11},
            "continuous_client_health_s": 181,
            "physical_retest": {"successful_trials_observed": 2},
        }
        self.validation_path = self.root / "validation.json"
        (self.canonical / "build-inputs.json").write_text('{}\n')
        (self.canonical / "binary-sha256.txt").write_text('synthetic fixture\n')
        self.save()

    def save(self):
        (self.canonical / "manifest.json").write_text(json.dumps(self.manifest))
        self.validation_path.write_text(json.dumps(self.validation))
        (self.canonical / "SHA256SUMS").write_text("".join(
            f"{digest(p.read_bytes())}  {p.name}\n" for p in sorted(self.canonical.iterdir())
            if p.name != "SHA256SUMS"))

    def run_tool(self, tag="ax3000t-rust9-v0.2.3"):
        return subprocess.run([sys.executable, str(TOOL), str(self.canonical),
                               str(self.validation_path), tag, self.source, str(self.output)],
                              cwd=REPO, text=True, capture_output=True, timeout=20)

    def test_next_release_uses_actual_versions_counts_and_image(self):
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        release = json.loads((self.output / "release-manifest.json").read_text())
        self.assertEqual(release["unified_package"]["version"], "0.2.3-r4")
        self.assertEqual(release["qualification"]["ROM_files_verified"], 923)
        self.assertEqual(release["qualification"]["installed_package_versions_verified"], 167)
        firmware = self.output / "owrt-rust9-v0.2.3-openwrt-25.12.6-ax3000t-sysupgrade.bin"
        self.assertEqual(firmware.read_bytes(), (self.canonical / "fixture.bin").read_bytes())
        notes = (self.output / "RELEASE_NOTES.md").read_text()
        self.assertIn("21 份系统配置及 11 份额外保护文件", notes)
        self.assertNotIn("v0.1.0", notes)
        self.assertNotIn("12.17 MiB", notes)
        for line in (self.output / "SHA256SUMS").read_text().splitlines():
            sha, name = line.split(None, 1)
            self.assertEqual(digest((self.output / name).read_bytes()), sha)

    def test_mismatched_validation_source_is_rejected(self):
        self.validation["firmware_source_commit"] = "f"*40
        self.save()
        self.assertNotEqual(self.run_tool().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_corrupt_artifact_is_rejected(self):
        (self.canonical / "fixture.bin").write_bytes(b"corrupted")
        self.assertNotEqual(self.run_tool().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_wrong_hardware_profile_is_rejected(self):
        self.manifest["profile"] = "unrelated-router"
        self.save()
        self.assertNotEqual(self.run_tool().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_unexpected_tag_is_rejected(self):
        self.assertNotEqual(self.run_tool("v0.2.3").returncode, 0)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
