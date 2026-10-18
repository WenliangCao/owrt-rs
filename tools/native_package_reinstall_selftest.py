#!/usr/bin/env python3
"""Verify package reinstalls repair files and reject successful no-op commands.

Run as root on an aarch64 Linux build host, with an extracted native image and
its offline APK fixtures. Every attempt uses disposable rootfs namespaces.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform

from native_image_check import Check


class SkipReinstall(Check):
    def __init__(self, source, out, stage):
        super().__init__(source, out)
        self.stage = stage
        self.skipped = 0

    def shell(self, name, root, script, success=True):
        if name == f"package-{self.stage}-reinstall":
            lines = script.splitlines()
            commands = [i for i, line in enumerate(lines)
                        if line.startswith("apk ") and " add --force-reinstall " in line]
            assert len(commands) == 1, "negative control did not locate the reinstall"
            lines[commands[0]] = ": # deliberately successful no-op reinstall"
            script = "\n".join(lines) + "\n"
            self.skipped += 1
        super().shell(name, root, script, success)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("apk_dir", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.system() == "Linux"
    assert platform.machine() == "aarch64" and not Path("/etc/openwrt_release").exists()
    source, apks, out = (p.resolve() for p in (args.rootfs, args.apk_dir, args.output))
    out.mkdir(parents=True, exist_ok=False)
    positive = Check(source, out / "real-reinstalls")
    positive.package_reinstall(apks)
    rows = []
    for stage in ("stock", "native"):
        for repeat in range(1, 5):
            check = SkipReinstall(source, out / f"skip-{stage}-{repeat}", stage)
            try:
                check.package_reinstall(apks)
            except (AssertionError, FileNotFoundError) as error:
                root = check.out / "package-reinstall"
                missing = ([root / "lib/apk/packages" / (name + ".list")
                            for name in check.manifest["stock_packages"]]
                           if stage == "stock" else [root / "usr/libexec/owrt-stock/sbin/procd"])
                assert check.skipped == 1 and all(not p.exists() for p in missing)
                result = (f"stock_package_reinstall_preserves_{check.component_word()}_Rust_files_and_dnsmasq_integration" if stage == "stock"
                          else "native_package_reinstall_preserves_Rust_and_recovery_files")
                assert result not in check.results
                rows.append({"stage": stage, "repeat": repeat, "rejected": True,
                             "missing_files": len(missing), "error_type": type(error).__name__})
            else:
                raise AssertionError(f"successful no-op {stage} reinstall was accepted")
    result = {"native_manifest_sha256": hashlib.sha256(
                  (source / "usr/share/owrt-control-plane/release.json").read_bytes()).hexdigest(),
              "real_reinstalls": positive.results, "negative_controls": rows,
              "physical_router_accessed": False}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
