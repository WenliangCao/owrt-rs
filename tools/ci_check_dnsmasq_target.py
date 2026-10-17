#!/usr/bin/env python3
"""One plain SDK build of frozen stage1, with strict compiler warning denial.

This produces diagnostic ELF/APK evidence only; it has no PGO, firmware,
publication, installation or deployment path.
"""
import argparse
import json
import platform
from pathlib import Path
import shutil
import subprocess

import ci_build_dnsmasq as builder
from dnsmasq.compiler_warnings import scan


SOURCE_COMMIT = "08f665502ad0ef72f3a33fcc5717ff1fea9e50f7"
SOURCE_DIGEST = "5d1c283e5603a1d943312fa92d3b9cf80cb3d29c86fcb90385eb9ff74bfbb379"
SPEC = {"source_commit": SOURCE_COMMIT, "source_digest": SOURCE_DIGEST,
        "package_release": "4", "reference_elf_sha256": None,
        "elf_max_bytes": 2_500_000, "apk_max_bytes": 1_400_000}


def freeze_source(out):
    # Git, not the current checkout, supplies every product/recipe input.
    files = builder.audit.inputs(builder.REPO)
    archive = out / "source.tar"
    subprocess.run(["git", "-C", str(builder.REPO), "archive", "--format=tar",
                    "--output", str(archive), SOURCE_COMMIT, "--", *files], check=True)
    frozen = out / "frozen-source"
    frozen.mkdir()
    subprocess.run(["tar", "-xf", str(archive), "-C", str(frozen)], check=True)
    files, digest = builder.source_identity(SPEC, frozen)
    builder.write(out / "source-manifest.json", {
        "commit": SOURCE_COMMIT, "digest": digest, "files": files,
        "archive_sha256": builder.audit.sha(archive)})
    return frozen


def prepare_sdk(work, out, frozen):
    manifest = json.loads((frozen / "manifests/release-25.12.5.json").read_text())
    name, expected = manifest["inputs"]["sdk"].split(" sha256 ")
    download = work / "dl" / name
    download.parent.mkdir(parents=True, exist_ok=True)
    if not download.exists():
        url = "https://downloads.openwrt.org/releases/25.12.5/targets/mediatek/filogic/" + name
        builder.audit.run(["curl", "--fail", "--show-error", "--location", "--output",
                           str(download), url], out / "sdk-download.log")
    builder.audit.require(builder.audit.sha(download) == expected, "SDK archive checksum mismatch")
    sdk = work / name.removesuffix(".tar.zst")
    builder.audit.require(not sdk.exists(), "target validation requires a fresh extracted SDK")
    builder.audit.run(["tar", "-xf", str(download), "-C", str(work)], out / "sdk-extract.log")
    if not (sdk / ".config").exists():
        builder.audit.run(["make", "defconfig"], out / "sdk-defconfig.log", cwd=sdk)


def retain_outputs(out, report):
    # The complete build log and original SDK outputs survive every failure.
    elf = out / "payload/usr/sbin/dnsmasq"
    if elf.is_file():
        shutil.copy2(elf, out / "dnsmasq-rs")
    artifacts = [path for path in out.glob("*.apk") if path.is_file()]
    if not artifacts:
        for package in (out / "sdk-output").rglob("dnsmasq-*.apk"):
            shutil.copy2(package, out / package.name)
    retained = [path for pattern in ("*.apk", "*.log", "source.tar", "source-manifest.json", "dnsmasq-rs")
                for path in out.glob(pattern) if path.is_file()]
    report["retained"] = {path.name: {"bytes": path.stat().st_size, "sha256": builder.audit.sha(path)}
                          for path in sorted(retained)}


def run(work):
    builder.audit.require(platform.system() == "Linux" and platform.machine() == "x86_64",
                          "native x86_64 Linux host required; no SDK wrapper modifications")
    out = work / "out/dnsmasq"
    out.mkdir(parents=True, exist_ok=False)
    report = {"status": "building", "scope": "diagnostic target build only; not accepted for deployment",
              "pgo": False, "firmware_built": False, "physical_boot_tested": False,
              "runner_commit": subprocess.check_output(
                  ["git", "-C", str(builder.REPO), "rev-parse", "HEAD"], text=True).strip()}
    try:
        frozen = freeze_source(out)
        prepare_sdk(work, out, frozen)
        builder.build(work, SPEC, report, frozen_source=frozen)
        report["frozen_product_commit"] = report.pop("accepted_product_commit")
        warnings = scan(sorted(out.glob("*.log")))
        report["warnings"] = warnings
        builder.audit.require(warnings["strict_compiler_warnings_zero"],
                              "Rust/Cargo or unclassified compiler warning; see warnings.json and original logs")
        compile_log = (out / "compile.log").read_text(errors="replace")
        builder.audit.require("dnsmasq-platform" in compile_log and "dnsmasq-rs" in compile_log,
                              "target product/platform compilation evidence missing")
        report["status"] = "passed-target-build-and-zero-compiler-warnings"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        report["warnings"] = scan(sorted(out.glob("*.log")))
        builder.write(out / "warnings.json", report["warnings"])
        retain_outputs(out, report)
        builder.write(out / "manifest.json", report)
    print(json.dumps({key: report[key] for key in ("status", "elf", "artifact", "warnings")}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    args = parser.parse_args()
    run(builder.audit.safe_path(args.work.resolve()))


if __name__ == "__main__":
    main()
