#!/usr/bin/env python3
"""Build the checked-out dnsmasq revision for OpenWrt and reject compiler warnings.

This produces diagnostic ELF/APK evidence only. The default CLI builds plain;
a candidate caller can supply a frozen PGO spec. It never builds firmware,
publishes, installs or deploys.
"""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import shutil
import subprocess

import ci_build_dnsmasq as builder
from dnsmasq.compiler_warnings import scan


def source_spec():
    files = builder.audit.inputs(builder.REPO)
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    commit = subprocess.check_output(["git", "-C", str(builder.REPO), "rev-parse", "HEAD"], text=True).strip()
    spec = {"source_commit": commit, "source_digest": digest,
            "package_release": "4", "reference_elf_sha256": None,
            "elf_max_bytes": 2_500_000, "apk_max_bytes": 1_400_000}
    builder.source_identity(spec)  # Reject dirty product/recipe inputs before archiving.
    return spec


def freeze_source(out, spec):
    # Git, not the current checkout, supplies every product/recipe input.
    files = builder.audit.inputs(builder.REPO)
    archive = out / "source.tar"
    subprocess.run(["git", "-C", str(builder.REPO), "archive", "--format=tar",
                    "--output", str(archive), spec["source_commit"], "--", *files], check=True)
    frozen = out / "frozen-source"
    frozen.mkdir()
    subprocess.run(["tar", "-xf", str(archive), "-C", str(frozen)], check=True)
    files, digest = builder.source_identity(spec, frozen)
    builder.audit.require(len(files) == spec.get("source_file_count", len(files)),
                          "frozen source input count differs from candidate")
    builder.write(out / "source-manifest.json", {
        "commit": spec["source_commit"], "digest": digest, "files": files,
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
    retained = [path for pattern in ("*.apk", "*.log", "source.tar", "source-manifest.json", "dnsmasq-rs",
                                    "pgo/*", "pgo-compilation/*", "pgo-*.json", "pgo-cargo")
                for path in out.glob(pattern) if path.is_file()]
    report["retained"] = {str(path.relative_to(out)): {"bytes": path.stat().st_size, "sha256": builder.audit.sha(path)}
                          for path in sorted(retained)}


def run(work, *, spec=None, pgo_stage="frozen-use"):
    builder.audit.require(platform.system() == "Linux" and platform.machine() == "x86_64",
                          "native x86_64 Linux host required; no SDK wrapper modifications")
    out = work / "out/dnsmasq"
    out.mkdir(parents=True, exist_ok=False)
    report = {"status": "building", "scope": "diagnostic target build only; not accepted for deployment",
              "pgo": False, "firmware_built": False, "physical_boot_tested": False, "release_qualified": False,
              "runner_commit": subprocess.check_output(
                  ["git", "-C", str(builder.REPO), "rev-parse", "HEAD"], text=True).strip()}
    try:
        if spec is None:
            spec = source_spec()
        if "pgo" in spec:
            report["pgo_stage"] = pgo_stage
            report["artifact_purpose"] = {"generate": "instrumented-training-only",
                                          "candidate-use": "unqualified-candidate",
                                          "frozen-use": "frozen-reference-reproduction"}[pgo_stage]
        builder.write(out / "build-spec.json", spec)
        frozen = freeze_source(out, spec)
        prepare_sdk(work, out, frozen)
        builder.build(work, spec, report, frozen_source=frozen, pgo_stage=pgo_stage)
        if "reference_elf_bytes" in spec:
            builder.audit.require(report["elf"]["size"] == spec["reference_elf_bytes"],
                                  "fresh CI ELF size differs from frozen reference")
        warnings = scan(sorted(out.glob("*.log")))
        report["warnings"] = warnings
        builder.audit.require(warnings["strict_compiler_warnings_zero"],
                              "Rust/Cargo or unclassified compiler warning; see warnings.json and original logs")
        compile_log = (out / "compile.log").read_text(errors="replace")
        builder.audit.require("dnsmasq-platform" in compile_log and "dnsmasq-rs" in compile_log,
                              "target product/platform compilation evidence missing")
        report["status"] = "passed-target-build-and-zero-compiler-warnings"
        if pgo_stage == "generate":
            report["status"] = "built-instrumented-training-only"
        elif pgo_stage == "candidate-use":
            report["status"] = "created-unqualified-pgo-candidate"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        if "accepted_product_commit" in report:
            report["checked_product_commit"] = report.pop("accepted_product_commit")
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
