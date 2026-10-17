#!/usr/bin/env python3
"""Compile accepted dnsmasq through its unchanged SDK recipe and frozen PGO input.

PGO releases require the fresh canonical-host ELF to equal the accepted artifact;
source/profile identity alone never qualifies a different executable.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tomllib
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent / "dnsmasq"))
import build_package as audit


REPO = Path(__file__).resolve().parent.parent


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def profile_asset(url):
    """Require one literal GitHub release asset; gh handles private-repo auth."""
    parsed = urlsplit(url)
    parts = [unquote(part) for part in parsed.path.strip("/").split("/")]
    audit.require(parsed.scheme == "https" and parsed.netloc == "github.com"
                  and not parsed.query and not parsed.fragment and len(parts) == 6
                  and parts[2:4] == ["releases", "download"], "expected fixed GitHub profile release URL")
    audit.require(all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) and part not in (".", "..")
                      for part in (parts[0], parts[1], parts[4], parts[5])),
                  "profile release URL must name literal owner/repo/tag/asset")
    return "/".join(parts[:2]), parts[4], parts[5]


def download_profile(spec, out):
    repo, tag, name = profile_asset(spec["profile_url"])
    audit.require(re.fullmatch(r"[0-9a-f]{64}", spec["profile_sha256"])
                  and isinstance(spec["profile_bytes"], int) and spec["profile_bytes"] > 0,
                  "invalid frozen PGO profile identity")
    directory = out / "pgo"
    directory.mkdir()
    command = ["gh", "release", "download", tag, "--repo", repo,
               "--pattern", name, "--dir", str(directory)]
    audit.run(command, out / "profile-download.log")
    profile = directory / name
    audit.require(profile.is_file() and profile.stat().st_size == spec["profile_bytes"]
                  and audit.sha(profile) == spec["profile_sha256"], "downloaded PGO profile differs from freeze")
    return profile, command


def verify_pgo_build(out, report):
    invocation = out / "pgo-invocation.json"
    audit.require(invocation.is_file(), "SDK compilation did not invoke the PGO Cargo wrapper")
    receipt = json.loads(invocation.read_text())
    audit.require(receipt["mode"] == "use" and receipt["profile_sha256"] == report["pgo"]["profile_sha256"],
                  "PGO invocation does not match the frozen profile")
    log = (out / "compile.log").read_text(errors="replace")
    bad = re.findall(r"^.*(?:no profile data available|hash mismatch|control flow change|profile data may be out of date|malformed instrumentation profile|unsupported instrumentation profile).*$",
                     log, re.I | re.M)
    audit.require(not bad, "profile missing/mismatch/invalid diagnostics: " + repr(bad[:5]))
    audit.require("-Cprofile-generate" not in receipt["effective_rustflags"], "instrumented build is not a release")
    report["pgo"].update(invocation=receipt, invocation_sha256=audit.sha(invocation),
                         profile_diagnostics=bad, compile_warning_lines=sum("warning:" in line for line in log.splitlines()))


def source_identity(spec):
    files = audit.inputs(REPO)
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    audit.require(digest == spec["source_digest"], "dnsmasq source/SDK recipe differs from accepted main product")
    status = subprocess.check_output(["git", "-C", str(REPO), "status", "--porcelain", "--", *files], text=True)
    audit.require(not status, "dnsmasq release inputs have uncommitted changes")
    return files, digest


def build(work, spec, report):
    files, digest = source_identity(spec)
    out = work / "out/dnsmasq"
    source = out / "source"
    audit.snapshot(REPO, source, files)
    report.update(source_files=files, source_digest=digest,
                  source_commit=subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip(),
                  accepted_product_commit=spec["source_commit"], build_mode="compile-and-package")
    epoch = subprocess.check_output(["git", "-C", str(REPO), "show", "-s", "--format=%ct", "HEAD"], text=True).strip()
    archive_name, archive_hash = json.loads((source / "manifests/release-25.12.5.json").read_text())["inputs"]["sdk"].split(" sha256 ")
    archive = work / "dl" / archive_name
    audit.require(audit.sha(archive) == archive_hash, "SDK archive differs from accepted release")
    sdk = work / archive_name.removesuffix(".tar.zst")
    audit.require(sdk.is_dir(), "matching extracted SDK is missing")
    report["sdk"] = {"name": sdk.name, "archive_sha256": archive_hash, "files": audit.sdk_inputs(sdk)}
    toolchain = sdk / "staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl"
    env = os.environ.copy()
    for name in ("CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC",
                 "RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR"):
        env.pop(name, None)
    for name in list(env):
        if name.startswith("CARGO_PROFILE_") or name == "LLVM_PROFILE_FILE":
            env.pop(name)
    env["RUSTUP_TOOLCHAIN"] = tomllib.loads((source / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    env["SOURCE_DATE_EPOCH"] = epoch
    cargo = audit.safe_path(Path(shutil.which("cargo") or "").absolute())
    audit.require(cargo.is_file(), "cargo executable missing")
    report["toolchain"] = {
        "cargo": audit.run([str(cargo), "--version"], out / "cargo-version.log", env=env).strip(),
        "rustc": audit.run([str(cargo.with_name("rustc")), "-Vv"], out / "rustc-version.log", env=env).strip(),
        "target_cc": audit.run([str(toolchain / "bin/aarch64-openwrt-linux-musl-gcc"), "--version"], out / "target-cc-version.log").strip(),
    }
    build_dir, output = out / "package-build", out / "sdk-output"
    cargo_home = audit.safe_path(Path(env.get("CARGO_HOME", str(Path.home() / ".cargo"))).resolve())
    rustup_home = audit.safe_path(Path(env.get("RUSTUP_HOME", str(Path.home() / ".rustup"))).resolve())
    build_cargo = cargo
    if "pgo" in spec:
        audit.require(env["RUSTUP_TOOLCHAIN"] == "1.98.1", "K PGO requires pinned Rust 1.98.1")
        profile, download = download_profile(spec["pgo"], out)
        build_cargo = out / "pgo-cargo"
        shutil.copy2(REPO / "tools/ci_dnsmasq_pgo_cargo.py", build_cargo)
        build_cargo.chmod(0o755)
        cc = str(toolchain / "bin/aarch64-openwrt-linux-musl-gcc")
        flags = (f"-Cforce-unwind-tables=no --remap-path-prefix={build_dir}=/build "
                 f"--remap-path-prefix={cargo_home}=/cargo -Clink-arg=-fuse-ld=bfd "
                 "-Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now "
                 "-Clink-arg=-Wl,-z,relro -Crelocation-model=pie -Ctarget-feature=+crt-static")
        plan = {"cargo": str(cargo), "build_dir": str(build_dir), "profile": str(profile),
                "profile_sha256": spec["pgo"]["profile_sha256"], "profile_bytes": spec["pgo"]["profile_bytes"],
                "receipt": str(out / "pgo-invocation.json"),
                "static_pie_linker_sha256": audit.sha(source / "packaging/openwrt/owrt-dnsmasq/static-pie-linker.py"),
                "recipe_environment": {"RUSTUP_TOOLCHAIN": "1.98.1", "CARGO_HOME": str(cargo_home),
                    "RUSTUP_HOME": str(rustup_home), "CARGO_BUILD_TARGET": "aarch64-unknown-linux-musl",
                    "CARGO_PROFILE_RELEASE_PANIC": "abort", "RUSTFLAGS": flags,
                    "DNSMASQ_STATIC_PIE_CC": cc}}
        plan_path = out / "pgo-plan.json"
        write(plan_path, plan)
        env["DNSMASQ_PGO_BUILD_PLAN"] = str(plan_path)
        report["pgo"] = {**spec["pgo"], "download_command": download, "plan_sha256": audit.sha(plan_path),
                         "wrapper_sha256": audit.sha(build_cargo), "mode": "use", "training_repeated": False}
    variables = ["V=s", "-j1", f"V1_PACKAGE_RELEASE={spec['package_release']}",
                 f"OWRT_COMPONENTS_SOURCE={source / 'components'}", f"OWRT_DNSMASQ_BUILD_DIR={build_dir}",
                 f"OWRT_DNSMASQ_OUTPUT_DIR={output}", f"V1_CARGO={build_cargo}",
                 f"V1_CARGO_HOME={cargo_home}", f"V1_RUSTUP_HOME={rustup_home}"]
    report["commands"] = []
    with (sdk / ".owrt-dnsmasq-build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with audit.package_recipe(sdk, source / "packaging/openwrt/owrt-dnsmasq", out, report):
            target = Path(report["sdk_recipe_path"]).relative_to(sdk).as_posix()
            for stage in ("prepare", "compile"):
                command = ["make", f"{target}/{stage}", *variables]
                report["commands"].append(command)
                audit.run(command, out / f"{stage}.log", cwd=sdk, env=env)
                if stage == "prepare":
                    for name, expected in files.items():
                        if name.startswith("components/"):
                            audit.require(audit.sha(build_dir / name.removeprefix("components/")) == expected,
                                          f"SDK prepare copied stale source: {name}")
    if "pgo" in spec:
        verify_pgo_build(out, report)
    packages = list(output.rglob("dnsmasq-*.apk"))
    package_id = audit.package_id(spec["package_release"])
    audit.require(len(packages) == 1 and packages[0].name == f"dnsmasq-{package_id}.apk",
                  f"unexpected dnsmasq SDK outputs: {packages}")
    artifact = out / packages[0].name
    shutil.copy2(packages[0], artifact)
    payload = out / "payload"
    payload.mkdir()
    apk = sdk / "staging_dir/host/bin/apk"
    audit.run([str(apk), "extract", "--allow-untrusted", "--no-network", "--no-chown",
               "--destination", str(payload), str(artifact)], out / "extract.log")
    report["payload_files"] = audit.audit_payload(payload)
    elf = payload / "usr/sbin/dnsmasq"
    readelf = toolchain / "bin/aarch64-openwrt-linux-musl-readelf"
    text = audit.run([str(readelf), "-W", "-h", "-l", "-d", str(elf)], out / "elf-readelf.log",
                     env=dict(os.environ, LC_ALL="C"))
    report["elf_layout"] = audit.audit_elf(elf.read_bytes(), text)
    metadata = audit.run([str(apk), "adbdump", str(artifact)], out / "apk-metadata.log")
    report["apk_metadata"] = audit.audit_metadata(metadata, spec["package_release"])
    audit.require(audit.inputs(REPO) == files, "dnsmasq source changed while building")
    report["elf"] = {"sha256": audit.sha(elf), "size": elf.stat().st_size,
                     "reference_sha256": spec["reference_elf_sha256"],
                     "matches_accepted_reference": audit.sha(elf) == spec["reference_elf_sha256"]}
    if "pgo" in spec:
        audit.require(report["elf"]["matches_accepted_reference"],
                      "fresh CI PGO ELF differs from accepted K; preserve evidence and investigate, never substitute the reference")
        audit.require(b"__llvm_profile_runtime" not in elf.read_bytes(), "profile generation runtime in release ELF")
    report["artifact"] = {"name": artifact.name, "sha256": audit.sha(artifact), "size": artifact.stat().st_size}
    report["budget"] = {key: spec[key] for key in ("elf_max_bytes", "apk_max_bytes")}
    audit.audit_sizes(report)
    report["binary_sha256"] = {"dnsmasq-rs": audit.sha(elf)}
    report["source_date_epoch"] = epoch
    report["physical_boot_tested"] = False
    report["status"] = "built-and-audited"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    args = parser.parse_args()
    work = audit.safe_path(args.work.resolve())
    image_spec = json.loads((REPO / "packaging/image/native-25.12.5.json").read_text())
    audit.require(platform.system() == "Linux", "matching Linux SDK build host required")
    audit.require(os.environ.get("OPENWRT_VERSION") == image_spec["openwrt"], "release version differs from pinned image")
    spec = image_spec["dnsmasq_build"]
    out = work / "out/dnsmasq"
    out.mkdir(parents=True, exist_ok=False)
    report = {"status": "building", "scope": "Fresh SDK build; final image runtime acceptance remains separate"}
    def interrupted(signum, frame):
        raise InterruptedError(f"dnsmasq release build interrupted by signal {signum}")
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        build(work, spec, report)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        write(out / "manifest.json", report)
    print(json.dumps({key: report[key] for key in ("status", "elf", "artifact")}, indent=2))


if __name__ == "__main__":
    main()
