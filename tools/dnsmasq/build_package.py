#!/usr/bin/env python3
"""Build and audit a dnsmasq replacement candidate in the matching SDK.

Inputs are snapshotted before prepare; output/build directories are new and
task-owned. The SDK package recipe is restored even when make fails. Full logs,
source hashes, artifacts and failure manifests remain under ignored private/.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "dnsmasq"
RECIPE = "owrt-dnsmasq"
TARGET = "aarch64-unknown-linux-musl"
ARCH = "aarch64_cortex-a53"
PACKAGE_VERSION = "2.93"
PACKAGE_RELEASE = "4"
PACKAGE_ID = f"{PACKAGE_VERSION}-r{PACKAGE_RELEASE}"
REPLACEMENT_FILES = {
    "etc/config/dhcp",
    "etc/dnsmasq.conf",
    "etc/hotplug.d/ntp/25-dnsmasqsec",
    "etc/init.d/dnsmasq",
    "etc/uci-defaults/50-dnsmasq-migrate-ipset.sh",
    "etc/uci-defaults/50-dnsmasq-migrate-resolv-conf-auto.sh",
    "usr/lib/dnsmasq/dhcp-script.sh",
    "usr/sbin/dnsmasq",
    "usr/share/acl.d/dnsmasq_acl.json",
    "usr/share/dnsmasq/dhcpbogushostname.conf",
    "usr/share/dnsmasq/rfc6761.conf",
}
PACKAGE_METADATA_FILES = {
    "lib/apk/packages/dnsmasq.conffiles",
    "lib/apk/packages/dnsmasq.conffiles_static",
    "lib/apk/packages/dnsmasq.list",
    "lib/apk/packages/dnsmasq.rusers",
    "lib/upgrade/keep.d/dnsmasq",
}
PAYLOAD_FILES = REPLACEMENT_FILES | PACKAGE_METADATA_FILES
OWNERSHIP_LIST = sorted("/" + path for path in REPLACEMENT_FILES | {
    "lib/apk/packages/dnsmasq.rusers", "lib/upgrade/keep.d/dnsmasq"
})


def package_id(release=PACKAGE_RELEASE):
    require(release in ('2', '3', '4'), 'package release must be 2, 3 or 4')
    return f'{PACKAGE_VERSION}-r{release}'


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(path):
    # The SDK's Make recipes do not quote all expanded paths. Reject shell/make
    # metacharacters before passing any caller-controlled path into that layer.
    require(re.fullmatch(r"/[A-Za-z0-9_./+-]+", str(path)), f"unsupported SDK path: {path}")
    return path


def files_below(path):
    require(path.exists() and not path.is_symlink(), f"missing or symlink input: {path}")
    values = [path] if path.is_file() else sorted(path.rglob("*"))
    for value in values:
        require(not value.is_symlink(), f"source symlink is not supported: {value}")
        if value.is_file():
            yield value


def release_manifest(version):
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version), "invalid OpenWrt release version")
    return f"manifests/release-{version}.json"


def inputs(root, version="25.12.5"):
    paths = ["rust-toolchain.toml", release_manifest(version),
             "packaging/openwrt/owrt-dnsmasq", "tools/dnsmasq/build_package.sh",
             "tools/dnsmasq/build_package.py", "components/dnsmasq/Cargo.lock",
             "components/dnsmasq/platform/Cargo.toml", "components/dnsmasq/platform/src"]
    # Historical frozen trees keep their original map; new snapshots bind the
    # compilation adapter as well as the SDK recipe that invokes it.
    if (root / "tools/mbx_cargo.sh").exists():
        paths.append("tools/mbx_cargo.sh")
    manifest = tomllib.loads((root / "components/dnsmasq/Cargo.toml").read_text())
    if any(target.get("path") == "platform/entry.rs" for target in manifest.get("bin", [])):
        # Current executables register fixed platform workers outside src/.
        # Detect the declared path, not file existence: a missing adapter must
        # fail rather than silently looking like an older frozen source tree.
        paths += ["components/dnsmasq/platform/entry.rs",
                  "components/dnsmasq/platform/register.rs",
                  "components/dnsmasq/platform/tests", "components/dnsmasq/tests"]
        for target in manifest.get("test", []):
            if "path" in target:
                paths.append("components/dnsmasq/" + target["path"])
    # Older frozen trees predate the shared core boundary; current trees must
    # bind all of it alongside ubus, without sweeping local build artifacts in.
    if (root / "components/platform/Cargo.toml").is_file():
        paths += ["components/platform/Cargo.toml", "components/platform/src"]
    for component in ("dnsmasq", "ubus"):
        paths += [f"components/{component}/Cargo.toml", f"components/{component}/src"]
    return {str(path.relative_to(root)): sha(path)
            for name in paths for path in files_below(root / name)}


def snapshot(root, destination, expected, version="25.12.5"):
    for name, digest in expected.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / name, target)
        require(sha(target) == digest, f"input changed while copying: {name}")
    require(inputs(root, version) == expected, "inputs changed during source snapshot")


def sdk_inputs(sdk):
    """Identify the pinned SDK tools used for either codegen or packaging."""
    toolchain = sdk / f"staging_dir/toolchain-{ARCH}_gcc-14.3.0_musl"
    paths = [sdk / name for name in (
        ".config", "rules.mk", "include/package.mk", "include/package-pack.mk", "include/feeds.mk",
        "scripts/rstrip.sh", "staging_dir/host/bin/apk", "staging_dir/host/bin/sstrip",
        "staging_dir/host/bin/patchelf", "staging_dir/host/bin/.apk.bin",
        "staging_dir/host/bin/.sstrip.bin", "staging_dir/host/bin/.patchelf.bin", "staging_dir/host/lib/runas.so",
        "staging_dir/host/lib/ld-linux-x86-64.so.2")]
    paths += [toolchain / name for name in ("include/stdio.h", "lib/libc.so", "lib/crt1.o")]
    # Hash the executable wrappers and their hidden .bin implementations.
    paths += [path for path in sorted((toolchain / "bin").iterdir()) if path.is_file()]
    return {str(path.relative_to(sdk)): sha(path) for path in paths}


def verify_freeze(freeze, source_files, sdk, source_commit, epoch, expected_elf_sha256, package_release=PACKAGE_RELEASE):
    """Bind a previously validated ELF to product, packaging and SDK inputs.

    source_commit identifies the product used for the ELF. source_files also
    locks the later packaging recipe and scripts; packaging does not claim
    that those later tools were part of the product commit.
    """
    require(isinstance(freeze, dict), "freeze manifest must be a JSON object")
    require(freeze.get("schema") == 1 and freeze.get("frozen") is True,
            "freeze manifest must have schema 1 and frozen=true")
    require(not freeze.get("pending"), "freeze manifest still has pending validation")
    require(freeze.get("package_release", "2") == package_release,
            "freeze manifest package release differs from --package-release")
    require(freeze.get("source_commit") == source_commit,
            "freeze manifest product commit differs from --source-commit")
    require(str(freeze.get("source_date_epoch")) == str(epoch),
            "freeze manifest source timestamp differs from --source-date-epoch")
    require(freeze.get("rust_elf_sha256") == expected_elf_sha256,
            "freeze manifest ELF differs from --expected-elf-sha256")
    locked = freeze.get("source_files")
    require(isinstance(locked, dict), "freeze manifest must contain the complete source_files map")
    require(all(isinstance(name, str) and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                for name, digest in locked.items()), "freeze source_files must map names to SHA256 hashes")
    changed = sorted(name for name in source_files.keys() | locked.keys()
                     if source_files.get(name) != locked.get(name))
    require(not changed, f"source/packaging inputs differ from freeze: {changed}")
    require(freeze.get("sdk_archive_sha256") == sdk["archive_sha256"],
            "freeze manifest SDK archive identity differs")
    require(freeze.get("sdk_files") == sdk["files"],
            "freeze manifest SDK file identities differ")
    postprocess = freeze.get("postprocess", {})
    require(isinstance(postprocess, dict) and postprocess.get("mode") in ("none", "sdk-sstrip")
            and postprocess.get("output_sha256") == expected_elf_sha256
            and isinstance(postprocess.get("input_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", postprocess["input_sha256"]),
            "freeze must identify postprocessing, including an explicit none when not applied")
    if postprocess["mode"] == "none":
        require(postprocess["input_sha256"] == expected_elf_sha256 and postprocess.get("reason"),
                "postprocess=none must preserve ELF identity and record why no extra processing ran")


@contextmanager
def package_recipe(sdk, source, out, report):
    stock = sdk / "package/network/services/dnsmasq"
    active = stock if stock.exists() else sdk / "package" / RECIPE
    report["sdk_recipe_path"] = str(active)
    # SDK discovery scans even hidden directories below package/. Keep the
    # recovery copy outside that tree so it cannot become a second recipe.
    backup = sdk / f".dnsmasq-backup-{out.name}"
    require(not backup.exists(), f"package recovery backup already exists: {backup}")
    existed = active.exists() or active.is_symlink()
    if existed:
        active.rename(backup)
    installed = False
    try:
        shutil.copytree(source, active)
        installed = True
        yield
    finally:
        if installed:
            shutil.rmtree(active)
        elif active.exists():
            # Only a failed copy into our previously absent destination can be
            # here; the original recipe remains in backup throughout the copy.
            shutil.rmtree(active)
        if existed:
            backup.rename(active)
        report["sdk_recipe_restored"] = True


def run(command, log, *, cwd=None, env=None):
    with log.open("wb") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, cwd=cwd, env=env)
    require(result.returncode == 0, f"command exited {result.returncode}; see {log}")
    return log.read_text(errors="replace")


def audit_payload(payload):
    allowed = PAYLOAD_FILES
    found = {str(path.relative_to(payload)): sha(path) for path in files_below(payload)}
    require(set(found) == allowed, f"unexpected package payload paths: {sorted(found)}")
    listing = (payload / "lib/apk/packages/dnsmasq.list").read_text().splitlines()
    require(listing == OWNERSHIP_LIST, f"unexpected package ownership list: {listing}")
    # The pinned SDK generates this from conffiles. Installing another copy
    # in the recipe makes package-pack.mk append the same directory twice.
    require((payload / "lib/upgrade/keep.d/dnsmasq").read_text() == "/etc/dnsmasq.d/\n",
            "upgrade keep file differs from the image's single directory entry")
    return found


def audit_metadata(metadata, package_release=PACKAGE_RELEASE):
    """Check replacement identity without treating adbdump text as authority."""
    identity = package_id(package_release)
    required = {
        "name": PACKAGE,
        "version": identity,
        "arch": ARCH,
    }
    for field, expected in required.items():
        require(re.search(rf"^  {re.escape(field)}: {re.escape(expected)}$", metadata, re.MULTILINE),
                f"APK metadata {field} does not identify {expected}")
    for field, values in {
        "provides": ("dnsmasq-any",),
        "depends": ("libc", "libubus20251202"),
    }.items():
        block = re.search(rf"^  {field}:.*?(?=^  [a-z]|^# data block|\Z)", metadata,
                          re.MULTILINE | re.DOTALL)
        require(block and all(re.search(rf"^    - {re.escape(value)}$", block.group(0), re.MULTILINE)
                              for value in values), f"APK metadata {field} misses required entries")
        if field == "depends":
            require(not re.search(r"^    - libgcc(?:1)?(?:[<>=~]|\s*$)", block.group(0), re.MULTILINE),
                    "static PIE package must not add a direct libgcc/libgcc1 dependency")
    for script in ("post-install", "pre-deinstall", "post-upgrade"):
        require(re.search(rf"^  {script}: \|$", metadata, re.MULTILINE),
                f"APK metadata misses {script} script")
    return {"name": PACKAGE, "version": identity,
            "arch": ARCH, "provides": ["dnsmasq-any"],
            "replacement": f"same package name dnsmasq, newer release {identity}",
            "variant_exclusion": "requires lifecycle solver tests with stock variant APKs",
            "depends": ["libc", "libubus20251202"]}


def audit_elf(data, readelf_text):
    """Check static PIE layout; runtime ASLR/RELRO is a separate gate."""
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01",
            "package ELF must be ELF64 little-endian")
    require(struct.unpack_from("<HH", data, 16) == (3, 183),
            "package ELF must be AArch64 ET_DYN")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    require(size == 56 and count > 0 and offset >= 64 and offset + count * size <= len(data),
            "invalid package ELF program headers")
    headers = [struct.unpack_from("<IIQQQQQQ", data, offset + index * size)
               for index in range(count)]
    require(all(row[2] + row[5] <= len(data) for row in headers),
            "package ELF segment exceeds file")
    loads = [row for row in headers if row[0] == 1]
    require(loads and all(row[5] <= row[6] and row[1] & 3 != 3 for row in loads),
            "package ELF has invalid or writable-executable LOAD segments")
    require(not any(row[0] == 3 for row in headers),
            "static PIE must not have a program interpreter")
    stacks = [row for row in headers if row[0] == 0x6474e551]
    require(len(stacks) == 1 and stacks[0][1] & 1 == 0,
            "package ELF must have a non-executable GNU_STACK")
    require(any(row[0] == 0x6474e552 and row[6] > 0 for row in headers),
            "package ELF must have a nonempty GNU_RELRO segment")
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", readelf_text)
    require(not needed, "static PIE must not depend on shared libraries")
    flags = re.search(r"\(FLAGS_1\)\s+Flags:\s*([^\n]+)", readelf_text)
    flags = set(flags.group(1).split()) if flags else set()
    require("PIE" in flags, "package ELF must have the PIE dynamic flag")
    require("TEXTREL" not in readelf_text, "package ELF must not use text relocations")
    require(not re.search(r"\((?:RPATH|RUNPATH)\)", readelf_text),
            "package ELF must not override the image library search path")
    return {"type": "ET_DYN", "machine": "AArch64", "linkage": "static-pie", "interpreter": None,
            "needed": [], "pie": True, "bind_now": "NOW" in flags or "(BIND_NOW)" in readelf_text,
            "gnu_relro": True, "nx_stack": True, "writable_executable_load": False,
            "runtime_protections_verified": False}


def read_budget(path):
    require(path.is_file(), f"M4 budget is missing: {path}")
    try:
        budget = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid M4 budget: {error}") from error
    require(budget.get("schema") == 1, "M4 budget schema must be 1")
    for field in ("elf_max_bytes", "apk_max_bytes"):
        require(isinstance(budget.get(field), int) and budget[field] > 0,
                f"M4 budget {field} must be a positive integer")
    result = {"schema": 1, "elf_max_bytes": budget["elf_max_bytes"],
              "apk_max_bytes": budget["apk_max_bytes"], "sha256": sha(path)}
    if "user_accepted_elf" in budget:
        accepted = budget["user_accepted_elf"]
        require(isinstance(accepted, dict) and isinstance(accepted.get("sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", accepted["sha256"])
                and accepted.get("bytes") == budget["elf_max_bytes"]
                and isinstance(accepted.get("original_target_bytes"), int)
                and 0 < accepted["original_target_bytes"] < accepted["bytes"]
                and isinstance(accepted.get("reason"), str) and accepted["reason"],
                "user ELF exception must identify the accepted bytes, SHA256, original target and reason")
        result["user_accepted_elf"] = accepted
    return result


def audit_sizes(report):
    """Retain both measurements even when either target is exceeded."""
    accepted = report["budget"].get("user_accepted_elf")
    if accepted:
        report["original_elf_target_met"] = report["elf"]["size"] <= accepted["original_target_bytes"]
        require(report["elf"].get("sha256") == accepted["sha256"]
                and report["elf"]["size"] == accepted["bytes"],
                "user ELF size exception does not authorize this artifact")
        report["size_acceptance"] = "explicit-user-exception; original ELF target remains unmet"
    report["budget_checks"] = {
        "apk": report["artifact"]["size"] <= report["budget"]["apk_max_bytes"],
        "elf": report["elf"]["size"] <= report["budget"]["elf_max_bytes"],
    }
    failures = [f"{kind.upper()} size {report[key]['size']} exceeds target "
                f"{report['budget'][kind + '_max_bytes']} bytes"
                for kind, key in (("apk", "artifact"), ("elf", "elf"))
                if not report["budget_checks"][kind]]
    if failures:
        report["failure_boundary"] = "size-target"
    require(not failures, "; ".join(failures))


def audit_build(args, out, report):
    sdk = safe_path(args.sdk.resolve())
    require(platform.system() == "Linux", "matching Linux SDK build host required")
    require(sdk.is_dir(), f"SDK is missing: {sdk}")
    version = getattr(args, "openwrt_version", "25.12.5")
    source_hashes = inputs(ROOT, version=version)
    source = out / "source"
    snapshot(ROOT, source, source_hashes, version=version)
    report["source_files"] = source_hashes
    report["source_digest"] = hashlib.sha256(json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if args.expected_source_digest:
        require(report["source_digest"] == args.expected_source_digest, "source snapshot differs from frozen input digest")
    if args.source_commit:
        require(re.fullmatch(r"[0-9a-f]{40}", args.source_commit), "source commit must be a full SHA1")
        require(args.source_date_epoch and args.source_date_epoch.isdigit() and args.expected_source_digest,
                "a copied source snapshot requires commit, epoch and frozen source digest")
        report.update(git_commit=args.source_commit, source_commit_provenance="caller; frozen source digest checked", source_git_status=None)
        epoch = args.source_date_epoch
    else:
        report["git_commit"] = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
        report["source_commit_provenance"] = "local git checkout; exact file hashes remain authoritative"
        report["source_git_status"] = subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain", "--",
            "rust-toolchain.toml", release_manifest(version), "components/dnsmasq", "components/ubus", "components/platform",
            "packaging/openwrt/owrt-dnsmasq", "tools/dnsmasq/build_package.sh", "tools/dnsmasq/build_package.py"], text=True)
        require(not report["source_git_status"], "build inputs have uncommitted changes; source commit would be inaccurate")
        epoch = subprocess.check_output(["git", "-C", str(ROOT), "show", "-s", "--format=%ct", "HEAD"], text=True).strip()
    archive_name, expected_hash = json.loads((source / release_manifest(version)).read_text())["inputs"]["sdk"].split(" sha256 ")
    require(sdk.name == archive_name.removesuffix(".tar.zst"), "SDK name differs from pinned release manifest")
    archive = sdk.parent / archive_name
    require(sha(archive) == expected_hash, "SDK archive differs from pinned release manifest")
    toolchain = sdk / f"staging_dir/toolchain-{ARCH}_gcc-14.3.0_musl"
    readelf = toolchain / "bin/aarch64-openwrt-linux-musl-readelf"
    apk = sdk / "staging_dir/host/bin/apk"
    report["sdk"] = {"path": str(sdk), "archive_sha256": expected_hash,
                     "files": sdk_inputs(sdk)}
    channel = tomllib.loads((source / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    env = os.environ.copy()
    for name in ("CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR"):
        env.pop(name, None)
    env["RUSTUP_TOOLCHAIN"] = channel
    env["SOURCE_DATE_EPOCH"] = epoch
    report["rust_channel"] = channel
    report["source_date_epoch"] = env["SOURCE_DATE_EPOCH"]
    build, output = out / "package-build", out / "sdk-output"
    report["package_release"] = args.package_release
    report["package_id"] = package_id(args.package_release)
    make_vars = ["V=s", "-j1", f"V1_PACKAGE_RELEASE={args.package_release}",
                 f"OWRT_COMPONENTS_SOURCE={source / 'components'}",
                 f"OWRT_DNSMASQ_BUILD_DIR={build}", f"OWRT_DNSMASQ_OUTPUT_DIR={output}"]
    if args.frozen_elf:
        frozen_elf = safe_path(args.frozen_elf.resolve())
        manifest = args.freeze_manifest.resolve()
        manifest_digest = sha(manifest)
        freeze = json.loads(manifest.read_text())
        verify_freeze(freeze, source_hashes, report["sdk"], args.source_commit, epoch, args.expected_elf_sha256, args.package_release)
        require(frozen_elf.is_file() and sha(frozen_elf) == args.expected_elf_sha256,
                "frozen ELF input does not match its validated identity")
        copied_elf = out / "frozen-dnsmasq"
        shutil.copy2(frozen_elf, copied_elf)
        shutil.copy2(manifest, out / "freeze-manifest.json")
        require(sha(copied_elf) == args.expected_elf_sha256 and sha(manifest) == manifest_digest
                and sha(out / "freeze-manifest.json") == manifest_digest,
                "frozen inputs changed during snapshot")
        report["build_mode"] = "package-frozen-elf"
        report["freeze_manifest_sha256"] = manifest_digest
        report["frozen_elf_input"] = {"sha256": sha(copied_elf), "size": copied_elf.stat().st_size}
        report["frozen_build_profile"] = freeze.get("build_profile")
        report["postprocess"] = freeze["postprocess"]
        report["strip_policy"] = "skip SDK RSTRIP to preserve the previously validated frozen ELF identity"
        make_vars.append(f"OWRT_DNSMASQ_FROZEN_ELF={copied_elf}")
    else:
        cargo = safe_path(Path(os.environ.get("CARGO") or shutil.which("cargo") or Path.home() / ".cargo/bin/cargo").absolute())
        require(cargo.is_file() and os.access(cargo, os.X_OK), "cargo executable missing")
        report["build_mode"] = "compile-and-package"
        report["cargo_version"] = run([str(cargo), "--version"], out / "cargo-version.log", env=env).strip()
        report["rustc_version"] = run([str(cargo.with_name("rustc")), "-Vv"], out / "rustc-version.log", env=env).strip()
        report["target_cc_version"] = run([str(toolchain / "bin/aarch64-openwrt-linux-musl-gcc"), "--version"], out / "target-cc-version.log").strip()
        adapter_root = source if (source / "tools/mbx_cargo.sh").is_file() else ROOT
        adapter = safe_path(adapter_root / "tools/mbx_cargo.sh")
        require(adapter.is_file() and os.access(adapter, os.X_OK), "mbx Cargo adapter missing")
        report["build_adapter"] = {"path": str(adapter), "sha256": sha(adapter)}
        if "tools/mbx_cargo.sh" in source_hashes:
            require(sha(adapter) == source_hashes["tools/mbx_cargo.sh"],
                    "build adapter differs from frozen source identity")
            report["build_adapter_compatibility"] = "source-snapshot-bound"
        else:
            report["build_adapter_compatibility"] = "legacy freeze has no adapter; current adapter identified separately"
        make_vars += [f"V1_CARGO={adapter}",
                      f"V1_CARGO_HOME={safe_path(Path(env.get('CARGO_HOME', str(Path.home() / '.cargo'))).resolve())}",
                      f"V1_RUSTUP_HOME={safe_path(Path(env.get('RUSTUP_HOME', str(Path.home() / '.rustup'))).resolve())}"]
    report["commands"] = []
    with (sdk / ".owrt-dnsmasq-build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with package_recipe(sdk, source / f"packaging/openwrt/{RECIPE}", out, report):
            recipe_target = Path(report["sdk_recipe_path"]).relative_to(sdk).as_posix()
            report["make_recipe_target"] = recipe_target
            for stage in ("prepare", "compile"):
                command = ["make", f"{recipe_target}/{stage}", *make_vars]
                report["commands"].append(command)
                run(command, out / f"{stage}.log", cwd=sdk, env=env)
                if stage == "prepare":
                    copied = {name.removeprefix("components/"): digest for name, digest in source_hashes.items() if name.startswith("components/")}
                    for name, expected in copied.items():
                        require(sha(build / name) == expected, f"SDK prepare copied stale source: {name}")
                    report["prepared_source_files"] = copied
                    if args.frozen_elf:
                        require(sha(build / "frozen-dnsmasq") == args.expected_elf_sha256,
                                "SDK prepare changed frozen ELF")
    artifact = output / f"packages/{ARCH}/base/{PACKAGE}-{package_id(args.package_release)}.apk"
    candidates = list(output.rglob(f"{PACKAGE}-*.apk"))
    require(candidates == [artifact], f"expected exactly the current package artifact; found {candidates}")
    shutil.copy2(artifact, out / artifact.name)
    artifact = out / artifact.name
    payload = out / "payload"
    payload.mkdir()
    run([str(apk), "extract", "--allow-untrusted", "--no-network", "--no-chown", "--destination", str(payload), str(artifact)], out / "extract.log")
    report["payload_files"] = audit_payload(payload)
    elf = payload / "usr/sbin/dnsmasq"
    elf_text = run([str(readelf), "-W", "-h", "-l", "-d", str(elf)], out / "elf-readelf.log",
                   env=dict(os.environ, LC_ALL="C"))
    report["elf_layout"] = audit_elf(elf.read_bytes(), elf_text)
    metadata = run([str(apk), "adbdump", str(artifact)], out / "apk-metadata.log")
    report["apk_metadata"] = audit_metadata(metadata, args.package_release)
    require(inputs(ROOT, version=version) == source_hashes, "source changed while building; artifact is not current")
    if args.frozen_elf:
        require(sha(out / "frozen-dnsmasq") == args.expected_elf_sha256,
                "frozen ELF snapshot changed while packaging")
        require(sdk_inputs(sdk) == report["sdk"]["files"], "SDK inputs changed while packaging")
    report["artifact"] = {"name": artifact.name, "sha256": sha(artifact), "size": artifact.stat().st_size}
    report["elf"] = {"sha256": sha(elf), "size": elf.stat().st_size, "install_path": "/usr/sbin/dnsmasq"}
    (out / "SHA256SUMS").write_text(f"{sha(artifact)}  {artifact.name}\n{sha(elf)}  payload/usr/sbin/dnsmasq\n")
    report["elf"]["source_commit"] = report["git_commit"]
    report["elf"]["expected_sha256"] = args.expected_elf_sha256
    require(report["elf"]["sha256"] == args.expected_elf_sha256,
            "packaged ELF differs from the frozen ELF; retain artifact and investigate build inputs")
    report["artifact_identity_verified"] = True
    audit_sizes(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdk", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--openwrt-version", default="25.12.5",
                        help="explicit SDK release; old frozen inputs default to 25.12.5")
    parser.add_argument("--package-release", choices=["2", "3", "4"], default=PACKAGE_RELEASE,
                        help="APK release; default 4, historical M5/M6b replays use 2/3")
    parser.add_argument("--budget", type=Path, required=True,
                        help="frozen JSON with elf_max_bytes/apk_max_bytes")
    parser.add_argument("--source-commit", help="original commit of a copied source snapshot")
    parser.add_argument("--source-date-epoch", help="original commit timestamp for that snapshot")
    parser.add_argument("--expected-source-digest", help="freeze SHA256 over the sorted input hash map")
    parser.add_argument("--expected-elf-sha256", required=True,
                        help="SHA256 of the final validated and frozen ELF")
    parser.add_argument("--frozen-elf", type=Path,
                        help="package this previously stripped, validated ELF without codegen or further stripping")
    parser.add_argument("--freeze-manifest", type=Path,
                        help="schema-1 freeze identity with complete source_files and sdk_files maps")
    args = parser.parse_args()
    require(bool(args.frozen_elf) == bool(args.freeze_manifest),
            "--frozen-elf and --freeze-manifest must be supplied together")
    require(not args.frozen_elf or args.source_commit,
            "frozen ELF packaging requires --source-commit")
    require(re.fullmatch(r"[0-9a-f]{64}", args.expected_elf_sha256), "frozen ELF SHA256 must be 64 lowercase hex digits")
    out = safe_path(args.out.resolve())
    budget_path = safe_path(args.budget.resolve())
    require(out.is_relative_to(ROOT / "private") and out != ROOT / "private", "output must be a new task directory below private/")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.mkdir()  # Refuse reused outputs before touching SDK state.
    report = {"package": PACKAGE, "recipe": RECIPE, "target": TARGET, "activation": "unvalidated-package",
              "physical_router": False, "status": "building",
              "scope": "APK build audit only; lifecycle and deployment acceptance are separate"}
    def interrupted(signum, frame):
        # Unwind the recipe context on bounded harness cancellation as well
        # as ordinary make failures. The manifest remains a failed attempt.
        raise InterruptedError(f"package build interrupted by signal {signum}")
    previous_signals = {number: signal.signal(number, interrupted)
                        for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        report["budget"] = read_budget(budget_path)
        audit_build(args, out, report)
        report["status"] = "built-and-audited"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        for number, handler in previous_signals.items(): signal.signal(number, handler)
        report["warnings"] = [line for log in out.glob("*.log") for line in log.read_text(errors="replace").splitlines()
                              if "warning" in line.lower() or "ld.so" in line.lower()]
        (out / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "package", "activation")}))
    return int(report["status"] != "built-and-audited")


if __name__ == "__main__":
    raise SystemExit(main())
