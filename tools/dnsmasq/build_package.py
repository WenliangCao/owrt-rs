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
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "dnsmasq"
RECIPE = "owrt-dnsmasq"
TARGET = "aarch64-unknown-linux-musl"
ARCH = "aarch64_cortex-a53"
PACKAGE_VERSION = "2.93"
PACKAGE_RELEASE = "2"
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


def inputs(root):
    paths = ["rust-toolchain.toml", "manifests/release-25.12.5.json",
             "packaging/openwrt/owrt-dnsmasq", "tools/dnsmasq/build_package.sh",
             "tools/dnsmasq/build_package.py", "components/dnsmasq/Cargo.lock"]
    for component in ("dnsmasq", "ubus"):
        paths += [f"components/{component}/Cargo.toml", f"components/{component}/src"]
    return {str(path.relative_to(root)): sha(path)
            for name in paths for path in files_below(root / name)}


def snapshot(root, destination, expected):
    for name, digest in expected.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / name, target)
        require(sha(target) == digest, f"input changed while copying: {name}")
    require(inputs(root) == expected, "inputs changed during source snapshot")


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
    return found


def audit_metadata(metadata):
    """Check replacement identity without treating adbdump text as authority."""
    required = {
        "name": PACKAGE,
        "version": PACKAGE_ID,
        "arch": ARCH,
    }
    for field, expected in required.items():
        require(re.search(rf"^  {re.escape(field)}: {re.escape(expected)}$", metadata, re.MULTILINE),
                f"APK metadata {field} does not identify {expected}")
    for field, values in {
        "provides": ("dnsmasq-any",),
        "conflicts": ("dnsmasq-dhcpv6", "dnsmasq-full"),
        "depends": ("libc", "libubus20251202"),
    }.items():
        block = re.search(rf"^  {field}:.*?(?=^  [a-z]|^# data block|\Z)", metadata,
                          re.MULTILINE | re.DOTALL)
        require(block and all(re.search(rf"^    - {re.escape(value)}$", block.group(0), re.MULTILINE)
                              for value in values), f"APK metadata {field} misses required entries")
    return {"name": PACKAGE, "version": PACKAGE_ID,
            "arch": ARCH, "provides": ["dnsmasq-any"],
            "conflicts": ["dnsmasq-dhcpv6", "dnsmasq-full"],
            "replacement": "same package name dnsmasq, newer release 2.93-r2",
            "depends": ["libc", "libubus20251202"]}


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
    return {"schema": 1, "elf_max_bytes": budget["elf_max_bytes"],
            "apk_max_bytes": budget["apk_max_bytes"], "sha256": sha(path)}


def audit_build(args, out, report):
    sdk = safe_path(args.sdk.resolve())
    require(platform.system() == "Linux", "matching Linux SDK build host required")
    require(sdk.is_dir(), f"SDK is missing: {sdk}")
    source_hashes = inputs(ROOT)
    source = out / "source"
    snapshot(ROOT, source, source_hashes)
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
            "components/dnsmasq", "components/ubus", "packaging/openwrt/owrt-dnsmasq", "tools/dnsmasq/build_package.sh", "tools/dnsmasq/build_package.py"], text=True)
        epoch = subprocess.check_output(["git", "-C", str(ROOT), "show", "-s", "--format=%ct", "HEAD"], text=True).strip()
    archive_name, expected_hash = json.loads((source / "manifests/release-25.12.5.json").read_text())["inputs"]["sdk"].split(" sha256 ")
    require(sdk.name == archive_name.removesuffix(".tar.zst"), "SDK name differs from pinned release manifest")
    archive = sdk.parent / archive_name
    require(sha(archive) == expected_hash, "SDK archive differs from pinned release manifest")
    toolchain = sdk / f"staging_dir/toolchain-{ARCH}_gcc-14.3.0_musl"
    readelf = toolchain / "bin/aarch64-openwrt-linux-musl-readelf"
    apk = sdk / "staging_dir/host/bin/apk"
    identity_paths = [sdk / ".config", sdk / "rules.mk", sdk / "include/package.mk",
                      sdk / "include/package-pack.mk", sdk / "include/feeds.mk",
                      toolchain / "include/stdio.h", toolchain / "lib/libc.so", toolchain / "lib/crt1.o",
                      readelf, apk, sdk / "staging_dir/host/lib/runas.so",
                      sdk / "staging_dir/host/lib/ld-linux-x86-64.so.2"]
    # This SDK ships executable wrappers and hidden .bin tools. Hash both,
    # including linker variants, instead of identifying only a shell wrapper.
    identity_paths += [path for path in sorted((toolchain / "bin").iterdir()) if path.is_file()]
    report["sdk"] = {"path": str(sdk), "archive_sha256": expected_hash,
                     "files": {str(path.relative_to(sdk)): sha(path) for path in identity_paths}}
    channel = tomllib.loads((source / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    cargo = safe_path(Path(os.environ.get("CARGO") or shutil.which("cargo") or Path.home() / ".cargo/bin/cargo").absolute())
    require(cargo.is_file() and os.access(cargo, os.X_OK), "cargo executable missing")
    env = os.environ.copy()
    for name in ("CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR"):
        env.pop(name, None)
    env["RUSTUP_TOOLCHAIN"] = channel
    env["SOURCE_DATE_EPOCH"] = epoch
    report["rust_channel"] = channel
    report["source_date_epoch"] = env["SOURCE_DATE_EPOCH"]
    report["cargo_version"] = run([str(cargo), "--version"], out / "cargo-version.log", env=env).strip()
    report["rustc_version"] = run([str(cargo.with_name("rustc")), "-Vv"], out / "rustc-version.log", env=env).strip()
    report["target_cc_version"] = run([str(toolchain / "bin/aarch64-openwrt-linux-musl-gcc"), "--version"], out / "target-cc-version.log").strip()
    build, output = out / "package-build", out / "sdk-output"
    make_vars = ["V=s", "-j1", f"V1_CARGO={cargo}",
                 f"V1_CARGO_HOME={safe_path(Path(env.get('CARGO_HOME', str(Path.home() / '.cargo'))).resolve())}",
                 f"V1_RUSTUP_HOME={safe_path(Path(env.get('RUSTUP_HOME', str(Path.home() / '.rustup'))).resolve())}",
                 f"OWRT_COMPONENTS_SOURCE={source / 'components'}",
                 f"OWRT_DNSMASQ_BUILD_DIR={build}", f"OWRT_DNSMASQ_OUTPUT_DIR={output}"]
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
    artifact = output / f"packages/{ARCH}/base/{PACKAGE}-{PACKAGE_VERSION}-r{PACKAGE_RELEASE}.apk"
    candidates = list(output.rglob(f"{PACKAGE}-*.apk"))
    require(candidates == [artifact], f"expected exactly the current package artifact; found {candidates}")
    shutil.copy2(artifact, out / artifact.name)
    artifact = out / artifact.name
    payload = out / "payload"
    payload.mkdir()
    run([str(apk), "extract", "--allow-untrusted", "--no-network", "--no-chown", "--destination", str(payload), str(artifact)], out / "extract.log")
    report["payload_files"] = audit_payload(payload)
    elf = payload / "usr/sbin/dnsmasq"
    elf_text = run([str(readelf), "-h", "-l", "-d", str(elf)], out / "elf-readelf.log")
    require("AArch64" in elf_text and "ELF64" in elf_text, "package ELF has the wrong target architecture")
    require("/lib/ld-musl-aarch64.so.1" in elf_text or "There is no dynamic section" in elf_text,
            "package ELF is neither target musl nor static")
    metadata = run([str(apk), "adbdump", str(artifact)], out / "apk-metadata.log")
    report["apk_metadata"] = audit_metadata(metadata)
    require(inputs(ROOT) == source_hashes, "source changed while building; artifact is not current")
    report["artifact"] = {"name": artifact.name, "sha256": sha(artifact), "size": artifact.stat().st_size}
    report["elf"] = {"sha256": sha(elf), "size": elf.stat().st_size, "install_path": "/usr/sbin/dnsmasq"}
    require(report["artifact"]["size"] <= report["budget"]["apk_max_bytes"],
            f"APK exceeds M4 budget: {report['artifact']['size']} > {report['budget']['apk_max_bytes']}")
    require(report["elf"]["size"] <= report["budget"]["elf_max_bytes"],
            f"ELF exceeds M4 budget: {report['elf']['size']} > {report['budget']['elf_max_bytes']}")
    report["budget_checks"] = {"apk": True, "elf": True}
    (out / "SHA256SUMS").write_text(f"{sha(artifact)}  {artifact.name}\n{sha(elf)}  payload/usr/sbin/dnsmasq\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdk", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--budget", type=Path, required=True,
                        help="frozen JSON with elf_max_bytes/apk_max_bytes")
    parser.add_argument("--source-commit", help="original commit of a copied source snapshot")
    parser.add_argument("--source-date-epoch", help="original commit timestamp for that snapshot")
    parser.add_argument("--expected-source-digest", help="freeze SHA256 over the sorted input hash map")
    args = parser.parse_args()
    out = safe_path(args.out.resolve())
    budget_path = safe_path(args.budget.resolve())
    require(out.is_relative_to(ROOT / "private") and out != ROOT / "private", "output must be a new task directory below private/")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.mkdir()  # Refuse reused outputs before touching SDK state.
    report = {"package": PACKAGE, "recipe": RECIPE, "target": TARGET, "activation": "candidate",
              "physical_router": False, "status": "building",
              "scope": "Replacement package candidate; no image assembly, deployment or production acceptance",
              "budget": read_budget(budget_path)}
    try:
        audit_build(args, out, report)
        report["status"] = "built-and-audited"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        report["warnings"] = [line for log in out.glob("*.log") for line in log.read_text(errors="replace").splitlines()
                              if "warning" in line.lower() or "ld.so" in line.lower()]
        (out / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "package", "activation")}))
    return int(report["status"] != "built-and-audited")


if __name__ == "__main__":
    raise SystemExit(main())
