#!/usr/bin/env python3
"""Audit an existing native C reference without starting a network service.

Run prepare_reference.py against the image inputs first; its identity SHA256 can
then be pinned here when checking a remote copy. The audit checks present source,
dependency and build identities. It does not claim reproducible-build proof or
target-router ABI/performance equivalence. JSON output belongs in private/.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shlex
import subprocess


ROOT = Path(__file__).resolve().parents[2]
COPTS = ["-DHAVE_UBUS", "-DHAVE_POLL_H", "-DNO_DHCP6", "-DNO_AUTH", "-DNO_IPSET", "-DNO_ID"]
FEATURES = (
    "IPv6 GNU-getopt no-DBus UBus no-i18n no-IDN DHCP no-DHCPv6 no-Lua TFTP "
    "no-conntrack no-ipset no-nftset no-auth no-DNSSEC no-ID loop-detect inotify dumpfile"
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def cmake_source(build):
    prefix = "CMAKE_HOME_DIRECTORY:INTERNAL="
    values = [line[len(prefix):] for line in (build / "CMakeCache.txt").read_text().splitlines()
              if line.startswith(prefix)]
    require(len(values) == 1, f"missing CMake source identity in {build}")
    return Path(values[0])


def verify(args):
    require(platform.system() == "Linux", "native Linux reference required")
    source = args.source.resolve()
    build = args.build.resolve()
    identity_path = source.parent / "identity.json"
    identity_hash = digest(identity_path)
    if args.identity_sha256:
        require(identity_hash == args.identity_sha256, "prepared identity SHA256 mismatch")
    identity = json.loads(identity_path.read_text())
    manifest = json.loads(args.manifest.read_text())
    recipe = manifest["recipes"]["feeds/base/network/services/dnsmasq"]
    require(identity["recipe_revision"] == recipe["repository_revision"], "recipe revision mismatch")
    require(identity["archive_sha256"] == recipe["source_assignments"]["PKG_HASH"][0]["value"],
            "source archive identity mismatch")
    require(identity["copts"] == COPTS, "prepared feature flags mismatch")
    for name, expected in identity["patched_files"].items():
        path = source / name
        require(path.resolve().is_relative_to(source), f"source escapes tree: {name}")
        require(digest(path) == expected, f"source drift: {name}")

    dependencies = {}
    for name, directory, key in (("libubox", "build-ubox", "feeds/base/libs/libubox"),
                                 ("ubus", "build-ubus", "feeds/base/system/ubus")):
        dep_source = cmake_source(build / directory)
        expected = manifest["recipes"][key]["source_assignments"]["PKG_SOURCE_VERSION"][0]["value"]
        actual = command("git", "-C", str(dep_source), "rev-parse", "HEAD")
        require(actual == expected, f"{name} revision mismatch")
        require(not command("git", "-C", str(dep_source), "status", "--porcelain", "--untracked-files=all"),
                f"{name} source is not clean")
        library = build / "deps/lib" / f"lib{name.removeprefix('lib')}.so"
        dependencies[name] = {"source": str(dep_source), "revision": actual,
                              "library_sha256": digest(library.resolve())}

    binary = build / "dnsmasq/dnsmasq"
    binary_hash = digest(binary)
    recorded_hash = (build / "binary.sha256").read_text().split()[0]
    require(binary_hash == recorded_hash, "C ELF differs from recorded build")
    require(binary.read_bytes()[:4] == b"\x7fELF", "C binary is not ELF")
    version = command(str(binary), "--version")
    require(version == (build / "version.txt").read_text().strip(), "C version output changed")
    require(version.splitlines()[0].startswith("Dnsmasq version 2.93 "), "C version mismatch")
    require(f"Compile time options: {FEATURES}" in version.splitlines(), "C feature set mismatch")
    linked = command("ldd", str(binary))
    for name in ("libubox.so", "libubus.so"):
        expected = str(build / "deps/lib" / name)
        require(f"{name} => {expected} " in linked, f"{name} resolves outside audited build")

    # Retain object identities for drivers linked to this build. Every object
    # must have a matching compile command with the expected feature gates.
    compile_rows = [shlex.split(line) for line in (build / "dnsmasq.log").read_text().splitlines()
                    if line.startswith("cc ") and " -c " in line]
    objects = {}
    for obj in sorted((build / "dnsmasq").glob("*.o")):
        filename = obj.with_suffix(".c").name
        rows = [row for row in compile_rows if row[-1] == filename]
        require(len(rows) == 1 and all(flag in rows[0] for flag in COPTS),
                f"missing or ambiguous feature-gated compile evidence for {obj.name}")
        require(digest(build / "dnsmasq" / filename) == identity["patched_files"][f"src/{filename}"],
                f"object source differs: {filename}")
        objects[obj.name] = digest(obj)
    require(len(objects) == len(compile_rows) and len(objects) > 0, "object/compile count mismatch")
    return {
        "status": "verified", "identity_sha256": identity_hash,
        "source_files": len(identity["patched_files"]), "source": str(source),
        "manifest_sha256": digest(args.manifest), "build": str(build),
        "binary_sha256": binary_hash, "version": version, "dependencies": dependencies,
        "objects": objects, "ldd": linked, "host": platform.platform(),
        "compiler_at_build": (build / "compiler.txt").read_text(),
        "scope": "Existing native C reference identity audit; no network service or target-router claim.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--manifest", type=Path,
                        default=ROOT / "manifests/ax3000t-stock-openwrt-25.12.5/sources.json")
    parser.add_argument("--identity-sha256", help="SHA256 of the locally reconstructed identity.json")
    args = parser.parse_args()
    try:
        report = verify(args)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"reference verification failed: {error}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
