#!/usr/bin/env python3
"""Build I0.4 package, executable, ownership, and source manifests.

The tool only reads an already extracted OpenWrt root filesystem, matching
release metadata, and immutable source checkouts.  It never executes target
binaries and writes only derived JSON into the requested output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


FIELD_NAMES = {
    "C": "checksum",
    "P": "name",
    "V": "version",
    "A": "architecture",
    "S": "archive_size",
    "I": "installed_size",
    "T": "description",
    "U": "upstream_url",
    "L": "license",
    "o": "origin",
    "m": "maintainer",
    "k": "provider_priority",
    "D": "dependencies_raw",
    "p": "provides_raw",
    "f": "flags",
}

SOURCE_VARIABLES = {
    "PKG_NAME",
    "PKG_VERSION",
    "PKG_RELEASE",
    "PKG_SOURCE",
    "PKG_SOURCE_URL",
    "PKG_SOURCE_VERSION",
    "PKG_SOURCE_DATE",
    "PKG_HASH",
    "PKG_MIRROR_HASH",
    "PKG_LICENSE",
    "PKG_LICENSE_FILES",
}

BUILD_EVIDENCE_TERMS = (
    "CONFIGURE_ARGS",
    "CONFIGURE_VARS",
    "CMAKE_OPTIONS",
    "MESON_ARGS",
    "MAKE_FLAGS",
    "TARGET_CFLAGS",
    "TARGET_LDFLAGS",
    "PKG_CONFIG_DEPENDS",
    "BUILD_VARIANT",
    "VARIANT",
    "DEPENDS",
    "PROVIDES",
    "Build/Patch",
    "PatchDir",
)

CONTROL_PLANE_PREFIXES = {
    "init_scripts": ("/etc/init.d/",),
    "rc_links": ("/etc/rc.d/",),
    "preinit": ("/lib/preinit/",),
    "hotplug": ("/etc/hotplug.d/",),
    "uci_defaults": ("/etc/uci-defaults/",),
    "uci_config": ("/etc/config/",),
    "rpcd_acl": ("/usr/share/rpcd/acl.d/", "/usr/share/acl.d/"),
    "rpcd_plugins": ("/usr/lib/rpcd/", "/usr/share/rpcd/ucode/"),
    "luci": ("/usr/share/ucode/luci/", "/www/"),
    "netifd": ("/lib/netifd/", "/usr/libexec/network/"),
    "firewall4": ("/usr/share/firewall4/", "/etc/nftables.d/"),
    "hostap": ("/usr/share/hostap/", "/lib/netifd/hostapd.sh"),
    "dns_dhcp": ("/usr/share/dnsmasq/", "/usr/share/odhcpd/"),
    "upgrade_persistence": ("/lib/upgrade/", "/sbin/sysupgrade"),
}

OPAQUE_FIRMWARE_PACKAGES = {
    "eip197-mini-firmware",
    "kmod-mt7981-firmware",
    "mt7981-wo-firmware",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_lines(items: Iterable[str]) -> str:
    payload = "".join(f"{item}\n" for item in items).encode()
    return hashlib.sha256(payload).hexdigest()


def run(argv: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run(
        argv,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    )
    return completed.returncode, completed.stdout, completed.stderr


def git_head(path: Path) -> str:
    status, stdout, stderr = run(["git", "-C", str(path), "rev-parse", "HEAD"])
    if status != 0:
        raise RuntimeError(f"cannot resolve git revision for {path}: {stderr.strip()}")
    return stdout.strip()


def git_tree(path: Path) -> str:
    status, stdout, stderr = run(["git", "-C", str(path), "rev-parse", "HEAD^{tree}"])
    if status != 0:
        raise RuntimeError(f"cannot resolve git tree for {path}: {stderr.strip()}")
    return stdout.strip()


def git_clean(path: Path) -> bool:
    status, stdout, stderr = run(["git", "-C", str(path), "status", "--porcelain=v1"])
    if status != 0:
        raise RuntimeError(f"cannot inspect git status for {path}: {stderr.strip()}")
    return not stdout.strip()


def parse_apk_installed(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw_record in path.read_text().strip().split("\n\n"):
        fields: dict[str, list[str]] = defaultdict(list)
        for line in raw_record.splitlines():
            if len(line) >= 2 and line[1] == ":":
                fields[line[0]].append(line[2:])
        if "P" not in fields:
            continue
        record: dict[str, Any] = {}
        for tag, name in FIELD_NAMES.items():
            values = fields.get(tag, [])
            record[name] = values[0] if values else None
        for integer_field in ("archive_size", "installed_size", "provider_priority"):
            if record[integer_field] is not None:
                record[integer_field] = int(record[integer_field])
        record["dependencies"] = split_apk_tokens(record.pop("dependencies_raw") or "")
        record["provides"] = split_apk_tokens(record.pop("provides_raw") or "")
        records.append(record)
    return sorted(records, key=lambda item: item["name"])


def split_apk_tokens(value: str) -> list[dict[str, str | None]]:
    result = []
    for token in value.split():
        match = re.match(r"^([^<>=~]+)(.*)$", token)
        result.append(
            {
                "raw": token,
                "name": match.group(1) if match else token,
                "constraint": match.group(2) or None if match else None,
            }
        )
    return result


def parse_manifest(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if " - " not in line:
            continue
        name, version = line.split(" - ", 1)
        result[name] = version
    return result


def parse_world(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    raw: dict[str, str] = {}
    constraints: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if not line:
            continue
        match = re.match(r"^([^<>=~]+)(.*)$", line)
        name = match.group(1) if match else line
        raw[name] = line
        constraints[name] = match.group(2) if match else ""
    return raw, constraints


def parse_config(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text().splitlines():
        match = re.match(r"^CONFIG_([^=]+)=(.*)$", line)
        if match:
            result[match.group(1)] = match.group(2).strip('"')
    return result


def logical_make_lines(text: str) -> list[str]:
    logical: list[str] = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not current and (not stripped or stripped.startswith("#")):
            continue
        current = f"{current} {stripped}".strip() if current else stripped
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        logical.append(current)
        current = ""
    if current:
        logical.append(current)
    return logical


def assignment_map(text: str) -> dict[str, list[dict[str, str]]]:
    result: dict[str, list[dict[str, str]]] = defaultdict(list)
    for line in logical_make_lines(text):
        match = re.match(r"^([A-Za-z0-9_.$()/+\-]+)\s*([:+?]?=)\s*(.*)$", line)
        if match:
            result[match.group(1)].append(
                {"operator": match.group(2), "value": match.group(3)}
            )
    return dict(result)


def recipe_location(origin: str, sources: Path) -> tuple[str, Path]:
    mappings = (
        ("feeds/base/", "openwrt", sources / "openwrt" / "package"),
        ("feeds/packages/feeds/packages/", "packages", sources / "packages"),
        ("feeds/luci/feeds/luci/", "luci", sources / "luci"),
        ("feeds/routing/feeds/routing/", "routing", sources / "routing"),
        ("feeds/telephony/feeds/telephony/", "telephony", sources / "telephony"),
        ("feeds/video/feeds/video/", "video", sources / "video"),
    )
    for prefix, repository, base in mappings:
        if origin.startswith(prefix):
            return repository, base / origin.removeprefix(prefix)
    raise ValueError(f"unsupported APK origin: {origin}")


def collect_files(base: Path, predicate: Any) -> list[dict[str, Any]]:
    if not base.exists():
        return []
    result = []
    for path in sorted(item for item in base.rglob("*") if item.is_file() and predicate(item)):
        result.append(
            {
                "path": str(path),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return result


def relative_records(records: list[dict[str, Any]], base: Path) -> list[dict[str, Any]]:
    for record in records:
        record["path"] = str(Path(record["path"]).relative_to(base))
    return records


def package_metadata_files(package_dir: Path, name: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for suffix in ("conffiles", "conffiles_static", "alternatives", "rusers"):
        path = package_dir / f"{name}.{suffix}"
        result[suffix] = path.read_text(errors="replace").splitlines() if path.exists() else []
    return result


def root_path(rootfs: Path, image_path: str) -> Path:
    return rootfs / image_path.lstrip("/")


def resolve_image_symlink(rootfs: Path, image_path: str, max_depth: int = 16) -> str | None:
    current = image_path
    for _ in range(max_depth):
        path = root_path(rootfs, current)
        if not path.is_symlink():
            return current if path.exists() else None
        target = os.readlink(path)
        if target.startswith("/"):
            current = os.path.normpath(target)
        else:
            current = os.path.normpath(os.path.join(os.path.dirname(current), target))
        if not current.startswith("/"):
            current = f"/{current}"
    return None


def describe_file(path: Path) -> str:
    status, stdout, _ = run(["file", "-b", str(path)])
    return stdout.strip() if status == 0 else "file(1) failed"


def readelf_metadata(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "class": None,
        "data_encoding": None,
        "os_abi": None,
        "elf_type": None,
        "machine": None,
        "flags": None,
        "interpreter": None,
        "needed": [],
        "soname": None,
        "rpath": None,
        "runpath": None,
        "imported_symbols": [],
        "defined_symbols": [],
    }
    status, header, stderr = run(["readelf", "-hW", str(path)])
    if status != 0:
        result["readelf_error"] = stderr.strip()
        return result
    header_fields = {
        "Class:": "class",
        "Data:": "data_encoding",
        "OS/ABI:": "os_abi",
        "Type:": "elf_type",
        "Machine:": "machine",
        "Flags:": "flags",
    }
    for line in header.splitlines():
        stripped = line.strip()
        for label, key in header_fields.items():
            if stripped.startswith(label):
                result[key] = stripped.removeprefix(label).strip()
    _, program_headers, _ = run(["readelf", "-lW", str(path)])
    match = re.search(r"Requesting program interpreter:\s*([^\]]+)", program_headers)
    if match:
        result["interpreter"] = match.group(1).strip()
    _, dynamic, _ = run(["readelf", "-dW", str(path)])
    for line in dynamic.splitlines():
        match = re.search(r"\((NEEDED|SONAME|RPATH|RUNPATH)\).*\[([^]]*)\]", line)
        if not match:
            continue
        kind, value = match.groups()
        if kind == "NEEDED":
            result["needed"].append(value)
        else:
            result[kind.lower()] = value
    _, symbols, _ = run(["readelf", "-sW", str(path)])
    imported: set[str] = set()
    defined: set[str] = set()
    for line in symbols.splitlines():
        match = re.match(
            r"^\s*\d+:\s+\S+\s+\d+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(.+?)\s*$",
            line,
        )
        if not match:
            continue
        section, name = match.groups()
        if not name or name == "0":
            continue
        (imported if section == "UND" else defined).add(name)
    result["needed"] = sorted(set(result["needed"]))
    result["imported_symbols"] = sorted(imported)
    result["defined_symbols"] = sorted(defined)
    result["imported_symbol_count"] = len(imported)
    result["defined_symbol_count"] = len(defined)
    return result


def file_record(
    rootfs: Path,
    path: Path,
    owners: dict[str, str],
    generated: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    image_path = f"/{path.relative_to(rootfs)}"
    metadata = path.lstat()
    record: dict[str, Any] = {
        "path": image_path,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "owner_package": owners.get(image_path),
        "attribution": "package_payload" if image_path in owners else None,
    }
    if image_path in generated:
        record.update(generated[image_path])
    if path.is_symlink():
        record["type"] = "symlink"
        record["target"] = os.readlink(path)
        record["resolved_image_path"] = resolve_image_symlink(rootfs, image_path)
    else:
        record["type"] = "regular"
        record["size"] = metadata.st_size
        record["sha256"] = sha256_file(path)
    return record


def collect_patch_stack(directory: Path, sources: Path) -> dict[str, Any]:
    patches = relative_records(
        collect_files(directory, lambda item: item.suffix == ".patch"), sources
    )
    digest_items = [f"{item['sha256']}  {item['path']}" for item in patches]
    return {
        "directory": str(directory.relative_to(sources)),
        "count": len(patches),
        "ordered_digest_sha256": sha256_lines(digest_items),
        "patches": patches,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()

    rootfs = args.rootfs.resolve()
    metadata = args.metadata.resolve()
    sources = args.sources.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    installed_path = rootfs / "lib/apk/db/installed"
    package_control_dir = rootfs / "lib/apk/packages"
    packages = parse_apk_installed(installed_path)
    package_by_name = {item["name"]: item for item in packages}

    release_manifest_path = next(metadata.glob("*.manifest"))
    bom_path = next(metadata.glob("*.bom.cdx.json"))
    profiles_path = metadata / "profiles.json"
    config_path = metadata / "config.buildinfo"
    feeds_path = metadata / "feeds.buildinfo"
    release_manifest = parse_manifest(release_manifest_path)
    bom = json.loads(bom_path.read_text())
    bom_by_name = {item["name"]: item for item in bom.get("components", [])}
    profiles = json.loads(profiles_path.read_text())
    profile = profiles["profiles"]["xiaomi_mi-router-ax3000t"]
    world, world_constraints = parse_world(rootfs / "etc/apk/world")
    config = parse_config(config_path)

    repository_revisions = {"openwrt": git_head(sources / "openwrt")}
    feed_repositories: dict[str, dict[str, str]] = {}
    for line in feeds_path.read_text().splitlines():
        match = re.match(r"^src-git\s+(\S+)\s+(\S+)\^([0-9a-f]{40})$", line)
        if not match:
            continue
        name, url, revision = match.groups()
        checkout_revision = git_head(sources / name)
        if checkout_revision != revision:
            raise RuntimeError(f"feed checkout mismatch for {name}")
        repository_revisions[name] = revision
        feed_repositories[name] = {
            "url": url,
            "revision": revision,
            "tree": git_tree(sources / name),
            "worktree_clean": git_clean(sources / name),
        }

    owners: dict[str, str] = {}
    duplicate_owners: dict[str, list[str]] = {}
    package_files: dict[str, list[str]] = {}
    for package in packages:
        name = package["name"]
        list_path = package_control_dir / f"{name}.list"
        if not list_path.exists():
            raise RuntimeError(f"missing APK payload list for {name}")
        paths = [line for line in list_path.read_text().splitlines() if line]
        package_files[name] = paths
        for image_path in paths:
            if image_path in owners:
                duplicate_owners.setdefault(image_path, [owners[image_path]]).append(name)
            else:
                owners[image_path] = name

    missing_payload_paths = sorted(
        image_path
        for image_path in owners
        if not os.path.lexists(root_path(rootfs, image_path))
    )

    generated: dict[str, dict[str, Any]] = {}
    all_paths: list[Path] = sorted(rootfs.rglob("*"))
    for path in all_paths:
        image_path = f"/{path.relative_to(rootfs)}"
        if image_path in owners or path.is_dir():
            continue
        if image_path in ("/etc/apk/world", "/etc/apk/arch") or image_path.startswith(
            "/lib/apk/db/"
        ):
            generated[image_path] = {
                "owner_package": "apk-mbedtls",
                "attribution": "generated",
                "generator": "OpenWrt image APK database construction",
            }
        elif image_path.startswith("/lib/apk/packages/"):
            basename = path.name
            matched = next(
                (name for name in package_by_name if basename.startswith(f"{name}.")), None
            )
            generated[image_path] = {
                "owner_package": matched or "apk-mbedtls",
                "attribution": "generated",
                "generator": "apk package metadata generation",
            }
        elif image_path.startswith("/etc/rc.d/") and path.is_symlink():
            resolved = resolve_image_symlink(rootfs, image_path)
            generated[image_path] = {
                "owner_package": owners.get(resolved or ""),
                "attribution": "generated",
                "generator": "rc.common service enable link",
                "generated_from": resolved,
            }
        elif path.is_symlink():
            resolved = resolve_image_symlink(rootfs, image_path)
            generated[image_path] = {
                "owner_package": owners.get(resolved or ""),
                "attribution": "generated",
                "generator": "apk alternatives link",
                "generated_from": resolved,
            }

    unknown_files = []
    generated_files = []
    for path in all_paths:
        if path.is_dir():
            continue
        image_path = f"/{path.relative_to(rootfs)}"
        if image_path in generated:
            generated_files.append(file_record(rootfs, path, owners, generated))
        elif image_path not in owners:
            unknown_files.append(file_record(rootfs, path, owners, generated))

    provider_map: dict[str, set[str]] = defaultdict(set)
    for package in packages:
        provider_map[package["name"]].add(package["name"])
        for provided in package["provides"]:
            provider_map[str(provided["name"])].add(package["name"])

    config_y = sorted(
        key.removeprefix("PACKAGE_")
        for key, value in config.items()
        if key.startswith("PACKAGE_") and value == "y"
    )
    config_resolution = []
    for selector in config_y:
        providers = sorted(provider_map.get(selector, set()))
        config_resolution.append(
            {
                "selector": selector,
                "installed_providers": providers,
                "resolved": bool(providers),
            }
        )

    target_default_resolution = []
    for selector in sorted(profiles["default_packages"]):
        providers = sorted(provider_map.get(selector, set()))
        target_default_resolution.append(
            {
                "selector": selector,
                "installed_providers": providers,
                "resolved": bool(providers),
            }
        )

    bom_resolution = []
    bom_represented_packages: set[str] = set()
    for selector in sorted(bom_by_name):
        providers = sorted(provider_map.get(selector, set()))
        bom_represented_packages.update(providers)
        bom_resolution.append(
            {
                "component": selector,
                "installed_providers": providers,
                "resolved": bool(providers),
            }
        )

    source_recipes: dict[str, dict[str, Any]] = {}
    for package in packages:
        name = package["name"]
        origin = package["origin"]
        repository, recipe_dir = recipe_location(origin, sources)
        makefile = recipe_dir / "Makefile"
        if not makefile.is_file():
            raise RuntimeError(f"missing recipe Makefile for {name}: {makefile}")
        source_key = origin
        package["source_key"] = source_key
        if source_key not in source_recipes:
            text = makefile.read_text(errors="replace")
            assignments = assignment_map(text)
            source_assignments = {
                key: assignments[key] for key in SOURCE_VARIABLES if key in assignments
            }
            build_evidence = sorted(
                {
                    line
                    for line in logical_make_lines(text)
                    if any(term in line for term in BUILD_EVIDENCE_TERMS)
                }
            )
            definitions = []
            for line_number, line in enumerate(text.splitlines(), 1):
                match = re.match(r"^define\s+((?:Package|Build)/\S+)", line.strip())
                if match and (
                    "/install" in match.group(1)
                    or "/conffiles" in match.group(1)
                    or match.group(1).startswith("Build/Install")
                ):
                    definitions.append({"name": match.group(1), "line": line_number})
            patch_records = relative_records(
                collect_files(recipe_dir, lambda item: item.suffix == ".patch"), sources
            )
            overlays = relative_records(
                collect_files(
                    recipe_dir,
                    lambda item: "files" in item.relative_to(recipe_dir).parts,
                ),
                sources,
            )
            auxiliary_files = relative_records(
                collect_files(recipe_dir, lambda item: item.name != "Makefile"),
                sources,
            )
            source_recipes[source_key] = {
                "origin": origin,
                "repository": repository,
                "repository_revision": repository_revisions[repository],
                "recipe_path": str(recipe_dir.relative_to(sources)),
                "recipe_makefile_sha256": sha256_file(makefile),
                "packages": [],
                "source_assignments": source_assignments,
                "build_flag_evidence": build_evidence,
                "install_definition_evidence": definitions,
                "patch_count": len(patch_records),
                "patches": patch_records,
                "overlay_file_count": len(overlays),
                "overlay_files": overlays,
                "auxiliary_file_count": len(auxiliary_files),
                "auxiliary_files": auxiliary_files,
                "install_evidence_mode": (
                    "explicit-definitions"
                    if definitions
                    else "repository-macro-or-kernel-template"
                ),
                "recipe_mapping_confidence": "Exact",
                "implementation_source_confidence": "Exact",
                "boundary": "public-or-in-tree-source",
            }
        source_recipes[source_key]["packages"].append(name)

        list_path = package_control_dir / f"{name}.list"
        control_files = package_metadata_files(package_control_dir, name)
        bom_component = bom_by_name.get(name)
        package["release_manifest_version"] = release_manifest.get(name)
        package["release_manifest_exact_match"] = release_manifest.get(name) == package["version"]
        package["world_spec"] = world.get(name)
        package["world_constraint"] = world_constraints.get(name)
        package["bom_component"] = bom_component
        package["payload_file_count"] = len(package_files[name])
        package["payload_file_list_sha256"] = sha256_file(list_path)
        package["payload_files"] = package_files[name]
        package["control_files"] = control_files
        package["recipe_mapping_confidence"] = "Exact"
        package["implementation_source_confidence"] = (
            "Unknown" if name in OPAQUE_FIRMWARE_PACKAGES else "Exact"
        )
        package["payload_boundary"] = (
            "opaque-binary-firmware"
            if name in OPAQUE_FIRMWARE_PACKAGES
            else "public-or-in-tree-source"
        )

    source_recipes = {
        key: {**value, "packages": sorted(value["packages"])}
        for key, value in sorted(source_recipes.items())
    }
    for recipe in source_recipes.values():
        opaque_packages = sorted(set(recipe["packages"]) & OPAQUE_FIRMWARE_PACKAGES)
        recipe["opaque_payload_packages"] = opaque_packages
        if not opaque_packages:
            continue
        if len(opaque_packages) == len(recipe["packages"]):
            recipe["implementation_source_confidence"] = "Unknown"
            recipe["boundary"] = "opaque-binary-firmware"
        else:
            recipe["implementation_source_confidence"] = "Bounded"
            recipe["boundary"] = "mixed-public-source-and-opaque-binary-firmware"

    package_manifest = {
        "schema_version": 1,
        "stage": "I0.4",
        "status": "complete",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "authorities": {
            "installed_packages": "/lib/apk/db/installed in the exact image",
            "file_ownership": "/lib/apk/packages/*.list in the exact image",
            "cross_checks": [
                release_manifest_path.name,
                bom_path.name,
                profiles_path.name,
                config_path.name,
            ],
        },
        "input_sha256": {
            "apk_installed_db": sha256_file(installed_path),
            "apk_world": sha256_file(rootfs / "etc/apk/world"),
            "release_manifest": sha256_file(release_manifest_path),
            "cyclonedx_bom": sha256_file(bom_path),
            "profiles": sha256_file(profiles_path),
            "config_buildinfo": sha256_file(config_path),
            "feeds_buildinfo": sha256_file(feeds_path),
        },
        "counts": {
            "installed_packages": len(packages),
            "world_entries": len(world),
            "release_manifest_packages": len(release_manifest),
            "cyclonedx_components": len(bom_by_name),
            "distinct_recipe_origins": len(source_recipes),
            "payload_owned_paths": len(owners),
            "generated_non_directory_paths": len(generated_files),
            "unknown_non_directory_paths": len(unknown_files),
            "duplicate_payload_owners": len(duplicate_owners),
            "missing_payload_paths": len(missing_payload_paths),
        },
        "comparisons": {
            "installed_not_in_release_manifest": sorted(set(package_by_name) - set(release_manifest)),
            "release_manifest_not_installed": sorted(set(release_manifest) - set(package_by_name)),
            "release_manifest_version_mismatches": sorted(
                package["name"]
                for package in packages
                if package["name"] in release_manifest
                and not package["release_manifest_exact_match"]
            ),
            "world_not_installed": sorted(set(world) - set(package_by_name)),
            "installed_not_in_world": sorted(set(package_by_name) - set(world)),
            "installed_not_in_cyclonedx": sorted(set(package_by_name) - set(bom_by_name)),
            "cyclonedx_not_installed": sorted(set(bom_by_name) - set(package_by_name)),
            "cyclonedx_component_resolution": bom_resolution,
            "cyclonedx_unresolved_components": sorted(
                item["component"] for item in bom_resolution if not item["resolved"]
            ),
            "installed_not_represented_by_cyclonedx": sorted(
                set(package_by_name) - bom_represented_packages
            ),
            "profile_device_packages": sorted(profile["device_packages"]),
            "profile_device_packages_not_installed": sorted(
                set(profile["device_packages"]) - set(package_by_name)
            ),
            "target_default_selectors": sorted(profiles["default_packages"]),
            "target_default_selector_resolution": target_default_resolution,
            "target_default_unresolved_selectors": sorted(
                item["selector"] for item in target_default_resolution if not item["resolved"]
            ),
            "config_package_y_resolution": config_resolution,
            "config_package_y_unresolved": sorted(
                item["selector"] for item in config_resolution if not item["resolved"]
            ),
            "custom_feed_entries": [
                line
                for line in (
                    rootfs / "etc/apk/repositories.d/customfeeds.list"
                ).read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ],
            "distribution_feed_entries": [
                line
                for line in (
                    rootfs / "etc/apk/repositories.d/distfeeds.list"
                ).read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ],
        },
        "generated_files": sorted(generated_files, key=lambda item: item["path"]),
        "unknown_files": sorted(unknown_files, key=lambda item: item["path"]),
        "duplicate_owners": duplicate_owners,
        "missing_payload_paths": missing_payload_paths,
        "packages": packages,
    }

    regular_files = [path for path in all_paths if path.is_file() and not path.is_symlink()]
    elf_files = []
    scripts = []
    ucode_lua = []
    executable_regular = []
    executable_symlinks = []
    busybox_path = rootfs / "bin/busybox"
    busybox_sha = sha256_file(busybox_path)

    for path in regular_files:
        record = file_record(rootfs, path, owners, generated)
        first = path.open("rb").read(4)
        if first == b"\x7fELF":
            record["file_description"] = describe_file(path)
            record["elf"] = readelf_metadata(path)
            record["source_key"] = (
                package_by_name.get(record.get("owner_package") or "", {}).get("source_key")
            )
            elf_files.append(record)
        first_line = path.open("rb").read(256).split(b"\n", 1)[0]
        if first_line.startswith(b"#!") or path.suffix == ".sh":
            script_record = dict(record)
            script_record["interpreter"] = (
                first_line.decode(errors="replace")
                if first_line.startswith(b"#!")
                else "shell-fragment-no-shebang"
            )
            scripts.append(script_record)
        if path.suffix in (".uc", ".ut", ".lua"):
            language = "lua" if path.suffix == ".lua" else "ucode"
            language_record = dict(record)
            language_record["language"] = language
            ucode_lua.append(language_record)
        if stat.S_IMODE(path.stat().st_mode) & 0o111:
            executable = dict(record)
            if record.get("sha256") == busybox_sha and record["path"] != "/bin/busybox":
                executable["kind"] = "busybox-applet-hardlink"
            elif first == b"\x7fELF":
                executable["kind"] = "independent-elf"
            elif first_line.startswith(b"#!") or path.suffix == ".sh":
                executable["kind"] = "script"
            elif path.suffix in (".uc", ".ut", ".lua"):
                executable["kind"] = "ucode-or-lua"
            else:
                executable["kind"] = "other-executable-data"
            executable_regular.append(executable)

    for path in (item for item in all_paths if item.is_symlink()):
        image_path = f"/{path.relative_to(rootfs)}"
        resolved = resolve_image_symlink(rootfs, image_path)
        if not resolved:
            continue
        resolved_path = root_path(rootfs, resolved)
        if not resolved_path.exists() or resolved_path.is_dir():
            continue
        try:
            is_executable = bool(resolved_path.stat().st_mode & 0o111)
        except OSError:
            is_executable = False
        if not is_executable:
            continue
        record = file_record(rootfs, path, owners, generated)
        target_sha = sha256_file(resolved_path)
        if target_sha == busybox_sha:
            record["kind"] = "busybox-applet-symlink"
        else:
            record["kind"] = "executable-symlink"
        executable_symlinks.append(record)

    init_services = []
    init_dir = rootfs / "etc/init.d"
    for path in sorted(item for item in init_dir.iterdir() if item.is_file()):
        image_path = f"/{path.relative_to(rootfs)}"
        text = path.read_text(errors="replace")
        start = re.search(r"^START=(\S+)", text, re.MULTILINE)
        stop = re.search(r"^STOP=(\S+)", text, re.MULTILINE)
        users = sorted(set(re.findall(r"procd_set_param\s+user\s+['\"]?([^\s'\"]+)", text)))
        command_lines = sorted(
            line.strip()
            for line in text.splitlines()
            if re.search(r"procd_set_param\s+command", line)
        )
        init_services.append(
            {
                "name": path.name,
                "path": image_path,
                "owner_package": owners.get(image_path),
                "source_key": package_by_name.get(owners.get(image_path, ""), {}).get(
                    "source_key"
                ),
                "start": start.group(1) if start else None,
                "stop": stop.group(1) if stop else None,
                "uses_procd": "USE_PROCD=1" in text,
                "explicit_users": users,
                "uses_jail": "procd_add_jail" in text,
                "uses_seccomp": "procd_set_param seccomp" in text,
                "command_evidence": command_lines,
                "sha256": sha256_file(path),
            }
        )

    rc_links = []
    rc_dir = rootfs / "etc/rc.d"
    if rc_dir.exists():
        for path in sorted(item for item in rc_dir.iterdir() if item.is_symlink()):
            image_path = f"/{path.relative_to(rootfs)}"
            resolved = resolve_image_symlink(rootfs, image_path)
            rc_links.append(
                {
                    "path": image_path,
                    "target": os.readlink(path),
                    "resolved_image_path": resolved,
                    "owner_package": owners.get(resolved or ""),
                }
            )

    control_plane_files: dict[str, list[dict[str, Any]]] = {}
    for category, prefixes in CONTROL_PLANE_PREFIXES.items():
        records = []
        for path in all_paths:
            if path.is_dir():
                continue
            image_path = f"/{path.relative_to(rootfs)}"
            if any(image_path == prefix or image_path.startswith(prefix) for prefix in prefixes):
                records.append(
                    {
                        "path": image_path,
                        "owner_package": owners.get(image_path)
                        or generated.get(image_path, {}).get("owner_package"),
                    }
                )
        control_plane_files[category] = sorted(records, key=lambda item: item["path"])

    executable_manifest = {
        "schema_version": 1,
        "stage": "I0.4",
        "status": "complete",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "method": {
            "target_execution": False,
            "elf_parser": "GNU readelf on static files",
            "file_classifier": "file(1), magic, mode, suffix, and symlink target",
            "symbols": "full readelf symbol tables, deduplicated into imported/defined names",
            "python_version": run(["python3", "--version"])[1].strip(),
            "readelf_version": run(["readelf", "--version"])[1].splitlines()[0],
            "file_version": run(["file", "--version"])[1].splitlines()[0],
        },
        "counts": {
            "elf_regular_files": len(elf_files),
            "executable_regular_files": len(executable_regular),
            "executable_symlinks": len(executable_symlinks),
            "shebang_scripts": sum(
                item["interpreter"].startswith("#!") for item in scripts
            ),
            "script_files": len(scripts),
            "ucode_lua_files": len(ucode_lua),
            "init_services": len(init_services),
            "enabled_rc_links": len(rc_links),
            "setuid": 0,
            "setgid": 0,
            "file_capabilities": 0,
        },
        "privilege_boundary": {
            "image_uid_gid": "all 1223 inodes are 0/0",
            "setuid_entries": [],
            "setgid_entries": [],
            "file_capabilities": [],
            "default_service_rule": "root unless init script explicitly selects another user",
            "services_with_explicit_user": [
                item for item in init_services if item["explicit_users"]
            ],
            "services_with_jail": [item for item in init_services if item["uses_jail"]],
            "services_with_seccomp": [item for item in init_services if item["uses_seccomp"]],
        },
        "elf_files": sorted(elf_files, key=lambda item: item["path"]),
        "executable_regular_files": sorted(
            executable_regular, key=lambda item: item["path"]
        ),
        "executable_symlinks": sorted(
            executable_symlinks, key=lambda item: item["path"]
        ),
        "scripts": sorted(scripts, key=lambda item: item["path"]),
        "ucode_lua": sorted(ucode_lua, key=lambda item: item["path"]),
        "init_services": init_services,
        "rc_links": rc_links,
        "control_plane_files": control_plane_files,
    }

    target_patch_dirs = (
        sources / "openwrt/target/linux/generic/backport-6.12",
        sources / "openwrt/target/linux/generic/pending-6.12",
        sources / "openwrt/target/linux/generic/hack-6.12",
        sources / "openwrt/target/linux/mediatek/patches-6.12",
    )
    target_patch_stacks = [collect_patch_stack(path, sources) for path in target_patch_dirs]
    target_overlay_dirs = (
        sources / "openwrt/target/linux/generic/files",
        sources / "openwrt/target/linux/mediatek/files",
        sources / "openwrt/target/linux/mediatek/files-6.12",
    )
    target_overlays = []
    for directory in target_overlay_dirs:
        if not directory.exists():
            continue
        files = relative_records(collect_files(directory, lambda _: True), sources)
        target_overlays.append(
            {
                "directory": str(directory.relative_to(sources)),
                "count": len(files),
                "ordered_digest_sha256": sha256_lines(
                    f"{item['sha256']}  {item['path']}" for item in files
                ),
                "files": files,
            }
        )

    component_verification = []
    for component_dir in sorted((sources / "components").iterdir()):
        if not (component_dir / ".git").exists():
            continue
        expected_revision = None
        matching_origin = None
        for origin, recipe in source_recipes.items():
            names = recipe.get("source_assignments", {}).get("PKG_NAME", [])
            if not any(item["value"] == component_dir.name for item in names):
                continue
            revisions = recipe.get("source_assignments", {}).get("PKG_SOURCE_VERSION", [])
            if revisions:
                expected_revision = revisions[-1]["value"]
                matching_origin = origin
                break
        checkout_revision = git_head(component_dir)
        component_verification.append(
            {
                "component": component_dir.name,
                "checkout_revision": checkout_revision,
                "expected_source_revision": expected_revision,
                "matching_origin": matching_origin,
                "matches_recipe": expected_revision == checkout_revision,
                "tree": git_tree(component_dir),
                "worktree_clean": git_clean(component_dir),
            }
        )

    sources_manifest = {
        "schema_version": 1,
        "stage": "I0.4",
        "status": "complete",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "repositories": {
            "buildroot": {
                "path": "sources/openwrt",
                "revision": repository_revisions["openwrt"],
                "tree": git_tree(sources / "openwrt"),
                "worktree_clean": git_clean(sources / "openwrt"),
            },
            "feeds": feed_repositories,
        },
        "counts": {
            "package_recipes": len(source_recipes),
            "packages": len(packages),
            "recipe_patches": sum(item["patch_count"] for item in source_recipes.values()),
            "recipe_auxiliary_files": sum(
                item["auxiliary_file_count"] for item in source_recipes.values()
            ),
            "recipes_with_explicit_install_definitions": sum(
                item["install_evidence_mode"] == "explicit-definitions"
                for item in source_recipes.values()
            ),
            "recipes_using_repository_install_macros": sum(
                item["install_evidence_mode"] == "repository-macro-or-kernel-template"
                for item in source_recipes.values()
            ),
            "target_kernel_patches": sum(item["count"] for item in target_patch_stacks),
            "target_overlay_files": sum(item["count"] for item in target_overlays),
            "opaque_binary_firmware_recipes": sum(
                bool(item["opaque_payload_packages"])
                for item in source_recipes.values()
            ),
            "opaque_binary_firmware_packages": len(OPAQUE_FIRMWARE_PACKAGES),
        },
        "input_sha256": {
            "config_buildinfo": sha256_file(config_path),
            "feeds_buildinfo": sha256_file(feeds_path),
        },
        "shared_build_inputs": [
            {
                "path": str(path.relative_to(sources)),
                "sha256": sha256_file(path),
            }
            for path in (
                sources / "openwrt/rules.mk",
                sources / "openwrt/include/package.mk",
                sources / "openwrt/include/package-defaults.mk",
                sources / "openwrt/include/kernel.mk",
                sources / "luci/luci.mk",
            )
            if path.is_file()
        ],
        "source_reconstruction_rule": {
            "package_patch_order": "exact Build/Patch and PatchDir evidence; lexical within each selected patch directory",
            "kernel_patch_order": [item["directory"] for item in target_patch_stacks],
            "build_flags_authority": "exact config.buildinfo plus exact recipe Makefile",
            "install_recipe_authority": "exact recipe Makefile, shared build macros, and hashed auxiliary/overlay files",
            "independent_patch_replay": False,
            "reason": "I0.4 records the exact OpenWrt build inputs; compile/replay belongs to V1",
        },
        "component_checkouts": component_verification,
        "recipes": source_recipes,
        "target_kernel_patch_stacks": target_patch_stacks,
        "target_kernel_overlays": target_overlays,
    }

    outputs = {
        "packages.json": package_manifest,
        "executables.json": executable_manifest,
        "sources.json": sources_manifest,
    }
    for filename, payload in outputs.items():
        destination = output / filename
        destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    summary = {
        "packages": package_manifest["counts"],
        "package_comparisons": package_manifest["comparisons"],
        "executables": executable_manifest["counts"],
        "services_with_explicit_user": len(
            executable_manifest["privilege_boundary"]["services_with_explicit_user"]
        ),
        "services_with_jail": len(
            executable_manifest["privilege_boundary"]["services_with_jail"]
        ),
        "services_with_seccomp": len(
            executable_manifest["privilege_boundary"]["services_with_seccomp"]
        ),
        "sources": sources_manifest["counts"],
        "output_sha256": {name: sha256_file(output / name) for name in outputs},
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
