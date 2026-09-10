#!/usr/bin/env python3
"""Inventory exact-image entrypoints, ELF dependencies and runtime assets.

Run on the Linux build host with readelf. This inventories uncompressed files,
not installed/compressed firmware size, exclusive dependency ownership or RAM.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    root = args.rootfs.resolve()
    manifest = json.loads(args.manifest.read_text())

    def resolve(name):
        name = posixpath.normpath("/" + name.lstrip("/"))
        for _ in range(40):
            parts = name.lstrip("/").split("/")
            for index in range(len(parts)):
                path = root.joinpath(*parts[:index + 1])
                if path.is_symlink():
                    target = os.readlink(path)
                    prefix = target if target.startswith("/") else "/" + "/".join(parts[:index] + [target])
                    name = posixpath.normpath(prefix + "/" + "/".join(parts[index + 1:]))
                    break
            else:
                return name, root / name.lstrip("/")
        raise RuntimeError("symlink loop")

    files = {}

    def inspect(name):
        canonical, path = resolve(name)
        if canonical not in files:
            content = path.read_bytes()
            needed = []
            if content.startswith(b"\x7fELF"):
                dynamic = subprocess.run(["readelf", "-d", str(path)], capture_output=True,
                                         text=True, check=True).stdout
                needed = re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic)
            files[canonical] = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
                                "elf_needed": needed}
        return canonical

    def closure(roots):
        found = set()
        pending = list(roots)
        while pending:
            name = inspect(pending.pop())
            if name in found:
                continue
            found.add(name)
            for library in files[name]["elf_needed"]:
                for directory in ("/lib/", "/usr/lib/"):
                    candidate = directory + library
                    if resolve(candidate)[1].is_file():
                        pending.append(candidate)
                        break
                else:
                    raise RuntimeError("missing image dependency: " + library)
        return sorted(found)

    def members(directory, pattern="**/*"):
        return ["/" + str(p.relative_to(root)) for p in (root / directory).glob(pattern)
                if p.is_file() and not p.is_symlink()]

    entrypoints = {name: value["original"]["path"] for name, value in manifest["components"].items()}
    for name, path in entrypoints.items():
        assert files[inspect(path)]["sha256"] == manifest["components"][name]["original"]["sha256"]
    groups = {"nine_entrypoints": sorted(inspect(path) for path in entrypoints.values()),
              "entrypoints_with_elf_dependency_closure": closure(entrypoints.values()),
              "shell_and_reload_cli_tools": closure(["/bin/busybox", "/bin/ubus", "/sbin/uci"]),
              "firewall_ucode_runtime": closure(["/usr/bin/ucode", "/usr/lib/ucode/fs.so",
                  "/usr/lib/ucode/uci.so", "/usr/lib/ucode/ubus.so", "/usr/share/ucode/fw4.uc"]
                  + members("usr/share/firewall4")),
              "httpd_ubus_and_tls_runtime": closure(["/usr/lib/uhttpd_ubus.so", "/lib/libustream-ssl.so"]),
              "rpcd_plugins_and_scripts": closure(members("usr/lib/rpcd") + members("usr/share/rpcd/ucode")),
              "image_ucode_native_modules": closure(members("usr/lib/ucode")),
              "netifd_ucode_scripts": closure(members("lib/netifd", "*.uc")),
              "preserved_nft_execution_plane": closure(["/usr/sbin/nft"])}
    selected = set().union(*(set(paths) for name, paths in groups.items() if name != "preserved_nft_execution_plane"))
    result = {"schema": 1, "image": manifest["image"], "unit": "uncompressed file bytes",
              "notes": ["Groups overlap; shared libraries are counted once within each group.",
                        "Selected runtime groups are an inventory, not a minimal exclusive dependency set.",
                        "BusyBox, libc, libuci, ucode and other dependencies are also used by preserved components.",
                        "Originals and packages remain installed for recovery; these are not removable-space estimates."],
              "rust_nine_static_entrypoints_bytes": sum(v["rust"]["bytes"] for v in manifest["components"].values()),
              "selected_original_runtime_union_bytes": sum(files[p]["bytes"] for p in selected),
              "groups": {name: {"bytes": sum(files[p]["bytes"] for p in paths), "files": paths}
                         for name, paths in groups.items()}, "files": dict(sorted(files.items()))}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
