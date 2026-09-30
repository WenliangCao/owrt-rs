#!/usr/bin/env python3
"""Verify the image's recipe/archive, then reconstruct its patched C source.

No downloads, router access, network listeners, or modification of input trees.
Generated source and identity records must live below the repository's private/.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

REPO = Path(__file__).resolve().parents[2]
EVIDENCE = REPO / "private/network-research-20260929/dns"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=EVIDENCE)
    parser.add_argument("--output", type=Path, default=REPO / "private/dnsmasq-rewrite/reference")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(REPO / "private"):
        parser.error("output must be in ignored private/")
    manifest = json.loads((REPO / "manifests/ax3000t-stock-openwrt-25.12.5/sources.json").read_text())
    recipe = manifest["recipes"]["feeds/base/network/services/dnsmasq"]
    archive = args.input / "dnsmasq-2.93.tar.xz"
    expected = recipe["source_assignments"]["PKG_HASH"][0]["value"]
    if digest(archive) != expected:
        raise SystemExit("archive SHA256 does not match exact image manifest")
    recipe_root = args.input / "recipe/dnsmasq"
    files = [{"path": recipe["recipe_path"] + "/Makefile", "sha256": recipe["recipe_makefile_sha256"]}]
    files += recipe["auxiliary_files"]
    for entry in files:
        path = recipe_root / Path(entry["path"]).relative_to(recipe["recipe_path"])
        if digest(path) != entry["sha256"]:
            raise SystemExit(f"recipe SHA256 mismatch: {path}")
    output.parent.mkdir(parents=True, exist_ok=True)
    # A fresh reconstruction also checks whether a pre-existing output drifted.
    with tempfile.TemporaryDirectory(dir=output.parent, prefix="reference-") as temp:
        with tarfile.open(archive) as tar:
            tar.extractall(temp, filter="data")
        tree = Path(temp) / "dnsmasq-2.93"
        for entry in recipe["patches"]:
            patch = recipe_root / "patches" / Path(entry["path"]).name
            subprocess.run(["patch", "--batch", "-p1", "-i", str(patch.resolve())], cwd=tree, check=True, capture_output=True)
        hashes = {str(p.relative_to(tree)): digest(p) for p in sorted(tree.rglob("*")) if p.is_file()}
        identity = {
            "openwrt": "25.12.5", "package": "dnsmasq", "version": "2.93-r1", "variant": "nodhcpv6",
            "recipe_revision": recipe["repository_revision"], "archive_sha256": expected,
            "recipe_files": files, "patched_files": hashes,
            "copts": ["-DHAVE_UBUS", "-DHAVE_POLL_H", "-DNO_DHCP6", "-DNO_AUTH", "-DNO_IPSET", "-DNO_ID"],
            "scope": "Matching source and feature flags; native host build is not a router performance result.",
        }
        if output.exists():
            previous = json.loads((output / "identity.json").read_text())
            if previous != identity:
                raise SystemExit("existing reference identity differs; choose a new output")
            for name, sha in hashes.items():
                if digest(output / "dnsmasq-2.93" / name) != sha:
                    raise SystemExit(f"existing reference source drifted: {name}")
        else:
            output.mkdir()
            tree.rename(output / "dnsmasq-2.93")
            (output / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    print(json.dumps({"verified_recipe_files": len(files), "verified_source_files": len(hashes),
                      "archive_sha256": expected, "identity": str(output / "identity.json")}))


if __name__ == "__main__":
    main()
