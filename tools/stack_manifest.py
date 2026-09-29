#!/usr/bin/env python3
"""Build fresh stack metadata from verified canonical artifacts, never deploy.

Only the exact-image original identities are reused from a previous manifest.
Workflow metadata is the JSON from gh run view --json databaseId,headSha,conclusion.
The output must be new; historical deployment archives remain immutable.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(bundle, original, workflow):
    image = read(bundle / "canonical-manifest.json")
    assert image.get("deployment_layout", "layered-six") == "layered-six", \
        "native firmware must not be deployed using the legacy bind-mount bundle"
    core = read(bundle / "canonical-core-manifest.json")
    source = image["source_commit"]
    assert source == core["source_commit"] == workflow["headSha"], "canonical source mismatch"
    assert workflow["conclusion"] == "success" and type(workflow["databaseId"]) is int and workflow["databaseId"] > 0
    assert sha(bundle / "canonical-manifest.json") == core["image_manifest_sha256"], "canonical manifest mismatch"
    hashes = dict(image["binary_sha256"])
    for name, digest in core["binary_sha256"].items():
        assert name not in hashes or hashes[name] == digest
        hashes[name] = digest
    names = {"ubusd", "netifd", "httpd", "fw4", "rpcd", "procd", "logd", "uci", "reload-config"}
    assert set(original["components"]) == names
    c_hashes = {name: digest for digest, name in (
        line.split(None, 1) for line in (bundle / "original.sha256").read_text().splitlines())}
    components = {}
    for name in sorted(names):
        old = original["components"][name]
        reference = old["original"]
        path = reference["path"]
        assert c_hashes.get(path, c_hashes.get("/rom" + path)) == reference["sha256"], "original image mismatch"
        binary = "reload_config_rs" if name == "reload-config" else name + "-rs"
        elf = bundle / "bins" / binary
        assert sha(elf) == hashes[binary], "canonical binary mismatch: " + binary
        components[name] = {"original": copy.deepcopy(reference), "rust": {
            "binary": binary, "sha256": hashes[binary], "bytes": elf.stat().st_size,
            "builder": f"GitHub release-image {workflow['databaseId']}", "source_commit": source}}
    assert {c["rust"]["binary"] for c in components.values()} == set(hashes)
    tools = {path.name: {"sha256": sha(path), "bytes": path.stat().st_size}
             for path in sorted((bundle / "bins").iterdir()) if path.is_file() and path.name not in hashes}
    scripts = [bundle / "stack-switch.sh", *(p for p in sorted((bundle / "tools").rglob("*")) if p.is_file())]
    return {"schema_version": 2, "status": "prepared_not_deployed", "image": original["image"],
            "source_commit": source, "fix_commit": source,
            "canonical_build": {"source_commit": source, "run_id": workflow["databaseId"], "conclusion": "success"},
            "canonical_manifest_sha256": sha(bundle / "canonical-manifest.json"),
            "core_manifest_sha256": sha(bundle / "canonical-core-manifest.json"),
            "components": components, "tools": tools,
            "scripts_sha256": {str(path.relative_to(bundle)): sha(path) for path in scripts},
            "validation_status": "not_inherited; validate this exact bundle before activation"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("bundle", type=Path)
    p.add_argument("original_manifest", type=Path)
    p.add_argument("workflow_json", type=Path)
    p.add_argument("output", type=Path)
    args = p.parse_args()
    data = build(args.bundle, read(args.original_manifest), read(args.workflow_json))
    with args.output.open("x") as stream:
        stream.write(json.dumps(data, indent=2) + "\n")
    print("Verified nine canonical binaries; wrote new metadata without legacy build labels.")


if __name__ == "__main__":
    main()
