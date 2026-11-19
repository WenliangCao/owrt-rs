#!/usr/bin/env python3
"""Create new comparison freezes without changing any historical specification."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib

import ci_check_dnsmasq_pgo_pipeline as pipeline
import ci_dnsmasq_profile as profiles


builder = pipeline.target.builder
V033 = "1e25d61dc707833f97afa5a56148f4dbceb50ed3"


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        stream.write(json.dumps(data, indent=2) + "\n")


def load(path):
    return json.loads(path.read_text())


def source(commit, directory):
    commit = subprocess.check_output(["git", "-C", str(builder.REPO), "rev-parse", commit + "^{commit}"], text=True).strip()
    roots = ["rust-toolchain.toml", "manifests/release-25.12.6.json", "components/dnsmasq", "components/ubus",
             "components/platform", "packaging/openwrt/owrt-dnsmasq", "tools/dnsmasq/build_package.py",
             "tools/dnsmasq/build_package.sh", "tools/cargo.sh", "tools/mbx_cargo.sh"]
    names = subprocess.check_output(["git", "-C", str(builder.REPO), "ls-tree", "-r", "--name-only", commit, "--", *roots], text=True).splitlines()
    archive = directory / "source.tar"
    subprocess.run(["git", "-C", str(builder.REPO), "archive", "--output", str(archive), commit, "--", *names], check=True)
    with tarfile.open(archive) as stream:
        stream.extractall(directory, filter="data")
    return commit, builder.audit.inputs(directory, version="25.12.6")


def generate(commit, role, out):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        commit, files = source(commit, root)
        compiler = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if role == "v033-aa":
        profiles.require(commit == V033 and compiler == "1.98.1", "A/A requires actual v033 product and original compiler/locks")
    else:
        profiles.require(compiler.startswith("1.100."), "toolchain/final comparisons require Rust 1.100.x")
    historic_path = builder.REPO / "packaging/image/native-25.12.6.json"
    historic = load(historic_path)["dnsmasq_build"]
    # This is the deployed input identity, never an alias for the new source.
    profiles.require(historic["source_commit"] == "0e077f258811c6250edfe188de62a52e48d7a8df", "historical native input changed")
    spec = {"schema": 1, "scope": "fresh CI PGO comparison; no deployment/performance qualification",
        "comparison_role": role, "openwrt": "25.12.6", "source_commit": commit,
        "source_date_epoch": int(subprocess.check_output(["git", "-C", str(builder.REPO), "show", "-s", "--format=%ct", commit], text=True)),
        "source_files": files, "source_file_count": len(files),
        "source_digest": hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "rust_toolchain": {"release": compiler}, "package_release": "4", "elf_max_bytes": 2_500_000,
        "apk_max_bytes": 1_400_000, "pgo_stage": "generate", "instrumentation_budget": dict(pipeline.INSTRUMENTATION_BUDGET),
        "pgo": {"build_slot": pipeline.COMPARISON_BUILD_SLOT, "profile_output_dir": pipeline.PROFILE_OUTPUT, "retain_link_map": True},
        "deployed_baseline": {key: historic[key] for key in ("source_commit", "source_digest", "reference_elf_sha256", "reference_elf_bytes")}}
    write(out, spec)
    pipeline.load_spec(out, "generate")
    return spec


def toolchain(path, native=False):
    spec = load(path)
    if native:
        spec = spec["dnsmasq_build"]
    commit = builder.resolve_commit(builder.REPO, spec["source_commit"])
    data = subprocess.check_output(["git", "-C", str(builder.REPO), "show", commit + ":rust-toolchain.toml"])
    profiles.require(hashlib.sha256(data).hexdigest() == spec["source_files"]["rust-toolchain.toml"], "selected toolchain input differs")
    return tomllib.loads(data.decode())["toolchain"]["channel"]


def use(spec_path, item, out):
    spec = copy.deepcopy(pipeline.load_spec(spec_path, "generate"))
    data, _, _ = profiles.get_profile(item)
    with tempfile.TemporaryDirectory() as directory:
        bundle = Path(directory) / "profile"
        profiles.unpack(data, bundle)
        profiles.require((bundle / "generation-spec.json").read_bytes() == spec_path.read_bytes(),
                         "embedded generation spec bytes differ")
        identities, _ = profiles.verify_bundle(bundle, spec)
        profile = bundle / "profile.profdata"
        profile_sha256, profile_bytes = profiles.sha(profile), profile.stat().st_size
    spec.pop("instrumentation_budget")
    spec["pgo_stage"] = "candidate-use"
    spec["pgo"].pop("profile_output_dir")
    spec["pgo"].update(profile_artifact=item, profile_sha256=profile_sha256,
                       profile_bytes=profile_bytes, training=identities)
    write(out, spec)
    pipeline.load_spec(out, "candidate-use")


def freeze(spec_path, manifest_path, artifact_path, out):
    spec = copy.deepcopy(pipeline.load_spec(spec_path, "candidate-use"))
    report = load(manifest_path)
    profiles.require(report["status"] == "created-unqualified-pgo-candidate"
        and report["pgo_stage"] == "candidate-use" and report["release_qualified"] is False
        and report["compiler_warnings"]["strict_compiler_warnings_zero"]
        and report["warnings"]["strict_compiler_warnings_zero"] and not report["pgo"]["profile_diagnostics"],
        "candidate must be freshly built with zero warnings/profile mismatches")
    for key in ("source_commit", "source_digest", "source_files", "source_date_epoch"):
        same = str(report[key]) == str(spec[key]) if key == "source_date_epoch" else report[key] == spec[key]
        profiles.require(same, "candidate freeze source differs: " + key)
    for key, value in spec["pgo"].items():
        profiles.require(report["pgo"][key] == value, "candidate PGO input differs: " + key)
    artifact = load(artifact_path)
    profiles.artifact_identity(artifact)
    evidence = profiles.metadata(artifact)
    run = evidence["run"]
    expected_name = f"dnsmasq-pgo-freeze-candidate-{run['head_sha']}-{run['id']}"
    profiles.require(evidence["artifact"]["name"] == expected_name
                     and report["runner_commit"] == run["head_sha"],
                     "candidate manifest is not bound to its successful CI run")
    archive, _, _ = profiles.get_archive(artifact)
    members = profiles.zip_members(archive, {"manifest.json", "build-spec.json", "dnsmasq-rs"},
                                   profiles.MAX_BYTES, exact=False)
    profiles.require(members["manifest.json"] == manifest_path.read_bytes(),
                     "candidate manifest differs from successful CI artifact")
    profiles.require(json.loads(members["build-spec.json"]) == spec,
                     "candidate build spec differs from successful CI artifact")
    profiles.require(profiles.sha_bytes(members["dnsmasq-rs"]) == report["elf"]["sha256"]
                     and len(members["dnsmasq-rs"]) == report["elf"]["size"],
                     "candidate ELF differs from successful CI artifact")
    spec.update(pgo_stage="frozen-use", reference_elf_sha256=report["elf"]["sha256"],
                reference_elf_bytes=report["elf"]["size"],
                candidate_build_manifest_sha256=profiles.sha(manifest_path),
                candidate_build_artifact=artifact)
    write(out, spec)
    pipeline.load_spec(out, "frozen-use")


def native(spec_path, receipts, out):
    dns = pipeline.load_spec(spec_path, "frozen-use")
    profiles.artifact_identity(dns.get("candidate_build_artifact", {}))
    profiles.require(pipeline.frozen_hash(dns.get("candidate_build_manifest_sha256")),
                     "candidate-use Actions artifact must be frozen")
    spec = copy.deepcopy(load(builder.REPO / "packaging/image/native-25.12.6.json"))
    hashes, commits, evidence, comparison_sources = {}, set(), [], []
    for path in receipts:
        report = load(path)
        profiles.require(report.get("status") == "passed" and report.get("phase") == "target"
                         and report.get("warnings", {}).get("strict_compiler_warnings_zero") is True
                         and pipeline.frozen_hash(report.get("source_commit"), 40)
                         and isinstance(report.get("binary_sha256"), dict),
                         "component receipt must be a passed zero-warning canonical target build")
        comparison = report.get("comparison_source", {})
        profiles.require(comparison.get("source_commit") == dns["source_commit"]
                         and pipeline.frozen_hash(comparison.get("runner_commit"), 40)
                         and pipeline.frozen_hash(comparison.get("component_tree"), 40)
                         and pipeline.frozen_hash(comparison.get("toolchain_sha256"))
                         and isinstance(comparison.get("adapter_files"), dict)
                         and comparison["adapter_files"]
                         and all(isinstance(name, str) and not Path(name).is_absolute()
                                 and ".." not in Path(name).parts and pipeline.frozen_hash(digest)
                                 for name, digest in comparison["adapter_files"].items()),
                         "component receipt lacks a pinned product/runner comparison source")
        product = builder.resolve_commit(builder.REPO, dns["source_commit"])
        tree = subprocess.check_output(["git", "-C", str(builder.REPO), "rev-parse", product + ":components"], text=True).strip()
        rust_toolchain = subprocess.check_output(["git", "-C", str(builder.REPO), "show",
                                                  product + ":rust-toolchain.toml"])
        profiles.require(comparison["component_tree"] == tree
                         and comparison["toolchain_sha256"] == hashlib.sha256(rust_toolchain).hexdigest(),
                         "comparison report product tree/toolchain differs from dnsmasq freeze")
        comparison_sources.append(comparison)
        commits.add(report["source_commit"])
        for name, digest in report["binary_sha256"].items():
            profiles.require(name not in hashes and pipeline.frozen_hash(digest), "duplicate/invalid component identity")
            hashes[name] = digest
        evidence.append({"sha256": profiles.sha(path), "source_commit": report["source_commit"]})
    profiles.require(len(commits) == 1, "component receipts must use one common CI source")
    profiles.require(commits == {dns["source_commit"]}, "component receipts target a different product revision")
    profiles.require(comparison_sources and all(item == comparison_sources[0] for item in comparison_sources),
                     "component receipts use different runner adapters or product mappings")
    expected_binaries = {item["binary"] for name, item in spec["components"].items() if name != "dnsmasq"}
    profiles.require(set(hashes) == expected_binaries, "component receipts do not cover exactly the native non-DNS binaries")
    for name, item in spec["components"].items():
        if name != "dnsmasq":
            profiles.require(item["binary"] in hashes, "missing freshly built component: " + name)
            item["reference_elf_sha256"] = hashes[item["binary"]]
    spec["dnsmasq_build"] = dns
    comparison = comparison_sources[0]
    spec["version"] = "0.3.4-r1"
    spec["comparison_build"] = {"source_commit": commits.pop(), "runner_commit": comparison["runner_commit"],
        "component_tree": comparison["component_tree"], "toolchain_sha256": comparison["toolchain_sha256"],
        "adapter_files": comparison["adapter_files"], "component_receipts": evidence,
        "dnsmasq_freeze_sha256": profiles.sha(spec_path), "release_published": False, "physical_router_qualified": False}
    write(out, spec)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--source-ref", required=True)
    g.add_argument("--role", required=True, choices=("v033-aa", "toolchain-only", "final"))
    g.add_argument("--out", type=Path, required=True)
    t = sub.add_parser("toolchain")
    t.add_argument("--spec", type=Path, required=True)
    t.add_argument("--native", action="store_true")
    u = sub.add_parser("use")
    u.add_argument("--spec", type=Path, required=True)
    u.add_argument("--artifact", type=Path, required=True, help="JSON: kind, repository, artifact_id, run_id, head_sha, archive_sha256")
    u.add_argument("--out", type=Path, required=True)
    f = sub.add_parser("freeze")
    f.add_argument("--spec", type=Path, required=True)
    f.add_argument("--manifest", type=Path, required=True)
    f.add_argument("--artifact", type=Path, required=True,
                   help="JSON identity for the successful candidate-use Actions artifact")
    f.add_argument("--out", type=Path, required=True)
    n = sub.add_parser("native")
    n.add_argument("--spec", type=Path, required=True)
    n.add_argument("--component-manifest", type=Path, action="append", required=True)
    n.add_argument("--out", type=Path, required=True)
    b = sub.add_parser("bundle")
    for flag in ("spec", "manifest", "receipt", "profile", "out"):
        b.add_argument("--" + flag, type=Path, required=True)
    a = p.parse_args()
    if a.action == "generate":
        generate(a.source_ref, a.role, a.out)
    elif a.action == "toolchain":
        print(toolchain(a.spec, a.native))
    elif a.action == "use":
        use(a.spec, load(a.artifact), a.out)
    elif a.action == "freeze":
        freeze(a.spec, a.manifest, a.artifact, a.out)
    elif a.action == "native":
        native(a.spec, a.component_manifest, a.out)
    else:
        profiles.bundle(a.spec, a.manifest, a.receipt, a.profile, a.out)


if __name__ == "__main__":
    main()
