#!/usr/bin/env python3
"""Source-bound PGO bundles transported through immutable Actions artifacts."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import zipfile


MEMBERS = {"profile.profdata", "training-profile.json", "generator-manifest.json", "generation-spec.json"}
MAX_BYTES = 20_000_000
MAX_ARCHIVE_BYTES = MAX_BYTES + 128 * 1024
CI_BRANCH = "ci/audit110-r3"
WORKFLOW = "dnsmasq-pgo-candidate.yml"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return sha_bytes(Path(path).read_bytes())


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def artifact_identity(item):
    require(isinstance(item, dict) and item.get("kind") == "github-actions-artifact", "expected Actions artifact input")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", item.get("repository", "")), "invalid artifact repository")
    require(all(part not in (".", "..") for part in item["repository"].split("/")), "invalid artifact repository")
    require(all(type(item.get(k)) is int and item[k] > 0 for k in ("artifact_id", "run_id")), "artifact/run IDs required")
    require(re.fullmatch(r"[0-9a-f]{40}", item.get("head_sha", "")) and
            re.fullmatch(r"[0-9a-f]{64}", item.get("archive_sha256", "")), "artifact commit and archive digest required")


def verify_bundle(directory, spec, pgo=None):
    require({p.name for p in directory.iterdir()} == MEMBERS and all(
        p.is_file() and not p.is_symlink() for p in directory.iterdir()), "unexpected PGO bundle members")
    generation = json.loads((directory / "generation-spec.json").read_text())
    built = json.loads((directory / "generator-manifest.json").read_text())
    receipt = json.loads((directory / "training-profile.json").read_text())
    if spec["pgo_stage"] == "generate":
        require(generation == spec, "bundle generation spec differs from CI input")
    for key in ("source_commit", "source_digest", "source_date_epoch", "source_file_count"):
        require(str(spec[key]) == str(generation[key]) == str(built[key]) == str(receipt[key]),
                "profile training source differs: " + key)
    require(spec["source_files"] == generation["source_files"] == built["source_files"], "profile source map differs")
    require(generation["pgo_stage"] == "generate" and built["status"] == "built-instrumented-training-only"
            and built["release_qualified"] is False and built["pgo"]["mode"] == "generate"
            and built["compiler_warnings"]["strict_compiler_warnings_zero"], "unverified generator build")
    require(receipt["status"] == "training-complete-unqualified" and receipt["release_qualified"] is False
            and receipt["product_training_reused"] is False
            and receipt["profile_count"] == 50 and receipt["scene_count"] == 11, "fresh complete training required")
    identities = {"generator_manifest_sha256": sha(directory / "generator-manifest.json"),
                  "generator_elf_sha256": built["elf"]["sha256"],
                  "training_receipt_sha256": sha(directory / "training-profile.json")}
    require(receipt["ci_build"]["sha256"] == identities["generator_manifest_sha256"]
            and receipt["generate_elf"]["sha256"] == identities["generator_elf_sha256"]
            and receipt["source_spec"]["sha256"] == sha(directory / "generation-spec.json"),
            "training receipt does not bind generator/spec")
    profile = directory / "profile.profdata"
    require(0 < profile.stat().st_size <= MAX_BYTES
            and receipt["merged_profile"]["sha256"] == sha(profile)
            and receipt["merged_profile"]["bytes"] == profile.stat().st_size, "training profile identity differs")
    if pgo is not None:
        require(pgo["training"] == identities and pgo["profile_sha256"] == sha(profile)
                and pgo["profile_bytes"] == profile.stat().st_size, "profile differs from committed freeze")
    return identities, built


def zip_members(data, members, limit, *, exact=True):
    require(0 < len(data) <= MAX_ARCHIVE_BYTES, "invalid Actions ZIP size")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        listing = archive.infolist()
        names = {m.filename for m in listing}
        require(len(names) == len(listing) and (names == members if exact else members <= names),
                "unexpected/duplicate artifact paths")
        selected = [archive.getinfo(name) for name in sorted(members)]
        require(sum(m.file_size for m in selected) <= limit, "PGO bundle is too large")
        for member in selected:
            require(not member.is_dir() and not stat.S_ISLNK(member.external_attr >> 16),
                    "artifact symlink/directory rejected")
        return {member.filename: archive.read(member) for member in selected}


def unpack(data, out):
    files = zip_members(data, MEMBERS, MAX_BYTES)
    out.mkdir(exist_ok=False)
    for name, content in files.items():
        (out / name).write_bytes(content)


def gh(*args, body=None):
    # Do not allow gh's HTTP trace to reveal a dispatch body or artifact bytes.
    env = dict(os.environ)
    env.pop("GH_DEBUG", None)
    return subprocess.check_output(["gh", "api", "--hostname", "github.com", *args],
                                   input=body, stderr=subprocess.PIPE, env=env, timeout=120)


def api(path):
    return json.loads(gh(path))


def verify_run(run, run_id):
    require(run["id"] == run_id and run["head_branch"] == CI_BRANCH
            and run["path"] == f".github/workflows/{WORKFLOW}"
            and run["event"] == "workflow_dispatch" and run["conclusion"] == "success",
            "PGO input must come from a successful dispatch on the authorized CI branch")


def find_artifact(repository, run, name):
    matches = [row for row in api(f"repos/{repository}/actions/runs/{run['id']}/artifacts")["artifacts"]
               if row["name"] == name]
    require(len(matches) == 1, f"expected one Actions artifact named {name} (run {run['id']})")
    artifact = matches[0]
    item = {"kind": "github-actions-artifact", "repository": repository,
            "run_id": run["id"], "head_sha": run["head_sha"], "artifact_id": artifact["id"],
            "archive_sha256": artifact.get("digest", "").removeprefix("sha256:")}
    artifact_identity(item)
    return item


def metadata(item):
    artifact_identity(item)
    require(item["repository"] == os.environ.get("GITHUB_REPOSITORY", item["repository"]),
            "PGO artifact must come from this repository")
    prefix = f"repos/{item['repository']}/actions"
    artifact = api(f"{prefix}/artifacts/{item['artifact_id']}")
    run = api(f"{prefix}/runs/{item['run_id']}")
    require(artifact["id"] == item["artifact_id"] and not artifact["expired"]
            and 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE_BYTES
            and artifact["workflow_run"]["id"] == item["run_id"]
            and artifact["workflow_run"]["head_sha"] == item["head_sha"]
            and artifact["digest"] == "sha256:" + item["archive_sha256"], "Actions artifact identity differs")
    verify_run(run, item["run_id"])
    require(run["head_sha"] == item["head_sha"], "profile input run commit differs")
    return {"artifact": artifact, "run": run}


def get_archive(item, *, max_bytes=MAX_ARCHIVE_BYTES):
    evidence = metadata(item)
    size = evidence["artifact"]["size_in_bytes"]
    require(size <= max_bytes, "Actions artifact exceeds its size limit")
    endpoint = f"repos/{item['repository']}/actions/artifacts/{item['artifact_id']}/zip"
    data = gh(endpoint)
    require(len(data) == size and sha_bytes(data) == item["archive_sha256"],
            "downloaded artifact archive digest/size differs")
    return data, evidence, ["gh", "api", "--hostname", "github.com", endpoint]


def get_profile(item):
    data, evidence, command = get_archive(item)
    run = evidence["run"]
    require(evidence["artifact"]["name"] == f"dnsmasq-profile-{run['id']}-{run['run_attempt']}",
            "expected assembled PGO profile artifact from this run attempt")
    return data, evidence, command


def download(pgo, out, spec):
    data, evidence, command = get_profile(pgo["profile_artifact"])
    archive = out / "profile-artifact.zip"
    with archive.open("xb") as stream:
        stream.write(data)
    directory = out / "pgo"
    unpack(archive.read_bytes(), directory)
    _, generator = verify_bundle(directory, spec, pgo)
    # Cargo's flags record the path, so different profile bytes must use a
    # different path even when the shared build cache has a usable executable.
    profile = directory / f"dnsmasq-{spec['source_commit'][:8]}-{pgo['profile_sha256']}.profdata"
    (directory / "profile.profdata").rename(profile)
    evidence["resolved_rustc"] = generator.get("resolved_rustc")
    (out / "profile-provenance.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return profile, command


def bundle(spec_path, built_path, receipt_path, profile, out):
    out.mkdir(exist_ok=False)
    for src, dest in ((spec_path, "generation-spec.json"), (built_path, "generator-manifest.json"),
                      (receipt_path, "training-profile.json"), (profile, "profile.profdata")):
        shutil.copy2(src, out / dest)
    return verify_bundle(out, json.loads(spec_path.read_text()))
