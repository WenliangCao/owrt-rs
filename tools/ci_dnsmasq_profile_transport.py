#!/usr/bin/env python3
"""Move a trained PGO ZIP to Actions, using the authenticated gh client.

Dispatch sends bytes on stdin. The runner reads its event file directly; keep
payloads out of step environments, command arguments, logs and Git.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

import ci_check_dnsmasq_pgo_pipeline as pipeline
import ci_dnsmasq_profile as profiles


CHUNK_BYTES = 36_000  # 48,000 base64 characters, below the dispatch limit.
MAX_PARTS = (profiles.MAX_ARCHIVE_BYTES + CHUNK_BYTES - 1) // CHUNK_BYTES
CHUNK_ARTIFACT_BYTES = CHUNK_BYTES + 4096
PREFIX = "dnsmasq-pgo-profile"
require = profiles.require


def spec_file(value):
    path = Path(value)
    require(re.fullmatch(r"packaging/image/[A-Za-z0-9_.-]+\.json", value)
            and path.is_file() and not path.is_symlink(), "expected a CI source spec in packaging/image")
    return path


def transport_fields(fields):
    transfer = fields["transfer"]
    digest = fields["bundle_sha256"]
    generation_run = fields["generation_run"]
    require(re.fullmatch(r"[0-9a-f]{32}", transfer) and pipeline.frozen_hash(digest)
            and re.fullmatch(r"[1-9][0-9]{0,19}", generation_run), "invalid PGO transfer identity")
    return transfer, digest, int(generation_run)


def verify_generator(repository, generation_run, bundle, spec):
    identities, built = profiles.verify_bundle(bundle, spec)
    run = profiles.api(f"repos/{repository}/actions/runs/{generation_run}")
    profiles.verify_run(run, generation_run)
    require(run["head_sha"] == built["runner_commit"], "generator runner commit differs")
    name = f"dnsmasq-pgo-generate-{run['head_sha']}-{generation_run}"
    item = profiles.find_artifact(repository, run, name)
    archive, _, _ = profiles.get_archive(item)
    members = profiles.zip_members(archive, {"manifest.json", "dnsmasq-rs", "build-spec.json"},
                                   profiles.MAX_BYTES, exact=False)
    require(profiles.sha_bytes(members["manifest.json"]) == identities["generator_manifest_sha256"]
            and profiles.sha_bytes(members["dnsmasq-rs"]) == identities["generator_elf_sha256"]
            and json.loads(members["build-spec.json"]) == spec, "bundle differs from actual CI generator")
    return item


def store_chunk(fields, out):
    transfer, digest, generator = transport_fields(fields)
    require(re.fullmatch(r"0|[1-9][0-9]{0,2}", fields["part"]), "invalid chunk number")
    index = int(fields["part"])
    encoded = fields["payload"]
    require(index < MAX_PARTS and 0 < len(encoded) <= CHUNK_BYTES * 4 // 3, "invalid chunk size")
    try:
        data = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise ValueError("invalid chunk encoding") from None
    require(0 < len(data) <= CHUNK_BYTES, "invalid chunk size")
    out.mkdir()
    (out / "chunk.bin").write_bytes(data)
    (out / "chunk.json").write_text(json.dumps({"transfer": transfer, "bundle_sha256": digest,
        "generation_run": generator, "part": index, "chunk_sha256": profiles.sha_bytes(data)}))


def assemble(fields, repository, head, out, evidence_path):
    transfer, digest, generator = transport_fields(fields)
    spec = pipeline.load_spec(spec_file(fields["spec"]), "generate")
    parts = fields["part"].split(",")  # Run IDs in chunk order.
    require(0 < len(parts) <= MAX_PARTS and len(set(parts)) == len(parts)
            and all(re.fullmatch(r"[1-9][0-9]{0,19}", part) for part in parts), "invalid chunk run list")
    chunks, artifacts = [], []
    for index, part in enumerate(parts):
        run_id = int(part)
        run = profiles.api(f"repos/{repository}/actions/runs/{run_id}")
        profiles.verify_run(run, run_id)
        label = f"{PREFIX}-chunk-{transfer}-{index}"
        require(run["head_sha"] == head and run["display_title"] == label, "chunk run identity differs")
        item = profiles.find_artifact(repository, run, f"{label}-{run['run_attempt']}")
        data, _, _ = profiles.get_archive(item, max_bytes=CHUNK_ARTIFACT_BYTES)
        files = profiles.zip_members(data, {"chunk.bin", "chunk.json"}, CHUNK_BYTES + 1024)
        chunk = files["chunk.bin"]
        require(0 < len(chunk) <= CHUNK_BYTES and (index == len(parts) - 1 or len(chunk) == CHUNK_BYTES),
                "invalid intermediate or final chunk size")
        require(json.loads(files["chunk.json"]) == {
            "transfer": transfer, "bundle_sha256": digest, "generation_run": generator,
            "part": index, "chunk_sha256": profiles.sha_bytes(chunk)}, "chunk identity differs")
        chunks.append(chunk)
        artifacts.append(item)
    data = b"".join(chunks)
    require(profiles.sha_bytes(data) == digest, "assembled profile ZIP digest differs")
    unpack_verified(data, spec_file(fields["spec"]), out)
    gen = verify_generator(repository, generator, out, spec)
    evidence_path.write_text(json.dumps({"transfer": transfer, "bundle_sha256": digest,
        "source_commit": spec["source_commit"], "generator": gen, "chunks": artifacts}, indent=2) + "\n")


def unpack_verified(data, spec_path, out):
    profiles.unpack(data, out)
    profiles.require((out / "generation-spec.json").read_bytes() == spec_path.read_bytes(),
                     "embedded generation spec bytes differ")
    profiles.verify_bundle(out, pipeline.load_spec(spec_path, "generate"))


def dispatch_run(repository, fields):
    url = f"repos/{repository}/actions/workflows/{profiles.WORKFLOW}/dispatches"
    body = json.dumps({"ref": profiles.CI_BRANCH, "inputs": fields, "return_run_details": True}).encode()
    response = profiles.gh(url, "--method", "POST", "--input", "-", body=body)
    if response:
        run_id = json.loads(response)["workflow_run_id"]
        require(type(run_id) is int and run_id > 0, "dispatch returned an invalid run ID")
        return run_id
    # Older API responses can be empty; locate this unique transfer title.
    label = f"{PREFIX}-{fields['stage'].removeprefix('profile-')}-{fields['transfer']}-{fields['part'] if fields['stage'] == 'profile-chunk' else 'all'}"
    endpoint = f"repos/{repository}/actions/workflows/{profiles.WORKFLOW}/runs"
    for _ in range(30):
        runs = profiles.api(f"{endpoint}?event=workflow_dispatch&branch=ci%2Faudit110-r3&per_page=50")["workflow_runs"]
        matches = [run["id"] for run in runs if run["display_title"] == label]
        require(len(matches) <= 1, "duplicate transport run title")
        if matches:
            return matches[0]
        time.sleep(2)
    raise ValueError(f"could not find dispatched run for transfer {fields['transfer']}")


def wait_runs(repository, run_ids, head, timeout):
    deadline = time.monotonic() + timeout
    completed = {}
    while time.monotonic() < deadline:
        for run_id in run_ids:
            if run_id in completed:
                continue
            run = profiles.api(f"repos/{repository}/actions/runs/{run_id}")
            require(run["head_sha"] == head, f"CI branch advanced during dispatch (run {run_id})")
            if run["status"] == "completed":
                require(run["conclusion"] == "success", f"transport run {run_id} ended with {run['conclusion']}")
                profiles.verify_run(run, run_id)
                completed[run_id] = run
        if len(completed) == len(run_ids):
            return completed
        time.sleep(5)
    raise ValueError(f"timed out waiting for Actions runs {run_ids}")


def dispatch(args):
    spec_path = spec_file(args.spec)
    require(not args.out.exists(), "choose an unused artifact identity output path")
    require(0 < args.bundle_zip.stat().st_size <= profiles.MAX_ARCHIVE_BYTES, "invalid profile ZIP size")
    data = args.bundle_zip.read_bytes()
    with tempfile.TemporaryDirectory() as directory:
        unpack_verified(data, spec_path, Path(directory) / "bundle")
    repository = args.repository
    require(re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", repository), "invalid CI repository")
    head = profiles.api(f"repos/{repository}/git/ref/heads/{profiles.CI_BRANCH}")["object"]["sha"]
    require(pipeline.frozen_hash(head, 40), "no immutable CI branch head")
    # Reject a stale checkout before sending any payload.
    require(profiles.gh(f"repos/{repository}/contents/{spec_path}?ref={head}",
                        "-H", "Accept: application/vnd.github.raw+json") == spec_path.read_bytes(),
            "local generation spec differs from the authorized CI branch")
    common = {"spec": str(spec_path), "transfer": uuid.uuid4().hex, "bundle_sha256": profiles.sha_bytes(data),
              "generation_run": str(args.generation_run)}
    transport_fields(common)
    print(f"Transfer {common['transfer']} on {head}, ZIP bytes: {len(data)}", flush=True)
    ids = []
    for index, start in enumerate(range(0, len(data), CHUNK_BYTES)):
        payload = base64.b64encode(data[start:start + CHUNK_BYTES]).decode("ascii")
        run = dispatch_run(repository, {**common, "stage": "profile-chunk", "part": str(index), "payload": payload})
        ids.append(run)
        print(f"Chunk {index}: run {run}", flush=True)
    wait_runs(repository, ids, head, args.timeout)
    run_id = dispatch_run(repository, {**common, "stage": "profile-assemble", "part": ",".join(map(str, ids))})
    print(f"Assembly: run {run_id}", flush=True)
    run = wait_runs(repository, [run_id], head, args.timeout)[run_id]
    item = profiles.find_artifact(repository, run, f"dnsmasq-profile-{run_id}-{run['run_attempt']}")
    profiles.metadata(item)
    with args.out.open("x") as stream:
        json.dump(item, stream, indent=2)
        stream.write("\n")
    print(f"Profile artifact {item['artifact_id']}; identity written to {args.out}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    sender = sub.add_parser("dispatch")
    sender.add_argument("--repository", required=True)
    sender.add_argument("--spec", required=True)
    sender.add_argument("--generation-run", type=int, required=True)
    sender.add_argument("--bundle-zip", type=Path, required=True)
    sender.add_argument("--out", type=Path, required=True)
    sender.add_argument("--timeout", type=int, default=900)
    sub.add_parser("receive")
    args = parser.parse_args()
    try:
        if args.mode == "dispatch":
            dispatch(args)
        else:
            require(os.environ["GITHUB_REF"] == f"refs/heads/{profiles.CI_BRANCH}", "unexpected transport branch")
            fields = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())["inputs"]
            if fields["stage"] == "profile-chunk":
                store_chunk(fields, Path("profile-chunk"))
            elif fields["stage"] == "profile-assemble":
                assemble(fields, os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"],
                         Path("profile-input"), Path("profile-transport.json"))
            else:
                raise ValueError("unexpected transport stage")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"GitHub API operation failed: {error}\n")


if __name__ == "__main__":
    main()
