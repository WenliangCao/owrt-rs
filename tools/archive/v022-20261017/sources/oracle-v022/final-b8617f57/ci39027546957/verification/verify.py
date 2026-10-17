#!/usr/bin/env python3
"""Read-only verification of the downloaded final plain target CI evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import zipfile

BASE = Path(__file__).resolve().parents[1]
REPO = BASE.parents[3]
COMMIT = "b8617f574d6d3674e35627f7beedb73a9dd655eb"
ART = BASE / "artifact"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": sha(data)}


def git(*args, **kwargs):
    return subprocess.check_output(["git", "-C", str(REPO), *args], **kwargs)


def write(name, value):
    (BASE / "verification" / name).write_text(json.dumps(value, indent=2) + "\n")


run = json.loads((BASE / "api/run.json").read_text())
job = json.loads((BASE / "api/jobs.json").read_text())["jobs"][0]
api_artifacts = json.loads((BASE / "api/artifacts.json").read_text())["artifacts"]
assert run["head_sha"] == COMMIT and run["conclusion"] == "success"
assert len(api_artifacts) == 1
artifact = api_artifacts[0]
archive = BASE / "downloads" / (str(artifact["id"]) + ".zip")
assert artifact["workflow_run"]["head_sha"] == COMMIT
assert artifact["digest"] == "sha256:" + sha(archive.read_bytes())
assert artifact["size_in_bytes"] == archive.stat().st_size
members = {}
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    for item in z.infolist():
        assert not item.is_dir() and item.filename not in members
        assert Path(item.filename).name == item.filename
        data = z.read(item)
        assert (ART / item.filename).read_bytes() == data
        members[item.filename] = {"bytes": len(data), "sha256": sha(data), "crc32": f"{item.CRC:08x}"}
assert len(members) == 18
write("zip-members.json", members)

manifest = json.loads((ART / "manifest.json").read_text())
source = json.loads((ART / "source-manifest.json").read_text())
for field in ("runner_commit", "source_commit", "checked_product_commit"):
    assert manifest[field] == COMMIT
assert source["commit"] == COMMIT
assert manifest["source_files"] == source["files"]
digest = sha(json.dumps(source["files"], sort_keys=True, separators=(",", ":")).encode())
assert digest == source["digest"] == manifest["source_digest"]
assert sha((ART / "source.tar").read_bytes()) == source["archive_sha256"]
assert git("get-tar-commit-id", input=(ART / "source.tar").read_bytes()).decode().strip() == COMMIT
tar_files = {}
with tarfile.open(ART / "source.tar") as t:
    for item in t:
        assert item.isdir() or item.isfile()
        if item.isfile():
            assert item.name not in tar_files
            tar_files[item.name] = sha(t.extractfile(item).read())
assert tar_files == source["files"]
input_paths = ["rust-toolchain.toml", "manifests/release-25.12.5.json",
               "packaging/openwrt/owrt-dnsmasq", "tools/dnsmasq/build_package.sh",
               "tools/dnsmasq/build_package.py", "components/dnsmasq/Cargo.lock",
               "components/dnsmasq/platform/Cargo.toml", "components/dnsmasq/platform/src"]
for component in ("dnsmasq", "ubus"):
    input_paths.extend([f"components/{component}/Cargo.toml", f"components/{component}/src"])
git_names = git("ls-tree", "-r", "--name-only", COMMIT, "--", *input_paths).decode().splitlines()
assert set(git_names) == set(source["files"])
for name, expected in source["files"].items():
    assert sha(git("show", f"{COMMIT}:{name}")) == expected, name
assert len(source["files"]) == 192
for name, expected in manifest["retained"].items():
    value = members[name]
    assert value["bytes"] == expected["bytes"] and value["sha256"] == expected["sha256"], name

for name in (".github/workflows/dnsmasq-target-check.yml", "tools/ci_check_dnsmasq_target.py",
             "tools/dnsmasq/compiler_warnings.py", "tools/dnsmasq/build_package.py"):
    (BASE / "verification" / Path(name).name).write_bytes(git("show", f"{COMMIT}:{name}"))
spec = importlib.util.spec_from_file_location("frozen_warning_gate", BASE / "verification/compiler_warnings.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
warnings = module.scan(sorted(ART.glob("*.log")))
assert warnings == json.loads((ART / "warnings.json").read_text()) == manifest["warnings"]
assert warnings["strict_compiler_warnings_zero"] and not warnings["compiler_or_unclassified"]
assert len(warnings["sdk_metadata"]) == 76
write("warnings-rescan.json", warnings)
compile_text = (ART / "compile.log").read_text()
assert "dnsmasq-platform" in compile_text and "dnsmasq-rs" in compile_text and "-Dwarnings" in compile_text
assert "profile-use" not in compile_text and "profile-generate" not in compile_text
assert manifest["pgo"] is False and manifest["firmware_built"] is False

elf = ART / "dnsmasq-rs"
apk = ART / manifest["artifact"]["name"]
for path, item in ((elf, manifest["elf"]), (apk, manifest["artifact"])):
    assert sha(path.read_bytes()) == item["sha256"] and path.stat().st_size == item["size"]
assert elf.stat().st_size <= 2500000 and apk.stat().st_size <= 1400000
data = elf.read_bytes()
assert data[:7] == b"\x7fELF\x02\x01\x01"
header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
etype, machine, phoff, phentsize, phnum = header[0], header[1], header[4], header[8], header[9]
assert etype == 3 and machine == 183 and phentsize == 56
phdrs = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize) for i in range(phnum)]
assert not any(p[0] == 3 for p in phdrs)
assert not any(p[0] == 1 and p[1] & 3 == 3 for p in phdrs)
dynamic = next(p for p in phdrs if p[0] == 2)
tags = [struct.unpack_from("<qQ", data, off) for off in range(dynamic[2], dynamic[2] + dynamic[5], 16)]
assert not any(tag == 1 for tag, value in tags)
assert any(tag == 0x6ffffffb and value & 0x08000000 for tag, value in tags)
assert any(tag == 24 or tag == 0x6ffffffb and value & 1 for tag, value in tags)
assert any(p[0] == 0x6474e552 for p in phdrs)
assert any(p[0] == 0x6474e551 and not p[1] & 1 for p in phdrs)
file_output = subprocess.check_output(["file", str(elf)], text=True).strip()
(BASE / "verification/elf-file.txt").write_text(file_output + "\n")
host_log = "\n".join((BASE / "actions.log").read_text().splitlines()[:21]) + "\n"
(BASE / "verification/host-log.txt").write_text(host_log)
assert "host: x86_64-unknown-linux-gnu" in manifest["toolchain"]["rustc"]
receipt = {
    "status": "verified-final-plain-target-artifact", "ci_run": run["id"], "ci_url": run["html_url"],
    "commit": COMMIT, "workflow": run["path"], "pgo": False,
    "artifact": {"id": artifact["id"], "name": artifact["name"], "zip": identity(archive),
                 "github_digest_match": True, "member_count": len(members), "all_members_verified": True},
    "source": {"file_count": len(tar_files), "digest": digest, "archive": identity(ART / "source.tar"),
               "all_files_match_git_commit": True, "archive_embedded_commit_match": True},
    "warnings": {"compiler_or_unclassified": 0, "sdk_metadata": 76, "strict_zero": True,
                 "original_logs_rescanned": True},
    "elf": {**identity(elf), "class": "ELF64", "machine": "AArch64", "type": "ET_DYN",
            "static_pie": True, "interpreter": None, "needed": [], "nx_stack": True,
            "bind_now": True, "relro": True, "runtime_tested": False},
    "apk": identity(apk),
    "host": {"os": "Ubuntu 24.04.5 LTS", "image": "ubuntu-24.04", "image_version": "20261012.334.1",
             "architecture": "x86_64", "runner_name": job["runner_name"], "runner_id": job["runner_id"],
             "labels": job["labels"], "toolchain": manifest["toolchain"]},
    "evidence": {"manifest": identity(ART / "manifest.json"), "source_manifest": identity(ART / "source-manifest.json"),
                 "logs_zip": identity(BASE / "downloads/run-logs.zip"), "actions_log": identity(BASE / "actions.log")},
}
write("receipt.json", receipt)
print(json.dumps(receipt, indent=2))
