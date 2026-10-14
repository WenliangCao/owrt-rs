#!/usr/bin/env python3
"""Verify audit input identities and run fresh isolated ordinary unit tests."""
import hashlib
import json
import pathlib
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(pathlib.Path(path).read_text())


root = pathlib.Path(sys.argv[1])
source = root / "source"
private = root / "private"
identity = read(sys.argv[2])
expected = identity["source_inputs"]
assert len(expected) == 178 and not identity["git_worktree_mismatches"]
result = private / "build-verification.json"
assert not result.exists(), "fresh verification output required"
report = {
    "head": identity["head"],
    "main": identity["main"],
    "source_digest": identity["source_digest"],
    "source_files_verified": len(expected),
    "scope": "Fresh SDK-linker Cargo release and test-profile builds; no fresh full SDK package build.",
    "commands": [],
    "complete": False,
}


def save():
    result.write_text(json.dumps(report, indent=2) + "\n")


def verify_source():
    assert all(sha(source / name) == digest for name, digest in expected.items())


def run(name, argv, timeout=1200):
    log = private / (name + ".log")
    assert not log.exists()
    row = {"name": name, "argv": list(map(str, argv)), "started": time.time()}
    report["commands"].append(row)
    save()
    with log.open("wb") as output:
        completed = subprocess.run(row["argv"], stdout=output, stderr=output, timeout=timeout)
    row.update(exit=completed.returncode, elapsed_seconds=time.time() - row["started"],
               log_sha256=sha(log))
    save()
    assert completed.returncode == 0, name
    return row


verify_source()
retained_sources = read(sys.argv[3])
for role, item in retained_sources.items():
    snapshot = pathlib.Path(item["source"])
    assert all(sha(snapshot / name) == digest for name, digest in item["source_inputs"].items()), role
report["retained_sources"] = retained_sources
report["toolchain"] = subprocess.check_output(["/home/ubuntu/.cargo/bin/rustc", "+1.98.1", "-Vv"], text=True)
artifacts = {
    "exact_image_c": (
        "/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files/usr/sbin/dnsmasq",
        "097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87"),
    "main_release": (
        "/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs",
        "ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863"),
    "pre_f2_fix_release": (
        "/home/ubuntu/dnsmasq-audit-fix5-20261014/private/release/dnsmasq-rs",
        "7a56d4302dc8fbd3df8d5c441d2b910c0cf2222d9d3b105ef599ad4ca2150f7c"),
}
report["retained_artifacts"] = {}
for name, (path, digest) in artifacts.items():
    assert sha(path) == digest, name
    report["retained_artifacts"][name] = {
        "path": path, "sha256": digest, "bytes": pathlib.Path(path).stat().st_size}

c_source = pathlib.Path("/home/ubuntu/dnsmasq-rewrite-20260929/reference/dnsmasq-2.93")
c_files = {
    "src/rfc1035.c": "231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222",
    "src/util.c": "33920165ef3e92f65d1cab75fe8da7772ad7389b37da79ba881957080f12f973",
}
assert all(sha(c_source / name) == digest for name, digest in c_files.items())
c_identity = read(c_source.parent / "identity.json")
assert c_identity["version"] == "2.93-r1"
assert c_identity["recipe_revision"] == "f0a60eee2fe051741c643ea6118718aae1ef17fb"
assert all(sha(c_source / name) == digest for name, digest in c_identity["patched_files"].items())
report["reference_source"] = {"path": str(c_source), "files_verified": c_files,
                              "patched_files_verified": len(c_identity["patched_files"]),
                              "identity_sha256": sha(c_source.parent / "identity.json"),
                              "recipe_revision": c_identity["recipe_revision"],
                              "basis": "Hashes from committed matching-source identity; actual image C determines semantics."}
release = private / "release"
report["release_build"] = read(release / "build.json")
report["release_build_argv"] = ["sh", str(source / "tools/dnsmasq/oracle_build.sh"),
                                str(source), str(release), "release"]
report["release_build_logs"] = {name: sha(release / name)
                                for name in ("build.json", "build.log", "build.stdout", "clean.log", "clean.stdout")}
for artifact in report["release_build"]["artifacts"]:
    assert sha(release / artifact["path"]) == artifact["sha256"]
save()

run("fresh-tests-build", ["sh", source / "tools/dnsmasq/oracle_build.sh", source,
                          private / "tests", "tests"])
report["test_build"] = read(private / "tests/build.json")
for name in ("lib-dnsmasq_rs", "bin-dnsmasq-rs"):
    binary = private / "tests" / name
    row = run("unit-" + name, [
        "sudo", "-n", "sh", source / "tools/dnsmasq/run_isolated.sh", "sh", "-c",
        'set -eu; mount -t tmpfs -o mode=1777 tmpfs /tmp; '
        'TMPDIR=$(mktemp -d /tmp/fix6-tests.XXXXXX); export TMPDIR; exec "$@"',
        "unit", binary, "--test-threads=1"], 600)
    row["elf_sha256"] = sha(binary)
    row["test_summary"] = [line for line in (private / ("unit-" + name + ".log")).read_text().splitlines()
                           if line.startswith("test result:")]
    assert len(row["test_summary"]) == 1 and "0 failed;" in row["test_summary"][0]
    save()
verify_source()
report["source_postcheck_passed"] = True
report["complete"] = True
save()
print(json.dumps({"complete": True, "source_files_verified": len(expected),
                  "unit_results": [row["test_summary"] for row in report["commands"] if "test_summary" in row]}))
