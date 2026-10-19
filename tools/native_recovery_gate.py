#!/usr/bin/env python3
"""Export exact-image evidence or create a local technical recovery gate.

The only device commands are read-only SSH consistency checks. This tool never
stages an image, enables a guard, changes configuration or authorizes flashing.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile

GROUPS = {"fit", "boot", "image", "apk", "guard", "handoff", "rollback_bundle", "log_settings"}
COMMANDS = {"boot", "image", "apk", "guard", "handoff", "rollback-bundle", "log-settings", "fit-identity"}
RESULTS = ("result.json", "request.json", "inputs.json", "observed-inputs.json", "root-identity.json",
           "boot-final/result.json", "boot-final/client-result.json", "image-checks/result.json",
           "apk-checks/result.json", "guard-checks/result.json", "handoff-checks/result.json",
           "log-settings-checks/results.json")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def qualification(value, source, image_sha, manifest_sha, ci_run):
    assert value["passed"] is True and value["inputs_source_and_rootfs_unchanged"] is True
    assert value["source_commit"] == value["source_snapshot_commit"] == source
    assert value["image_sha256"] == image_sha and value["manifest_sha256"] == manifest_sha
    assert str(value["ci_run_id"]) == str(ci_run)
    assert set(value["groups"]) == GROUPS and all(row["passed"] is True for row in value["groups"].values())
    assert value["groups"]["guard"]["branches"] == 23
    assert value["groups"]["rollback_bundle"]["original_members_identical"] == 46
    assert value["groups"]["rollback_bundle"]["recovery_files_verified"] == 13
    assert value["groups"]["log_settings"]["cases"] == 16
    assert value["accepted_component_elfs_verified"] == 11


def export(args):
    root = args.qualification.resolve()
    assert sha(root / "result.json") == args.result_sha256
    result = read(root / "result.json")
    qualification(result, args.source, args.image_sha256, args.manifest_sha256, args.ci_run)
    paths = [root / name for name in RESULTS] + sorted((root / "logs").glob("*.command.json"))
    commands = {path.name.removesuffix(".command.json"): read(path) for path in paths if path.name.endswith(".command.json")}
    assert COMMANDS <= commands.keys() and all(value["exit_code"] == 0 for value in commands.values())
    payload = {str(path.relative_to(root)): path.read_bytes() for path in paths}
    assert all(path.is_file() and not path.is_symlink() for path in paths)
    image = root / "rootfs"
    extras = {"ujail_sha256": sha(image / "sbin/ujail"),
              "default_recovery_sha256": {path: sha(image / path.lstrip("/")) for path in ("/etc/ethers", "/etc/sysupgrade.conf")},
              "migration_marker_absent": not (image / "etc/owrt-log-settings-v1").exists(),
              "no_router_access": True}
    assert extras["migration_marker_absent"]
    payload["root-extra.json"] = (json.dumps(extras, indent=2) + "\n").encode()
    index = {"qualification_directory": str(root), "result_sha256": sha(root / "result.json"),
             "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in payload.items()},
             "scope": "explicit result and command-receipt allowlist; no rootfs, configuration, sessions or secrets",
             "exporter_sha256": sha(__file__)}
    payload["bundle.json"] = (json.dumps(index, indent=2) + "\n").encode()
    with tarfile.open(args.out, "x:gz") as archive:
        for name, data in sorted(payload.items()):
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = 0o600, len(data)
            archive.addfile(entry, io.BytesIO(data))
    print(json.dumps({"path": str(args.out), "sha256": sha(args.out), "files": len(payload)}))


def bundle(path, expected):
    assert sha(path) == expected
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        assert all(member.isfile() and not member.name.startswith("/") and ".." not in Path(member.name).parts for member in members)
        assert len({member.name for member in members}) == len(members)
        files = {member.name: archive.extractfile(member).read() for member in members}
    index = json.loads(files.pop("bundle.json"))
    assert set(files) == set(index["files"])
    for name, data in files.items():
        assert len(data) == index["files"][name]["bytes"]
        assert hashlib.sha256(data).hexdigest() == index["files"][name]["sha256"]
        assert name in RESULTS or name == "root-extra.json" or name.startswith("logs/") and name.endswith(".command.json")
    return index, {name: json.loads(data) for name, data in files.items()}


def fingerprints(path):
    return {line.split(None, 1)[1].strip(): line.split(None, 1)[0] for line in path.read_text().splitlines()}


def fresh(args, output):
    output.mkdir(mode=0o700)
    expected = {name: fingerprints(args.snapshot / (name + "-before.sha256"))
                for name in ("config", "protected", "archive-inputs")}
    assert [len(expected[name]) for name in expected] == [19, 12, 45]
    boot = (args.snapshot / "boot-id-after.txt").read_text().strip()
    ssh = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", args.host]
    observations = []
    for phase in ("before", "after"):
        rows = {}
        scripts = {"boot": "cat /proc/sys/kernel/random/boot_id",
                   "hardware": "readlink /sys/bus/mdio_bus/devices/mdio-bus:01/driver",
                   "config": "sha256sum /etc/config/*"}
        scripts.update({name: "sha256sum " + " ".join(map(shlex.quote, expected[name]))
                        for name in ("protected", "archive-inputs")})
        for name, command in scripts.items():
            done = subprocess.run(ssh + [command], capture_output=True, timeout=30)
            (output / (phase + "-" + name + ".stdout")).write_bytes(done.stdout)
            (output / (phase + "-" + name + ".stderr")).write_bytes(done.stderr)
            assert done.returncode == 0, "fresh device read failed: " + name
            value = done.stdout.decode().strip()
            if name == "boot": assert value == boot
            elif name == "hardware": assert value.endswith("/an8855")
            else:
                actual = {line.split(None, 1)[1].strip(): line.split(None, 1)[0] for line in value.splitlines()}
                assert actual == expected[name], "device changed since backup: " + name
            rows[name] = hashlib.sha256(done.stdout).hexdigest()
        observations.append(rows)
    assert observations[0] == observations[1]
    result = {"passed": True, "boot_id": boot, "hardware": "an8855", "configuration_files": 19,
              "protected_files": 12, "backup_source_files": 45, "matches_backup_snapshot": True,
              "before_after_equal": True, "read_only_commands": True,
              "checked_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "observations": observations}
    save(output / "result.json", result)
    return result


def create(args):
    base = args.deploy.resolve()
    assert not (base / "recovery-gate.json").exists()
    manifest_path = args.inputs.resolve() / "manifest.json"
    manifest, prepared, trial = read(manifest_path), read(base / "prepared-not-ready.json"), read(base / "trial-config.tar.json")
    image = args.inputs.resolve() / manifest["image"]["file"]
    assert sha(image) == prepared["image_sha256"] == trial["image"]["sha256"] == manifest["image"]["sha256"]
    assert sha(manifest_path) == prepared["manifest_sha256"]
    assert sha(base / "trial-config.tar.gz") == prepared["trial_archive_sha256"] == trial["archive_sha256"]
    assert prepared["status"] == "prepared_not_ready" and prepared["original_backup_unchanged"]
    assert prepared["original_members_preserved"] == 46 and prepared["recovery_files_verified"] == 13
    migration = read(base / "log-settings-migration/result.json")
    assert migration["passed"] and prepared["log_settings_migration"] == migration["log_settings_migration"]
    assert migration["log_settings_migration"] == {"system_sha256": sha(base / "log-settings-migration/system-after"),
                                                 "marker_sha256": sha(base / "log-settings-migration/marker")}
    evidence_path = base / "guard-evidence.tar.gz"
    index, evidence = bundle(evidence_path, args.evidence_sha256)
    assert index["result_sha256"] == args.qualification_sha256
    qualification(evidence["result.json"], manifest["source_commit"], sha(image), sha(manifest_path), args.ci_run)
    commands = {Path(name).name.removesuffix(".command.json"): value for name, value in evidence.items() if name.endswith(".command.json")}
    assert COMMANDS <= commands.keys() and all(value["exit_code"] == 0 for value in commands.values())
    guard = evidence["guard-checks/result.json"]
    assert len(guard) == 23 and all(value is True for value in guard.values())
    assert evidence["root-extra.json"]["migration_marker_absent"]
    assert sha(args.repro) == args.repro_sha256
    repro = read(args.repro)
    assert repro["status"] == "passed-byte-identical-v032-images" and repro["source_commit"] == manifest["source_commit"]
    assert repro["image"] == manifest["image"] and repro["manifest_sha256"] == sha(manifest_path)
    assert all(repro["required_files_byte_identical"].values()) and all(repro["extracted_files_byte_identical"].values())
    assert len(repro["builds"]) == 2
    assert {str(row["run"]["id"]) for row in repro["builds"]} == {str(args.ci_run), str(args.second_ci_run)}
    assert all(row["run"]["head_sha"] == manifest["source_commit"] and row["run"]["conclusion"] == "success"
               and row["checksum_entries"] == 40 and len(row["binaries"]) == 11 for row in repro["builds"])
    rollback = read(args.rollback_manifest)
    assert rollback["source_commit"] == "c4acff16546f3e23397a37cf5d2ee5037d85ccca"
    assert sha(args.rollback) == prepared["rollback_sha256"] == rollback["image"]["sha256"]
    backup_names = ("config-before.tar.gz", "config-before.sha256", "protected-before.sha256")
    backups = {name: sha(base / name) for name in backup_names}
    assert backups["config-before.tar.gz"] == prepared["backup_sha256"] == trial["original_config_archive_sha256"]
    for name in backup_names[1:]: assert (base / name).read_bytes() == (args.snapshot / name).read_bytes()
    expected_defaults = fingerprints(args.snapshot / "protected-before.sha256")
    assert all(expected_defaults[name] == digest for name, digest in evidence["root-extra.json"]["default_recovery_sha256"].items())
    # The final device read happens only after every local gate above passed.
    current = fresh(args, base / args.fresh_label)
    gate = {"ready_for_staging": True, "technical_readiness_only": True, "authorization": "pending",
            "not_staged": True, "not_flashed": True, "image_path": str(image), "image_sha256": sha(image),
            "manifest_path": str(manifest_path), "manifest_sha256": sha(manifest_path),
            "rollback_image_path": str(args.rollback.resolve()), "rollback_sha256": sha(args.rollback),
            "rollback_version": "v0.3.1", "rollback_source_commit": rollback["source_commit"],
            "ujail_sha256": evidence["root-extra.json"]["ujail_sha256"], "bounded_sha256": prepared["bounded_sha256"],
            "previous_boot_id": current["boot_id"], "backup_sha256": backups, "configuration_members_preserved": 46,
            "guard_evidence_sha256": args.evidence_sha256, "log_settings_migration": prepared["log_settings_migration"],
            "source_commit": manifest["source_commit"], "qualification_ci": str(args.ci_run),
            "second_image_ci": str(args.second_ci_run), "reproducibility_path": str(args.repro.resolve()),
            "reproducibility_sha256": args.repro_sha256, "offline_qualification": evidence["result.json"]["groups"],
            "fresh_consistency": {"path": str(base / args.fresh_label / "result.json"),
                                  "sha256": sha(base / args.fresh_label / "result.json"), "checked_utc": current["checked_utc"]},
            "creator_sha256": sha(__file__)}
    save(base / "recovery-gate.json.new", gate)
    (base / "recovery-gate.json.new").replace(base / "recovery-gate.json")
    print(json.dumps({"ready_for_staging": True, "authorization": "pending", "gate_sha256": sha(base / "recovery-gate.json")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    output = sub.add_parser("export")
    output.add_argument("--qualification", type=Path, required=True)
    output.add_argument("--out", type=Path, required=True)
    for name in ("source", "image-sha256", "manifest-sha256", "result-sha256", "ci-run"):
        output.add_argument("--" + name, required=True)
    gate = sub.add_parser("create")
    for name in ("deploy", "inputs", "snapshot", "repro", "rollback", "rollback-manifest"):
        gate.add_argument("--" + name, type=Path, required=True)
    for name in ("evidence-sha256", "qualification-sha256", "repro-sha256", "ci-run", "second-ci-run", "fresh-label"):
        gate.add_argument("--" + name, required=True)
    gate.add_argument("--host", default="openwrt")
    args = parser.parse_args()
    assert __debug__
    os.umask(0o077)
    export(args) if args.command == "export" else create(args)


if __name__ == "__main__":
    main()
