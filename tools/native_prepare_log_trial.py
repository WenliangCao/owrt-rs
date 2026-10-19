#!/usr/bin/env python3
"""Prepare a private trial archive and exact log-migration hashes offline.

Run on Linux against the final extracted image. Only a disposable chroot runs
the image's UCI migration; no service, SSH, staging or firmware command runs.
The result is deliberately not a ready-for-staging recovery gate.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile


MARKER = "etc/owrt-log-settings-v1"
MIGRATION = "etc/uci-defaults/06-owrt-log-settings"
KEEP = "lib/upgrade/keep.d/owrt-log-settings"
BOUNDED_SHA = "21609fa0e03e4a4595e74d266235a9566f2cc37f71571ad9315900d3def5cb49"
ROLLBACK_SHA = "099db9920bc59cfa943f2656a8c057e6eb00360bee71d5f513b5ed39aee34c3d"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def configs(root):
    return {str(path.relative_to(root)): ("symlink", os.readlink(path)) if path.is_symlink()
            else ("file", sha(path)) for path in sorted((root / "etc/config").rglob("*"))
            if path.is_symlink() or path.is_file()}


def replace_settings(data):
    for old, new in ((b"\toption log_size '128'\n", b"\toption log_size '2048'\n"),
                     (b"\toption conloglevel '8'\n", b"\toption conloglevel '4'\n")):
        assert data.count(old) == 1, "backup differs from the explicitly reviewed old logging configuration"
        data = data.replace(old, new)
    return data


def chroot(root, *argv):
    return subprocess.run(["chroot", str(root), *argv], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=30).stdout


def migration(rootfs, backup, manifest, output):
    assert not (rootfs / MARKER).exists(), "image must not pre-install the once-only marker"
    repo = Path(__file__).resolve().parent.parent
    assert (rootfs / MIGRATION).read_bytes() == (repo / "packaging/image/06-owrt-log-settings").read_bytes()
    assert (rootfs / KEEP).read_bytes() == (repo / "packaging/image/owrt-log-settings.keep").read_bytes()
    assert sha(rootfs / "sbin/uci") == manifest["components"]["uci"]["rust_sha256"]
    with tarfile.open(backup) as archive:
        member = archive.getmember("etc/config/system")
        assert member.isfile()
        before = archive.extractfile(member).read()
    output.mkdir(mode=0o700)
    (output / "system-before").write_bytes(before)
    with tempfile.TemporaryDirectory(prefix="native-log-migration-") as directory:
        root = Path(directory) / "root"
        subprocess.run(["cp", "-a", rootfs, root], check=True)
        shutil.rmtree(root / "dev")
        (root / "dev").mkdir()
        os.mknod(root / "dev/null", stat.S_IFCHR | 0o666, os.makedev(1, 3))
        (root / "tmp/.uci").mkdir(parents=True, exist_ok=True)
        target = root / "etc/config/system"
        assert not target.is_symlink()
        target.write_bytes(before)
        target.chmod(member.mode)
        os.chown(target, member.uid, member.gid)
        before_files = configs(root)
        before_export = chroot(root, "uci", "export", "system")
        chroot(root, "/bin/sh", "/" + MIGRATION)
        after = target.read_bytes()
        after_export = chroot(root, "uci", "export", "system")
        # The actual image UCI parser/exporter proves semantics. Exact raw-byte
        # comparison additionally rejects unrelated formatting/comment edits.
        assert after_export == replace_settings(before_export)
        assert after == replace_settings(before)
        after_files = configs(root)
        assert before_files.keys() == after_files.keys()
        assert all(before_files[name] == after_files[name] for name in before_files if name != "etc/config/system")
        marker = (root / MARKER).read_bytes()
        assert marker == b"complete\n"
        # A second invocation must preserve both exact outputs.
        chroot(root, "/bin/sh", "/" + MIGRATION)
        assert target.read_bytes() == after and (root / MARKER).read_bytes() == marker
        for name, value in (("system-after", after), ("export-before", before_export),
                            ("export-after", after_export), ("marker", marker)):
            (output / name).write_bytes(value)
    (output / "system.diff").write_text("".join(difflib.unified_diff(before.decode().splitlines(True),
        after.decode().splitlines(True), fromfile="backup/etc/config/system", tofile="migrated/etc/config/system")))
    result = {"passed": True, "backup_sha256": sha(backup), "uci_sha256": sha(rootfs / "sbin/uci"),
              "script_sha256": sha(rootfs / MIGRATION), "keep_sha256": sha(rootfs / KEEP),
              "only_changes": {"system.@system[0].log_size": ["128", "2048"],
                               "system.@system[0].conloglevel": ["8", "4"]},
              "other_system_bytes_unchanged": True, "other_configuration_files_unchanged": True,
              "uci_exports_only_expected_changes": True, "second_run_unchanged": True,
              "log_settings_migration": {"system_sha256": sha(output / "system-after"),
                                         "marker_sha256": sha(output / "marker")}}
    save(output / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("rootfs", "manifest", "image", "backup", "bounded", "rollback", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--backup-sha256", required=True)
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0 and not sys.flags.optimize
    os.umask(0o077)
    # Qualification source snapshots are immutable, including imported helper
    # modules. Propagate this to the trial-builder child as well as this process.
    sys.dont_write_bytecode = True
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    root, output = args.rootfs.resolve(), args.out.resolve()
    assert "private" in output.parts and not output.exists()
    assert sha(args.backup) == args.backup_sha256
    assert sha(args.bounded) == BOUNDED_SHA and sha(args.rollback) == ROLLBACK_SHA
    manifest = json.loads(args.manifest.read_text())
    release = json.loads((root / "usr/share/owrt-control-plane/release.json").read_text())
    assert release["version"] == manifest["packages"]["owrt-control-plane"] == "0.3.2-r1"
    assert sha(args.image) == manifest["image"]["sha256"] and args.image.stat().st_size == manifest["image"]["size"]
    for key in ("source_commit", "components", "integration_files"):
        assert release[key] == manifest[key]
    output.mkdir(mode=0o700, parents=True)
    result = {"status": "preparing-offline", "ready_for_staging": False, "not_staged": True, "not_flashed": True,
              "image_sha256": sha(args.image), "manifest_sha256": sha(args.manifest),
              "backup_sha256": args.backup_sha256, "bounded_sha256": BOUNDED_SHA,
              "rollback_sha256": ROLLBACK_SHA, "source_commit": manifest["source_commit"],
              "pending": ["exact final image eight-group qualification receipt", "fresh router consistency", "explicit flash authorization"]}
    try:
        backup = output / "config-before.tar.gz"
        shutil.copy2(args.backup, backup)
        settings = migration(root, backup, manifest, output / "log-settings-migration")
        result["log_settings_migration"] = settings["log_settings_migration"]
        trial = output / "trial-config.tar.gz"
        prepare = Path(__file__).with_name("native_trial_prepare.py")
        with (output / "trial-prepare.log").open("wb") as log:
            subprocess.run([sys.executable, "-B", str(prepare), str(backup), str(args.manifest), str(args.bounded), str(trial),
                            "--rootfs", str(root), "--rollback-image", str(args.rollback), "--rollback-sha256", ROLLBACK_SHA,
                            "--rollback-version", "v0.3.1"], check=True, stdout=log, stderr=subprocess.STDOUT)
        metadata = json.loads(trial.with_suffix(".json").read_text())
        assert metadata["original_members_preserved"] == 46 and metadata["archive_sha256"] == sha(trial)
        with tarfile.open(backup) as old, tarfile.open(trial) as new:
            assert len(old.getmembers()) == 46
            for member in old:
                copied = new.getmember(member.name.lstrip("/"))
                for field in ("mode", "uid", "gid", "mtime", "type", "linkname", "uname", "gname", "size", "pax_headers"):
                    assert getattr(member, field) == getattr(copied, field), (member.name, field)
                if member.isfile():
                    assert old.extractfile(member).read() == new.extractfile(copied).read(), member.name
            prefix = "root/owrt-native-trial/"
            assert new.extractfile(prefix + "rollback-config.tar.gz").read() == backup.read_bytes()
            assert new.extractfile(prefix + "rollback.bin").read() == args.rollback.read_bytes()
            recovery = dict(line.split(None, 1)[::-1] for line in new.extractfile(prefix + "recovery.sha256").read().decode().splitlines())
            files = [*manifest["components"].values(), *manifest["integration_files"].values()]
            assert len(files) == 13 and len(recovery) == 15
            for item in files:
                assert recovery[item["recovery_path"]] == item["stock_sha256"]
                assert sha(root / item["recovery_path"].lstrip("/")) == item["stock_sha256"]
            for name, digest in metadata["payload_sha256"].items():
                assert hashlib.sha256(new.extractfile(name).read()).hexdigest() == digest
        assert sha(args.backup) == sha(backup) == args.backup_sha256
        result.update(status="prepared_not_ready", trial_archive_sha256=sha(trial),
                      original_members_preserved=46, recovery_files_verified=13,
                      original_backup_unchanged=True, migration_receipt_sha256=sha(output / "log-settings-migration/result.json"))
    except BaseException as error:
        result.update(status="failed-preserved", error=repr(error))
        raise
    finally:
        save(output / "prepared-not-ready.json", result)
        print(json.dumps({key: result[key] for key in ("status", "ready_for_staging", "image_sha256", "backup_sha256")}))


if __name__ == "__main__":
    main()
