#!/usr/bin/env python3
"""Add a temporary native-image guard to a private sysupgrade config backup.

Creates a new archive; never writes to a router. The firmware itself is unchanged.
"""
import argparse
import hashlib
import io
import json
import re
from pathlib import Path
import tarfile
import uuid
from r84_device_probe import native_paths


def validate_members(members, reserved):
    """Reject ambiguous paths and archive links that could redirect extraction."""
    names = set()
    links = set()
    for member in members:
        name = member.name.lstrip("/").rstrip("/")
        assert name and ".." not in Path(name).parts and "." not in name.split("/"), name
        assert all(ord(character) >= 32 and ord(character) != 127 for character in name), name
        assert not name.startswith("-"), name
        assert name not in names and "//" not in name, name
        assert member.isfile() or member.isdir() or member.issym(), name
        assert not name.endswith(".boot-enable"), name
        assert not any(name == path or name.startswith(path + "/") for path in reserved), name
        names.add(name)
        if member.issym():
            links.add(name)
    for name in names | set(reserved):
        assert not any(parent.as_posix() in links for parent in Path(name).parents), name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("bounded", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--rootfs", type=Path, required=True,
                        help="extracted exact candidate image, for recovery identities")
    parser.add_argument("--rollback-image", type=Path, required=True)
    parser.add_argument("--rollback-sha256", required=True,
                        help="independently verified rollback Release image SHA256")
    parser.add_argument("--rollback-version", required=True,
                        help="verified rollback release, such as v0.2.1")
    args = parser.parse_args()
    assert re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.rollback_version)
    assert not args.output.exists()
    manifest = json.loads(args.manifest.read_text())
    paths = native_paths(manifest["deployment_layout"])
    assert {name: item["path"] for name, item in manifest["components"].items()} == paths
    assert len(manifest["integration_files"]) == 2
    rollback_image = args.rollback_image.read_bytes()
    assert hashlib.sha256(rollback_image).hexdigest() == args.rollback_sha256
    original_config = args.config.read_bytes()
    with tarfile.open(args.config) as original:
        original_names = [m.name.lstrip("/").rstrip("/") for m in original.getmembers()]
    member_list = ("\n".join(original_names) + "\n").encode()
    repo = Path(__file__).resolve().parent.parent
    base = "root/owrt-native-trial/"
    token = str(uuid.uuid4())
    files = [*manifest["components"].values(), *manifest["integration_files"].values()]
    image_manifest = json.loads((args.rootfs / "usr/share/owrt-control-plane/release.json").read_text())
    assert image_manifest["source_commit"] == manifest["source_commit"]
    assert image_manifest["components"] == manifest["components"]
    assert image_manifest["integration_files"] == manifest["integration_files"]
    stock = (args.rootfs / "usr/share/owrt-control-plane/stock.sha256").read_text()
    observed = dict(line.split(None, 1)[::-1] for line in stock.splitlines())
    assert len(stock.splitlines()) == len(files) and len(observed) == len(files)
    assert observed == {c["recovery_path"]: c["stock_sha256"] for c in files}
    for path, expected in observed.items():
        assert hashlib.sha256((args.rootfs / path.lstrip("/")).read_bytes()).hexdigest() == expected
    recovery = stock + hashlib.sha256((args.rootfs / "usr/sbin/owrt-recover-c").read_bytes()).hexdigest() + "  /usr/sbin/owrt-recover-c\n"
    recovery += hashlib.sha256(stock.encode()).hexdigest() + "  /usr/share/owrt-control-plane/stock.sha256\n"
    rollback = (args.rollback_sha256 + "  /" + base + "rollback.bin\n" +
                hashlib.sha256(original_config).hexdigest() + "  /" + base + "rollback-config.tar.gz\n" +
                hashlib.sha256(member_list).hexdigest() + "  /" + base + "rollback-members.txt\n")
    payload = {
        base + "native_trial_guard.sh": ((repo / "tools/native_trial_guard.sh").read_bytes(), 0o700),
        base + "bounded": (args.bounded.read_bytes(), 0o700),
        base + "armed": ((token + "\n").encode(), 0o600),
        base + "recovery.sha256": (recovery.encode(), 0o600),
        base + "rollback.sha256": (rollback.encode(), 0o600),
        base + "rollback.bin": (rollback_image, 0o600),
        base + "rollback-config.tar.gz": (original_config, 0o600),
        base + "rollback-members.txt": (member_list, 0o600),
        "etc/init.d/owrt-native-trial": ((repo / "tools/native_trial.init").read_bytes(), 0o755),
    }
    link = "etc/rc.d/S01owrt-native-trial"
    hashes = {name: hashlib.sha256(data).hexdigest() for name, (data, _) in payload.items()}
    with tarfile.open(args.config) as old, tarfile.open(args.output, "x:gz") as new:
        args.output.chmod(0o600)
        members = old.getmembers()
        validate_members(members, [base.rstrip("/"), *payload, link,
                                   "root/owrt-native-rollback-receipt",
                                   *(c["path"].lstrip("/") for c in files)])
        names = set()
        for member in members:
            name = member.name.lstrip("/")
            assert ".." not in Path(name).parts and name not in names, name
            assert name not in payload and name != link and name != base.rstrip("/") and not name.startswith(base), name
            assert not name.endswith(".boot-enable"), name
            names.add(name)
            member.name = name
            new.addfile(member, old.extractfile(member) if member.isfile() else None)
        directory = tarfile.TarInfo(base.rstrip("/"))
        directory.type, directory.mode = tarfile.DIRTYPE, 0o700
        new.addfile(directory)
        for name, (data, mode) in payload.items():
            member = tarfile.TarInfo(name)
            member.mode, member.size = mode, len(data)
            new.addfile(member, io.BytesIO(data))
        member = tarfile.TarInfo(link)
        member.type, member.linkname, member.mode = tarfile.SYMTYPE, "../init.d/owrt-native-trial", 0o777
        new.addfile(member)
    with tarfile.open(args.output) as new, tarfile.open(args.config) as old:
        for member in old.getmembers():
            copy = new.getmember(member.name.lstrip("/"))
            assert (member.type, member.mode, member.uid, member.gid, member.linkname) == (copy.type, copy.mode, copy.uid, copy.gid, copy.linkname)
            if member.isfile():
                assert old.extractfile(member).read() == new.extractfile(copy).read()
        for name, (data, mode) in payload.items():
            assert new.extractfile(name).read() == data
            entry = new.getmember(name)
            assert (entry.uid, entry.gid, entry.mode) == (0, 0, mode)
        assert new.getmember(link).linkname == "../init.d/owrt-native-trial"
    result = {"image": manifest["image"], "token": token,
              "archive_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
              "original_config_archive_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
              "original_members_preserved": len(members), "payload_sha256": hashes,
              "guard_start_link": link, "first_confirmation_timeout_s": 600,
              "accepted_health_failure_timeout_s": 300, "unhealthy_boot_limit": 3,
              "confirmation_required_each_boot": True,
              "rollback_image_sha256": args.rollback_sha256,
              "rollback_image_bytes": len(rollback_image), "rollback_version": args.rollback_version,
              "recovery_rootfs_manifest_sha256": hashlib.sha256((args.rootfs / "usr/share/owrt-control-plane/release.json").read_bytes()).hexdigest()}
    record = args.output.with_suffix(".json")
    assert not record.exists()
    record.write_text(json.dumps(result, indent=2) + "\n")
    record.chmod(0o600)
    print(f"Prepared {args.output}; all {len(members)} original backup members preserved")


if __name__ == "__main__":
    main()
