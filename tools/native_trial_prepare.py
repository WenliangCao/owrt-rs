#!/usr/bin/env python3
"""Add a temporary native-image guard to a private sysupgrade config backup.

Creates a new archive; never writes to a router. The firmware itself is unchanged.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("bounded", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    assert not args.output.exists()
    manifest = json.loads(args.manifest.read_text())
    assert manifest["deployment_layout"] == "native-nine"
    assert len(manifest["components"]) == 9
    repo = Path(__file__).resolve().parent.parent
    base = "root/owrt-native-trial/"
    token = str(uuid.uuid4())
    stock = "".join(f"{c['stock_sha256']}  {c['recovery_path']}\n"
                    for c in manifest["components"].values())
    recovery = stock + hashlib.sha256((repo / "packaging/image/owrt-recover-c").read_bytes()).hexdigest() + "  /usr/sbin/owrt-recover-c\n"
    recovery += hashlib.sha256(stock.encode()).hexdigest() + "  /usr/share/owrt-control-plane/stock.sha256\n"
    payload = {
        base + "native_trial_guard.sh": ((repo / "tools/native_trial_guard.sh").read_bytes(), 0o700),
        base + "bounded": (args.bounded.read_bytes(), 0o700),
        base + "armed": ((token + "\n").encode(), 0o600),
        base + "recovery.sha256": (recovery.encode(), 0o600),
        "etc/init.d/owrt-native-trial": ((repo / "tools/native_trial.init").read_bytes(), 0o755),
    }
    link = "etc/rc.d/S01owrt-native-trial"
    hashes = {name: hashlib.sha256(data).hexdigest() for name, (data, _) in payload.items()}
    with tarfile.open(args.config) as old, tarfile.open(args.output, "x:gz") as new:
        args.output.chmod(0o600)
        members = old.getmembers()
        names = set()
        for member in members:
            name = member.name.lstrip("/")
            assert ".." not in Path(name).parts and name not in names, name
            assert name not in payload and name != link and not name.startswith(base), name
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
            assert (member.type, member.mode, member.linkname) == (copy.type, copy.mode, copy.linkname)
            if member.isfile():
                assert old.extractfile(member).read() == new.extractfile(copy).read()
        for name, (data, _) in payload.items():
            assert new.extractfile(name).read() == data
        assert new.getmember(link).linkname == "../init.d/owrt-native-trial"
    result = {"image": manifest["image"], "token": token,
              "archive_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
              "original_config_archive_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
              "original_members_preserved": len(members), "payload_sha256": hashes,
              "guard_start_link": link, "first_confirmation_timeout_s": 600,
              "accepted_health_failure_timeout_s": 300, "unhealthy_boot_limit": 3}
    record = args.output.with_suffix(".json")
    assert not record.exists()
    record.write_text(json.dumps(result, indent=2) + "\n")
    record.chmod(0o600)
    print(f"Prepared {args.output}; all {len(members)} original backup members preserved")


if __name__ == "__main__":
    main()
